package taskservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calypr/funnel/api/config"
	"github.com/calypr/funnel/api/tes"
	"github.com/calypr/funnel/internal/compute/noop"
	"github.com/calypr/funnel/internal/database/badger"
	"github.com/calypr/funnel/internal/database/boltdb"
	"github.com/calypr/funnel/internal/events"
	"github.com/calypr/funnel/internal/identity"
	"github.com/calypr/funnel/internal/logger"
	taskpolicy "github.com/calypr/funnel/internal/task"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Case numbers refer to the conformance cases of the TES AuthZ spec
// (tes-authzen/1, section 8.2).

const (
	testIssuer = "https://issuer.tes-authz.test/"
	vo         = "urn:geant:lifescience-ri.eu:group:example-vo"
	subgroup   = vo + ":analysts#login.aai.lifescience-ri.eu"
	nearMiss   = "urn:geant:lifescience-ri.eu:group:example-vox#login.aai.lifescience-ri.eu"
)

var voRule = &config.AuthzRequiredClaim{Name: "eduperson_entitlement", Prefixes: []string{vo + ":"}}

// recorded is one evaluation request as the decision service saw it.
type recorded struct {
	body    map[string]any
	headers http.Header
}

// stubPDP is a recording decision service with scripted answers.
type stubPDP struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recorded
	answer   func(body map[string]any) (int, string)
}

func newStubPDP(t *testing.T) *stubPDP {
	t.Helper()
	pdp := &stubPDP{}
	pdp.allow(true)
	pdp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decision request is not JSON: %v", err)
		}
		pdp.mu.Lock()
		pdp.requests = append(pdp.requests, recorded{body, r.Header.Clone()})
		answer := pdp.answer
		pdp.mu.Unlock()
		code, text := answer(body)
		w.WriteHeader(code)
		if _, err := w.Write([]byte(text)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(pdp.Close)
	return pdp
}

// allow answers every request with the same decision.
func (p *stubPDP) allow(decision bool) {
	p.script(func(map[string]any) bool { return decision })
}

// script answers with a decision computed from the request.
func (p *stubPDP) script(decide func(body map[string]any) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = func(body map[string]any) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"decision": %v}`, decide(body))
	}
}

func (p *stubPDP) respond(code int, text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = func(map[string]any) (int, string) { return code, text }
}

func (p *stubPDP) take() []recorded {
	p.mu.Lock()
	defer p.mu.Unlock()
	requests := p.requests
	p.requests = nil
	return requests
}

func action(body map[string]any) string { return body["action"].(map[string]any)["name"].(string) }

func resourceID(body map[string]any) string { return body["resource"].(map[string]any)["id"].(string) }

// newAuthzService returns a task service on a fresh embedded database.
func newAuthzService(t *testing.T, backend string, server *config.Server) *Service {
	t.Helper()
	type store interface {
		taskpolicy.ReadOnlyServer
		events.Writer
		Init() error
	}
	var db store
	var err error
	path := filepath.Join(t.TempDir(), backend)
	if backend == "badger" {
		db, err = badger.NewBadger(&config.Badger{Path: path})
	} else {
		db, err = boltdb.NewBoltDB(&config.BoltDB{Path: path})
	}
	if err == nil {
		err = db.Init()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if server.BasicAuth == nil {
		server.BasicAuth = []*config.BasicCredential{{User: "worker", Password: "secret", Admin: true}}
	}
	log := testLogger()
	authz, err := NewAuthz(server, log)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Event: db, Read: db, Compute: noop.NewBackend(), Log: log, Config: &config.Config{Server: server}, Authz: authz}
}

func withPDP(pdp *stubPDP, conf *config.AuthzDecisionService) *config.Server {
	conf.URL = pdp.URL
	return &config.Server{Authz: &config.Authz{DecisionService: conf}}
}

func withRule(rule *config.AuthzRequiredClaim) *config.Server {
	return &config.Server{Authz: &config.Authz{RequiredClaim: rule}}
}

// as returns a context for an OIDC caller; claims pass through JSON like
// a validated token's.
func as(sub string, extra map[string]any, mode identity.AccessMode) context.Context {
	claims := map[string]any{"iss": testIssuer, "sub": sub, "azp": "tes-client", "scope": "openid eduperson_entitlement"}
	for key, value := range extra {
		claims[key] = value
	}
	var decoded identity.Claims
	roundTrip(claims, &decoded)
	return identity.WithUser(context.Background(), &identity.UserInfo{Username: sub, Token: "token-" + sub, Claims: &decoded, AccessMode: mode})
}

var (
	alice = as("alice-sub", map[string]any{"eduperson_entitlement": []string{subgroup}}, identity.AccessAll)
	bob   = as("bob-sub", map[string]any{"eduperson_entitlement": []string{subgroup}}, identity.AccessAll)
	carol = as("carol-sub", map[string]any{"eduperson_entitlement": []string{nearMiss}}, identity.AccessAll)
)

func simpleTask() *tes.Task {
	return &tes.Task{Name: "t", Executors: []*tes.Executor{{Image: "docker.io/library/alpine:3.20", Command: []string{"true"}}}}
}

func create(t *testing.T, ts *Service, ctx context.Context) string {
	t.Helper()
	resp, err := ts.CreateTask(ctx, simpleTask())
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	return resp.Id
}

func code(err error) codes.Code { return status.Code(err) }

func backends(t *testing.T, test func(t *testing.T, backend string)) {
	for _, backend := range []string{"boltdb", "badger"} {
		t.Run(backend, func(t *testing.T) { test(t, backend) })
	}
}

func TestAuthzStripURLGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/authz/url-stripping.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Input    string
		Expected *string
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 27 {
		t.Fatalf("golden rows = %d, want at least 27", len(rows))
	}
	for _, row := range rows {
		got, ok := stripURL(row.Input)
		if row.Expected == nil && ok || row.Expected != nil && (!ok || got != *row.Expected) {
			t.Errorf("stripURL(%q) = %q, %v; want %v", row.Input, got, ok, row.Expected)
		}
	}
}

func TestAuthzClaimRule(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule *config.AuthzRequiredClaim
		ctx  context.Context
		want codes.Code
	}{
		{"3 exact value", &config.AuthzRequiredClaim{Name: "eduperson_entitlement", Values: []string{subgroup}}, alice, codes.OK},
		{"4 prefix", voRule, alice, codes.OK},
		{"4b near miss", voRule, carol, codes.PermissionDenied},
		{"5 claim missing", voRule, as("x", nil, identity.AccessAll), codes.PermissionDenied},
		{"5c dotted path", &config.AuthzRequiredClaim{Name: "ctx.groups", Values: []string{"g1"}}, as("x", map[string]any{"ctx": map[string]any{"groups": []string{"g1"}}}, identity.AccessAll), codes.OK},
		{"5c URI name", &config.AuthzRequiredClaim{Name: "https://e.org/groups", Values: []string{"g1"}}, as("x", map[string]any{"https://e.org/groups": []string{"g1"}}, identity.AccessAll), codes.OK},
		{"5c exact name before path", &config.AuthzRequiredClaim{Name: "a.b", Values: []string{"exact"}}, as("x", map[string]any{"a.b": "exact", "a": map[string]any{"b": "path"}}, identity.AccessAll), codes.OK},
		{"5d client credentials", voRule, as("protes", map[string]any{"client_id": "protes"}, identity.AccessAll), codes.PermissionDenied},
		{"6 string claim", voRule, as("x", map[string]any{"eduperson_entitlement": subgroup}, identity.AccessAll), codes.OK},
		{"6 list with one match", voRule, as("x", map[string]any{"eduperson_entitlement": []string{"other", subgroup}}, identity.AccessAll), codes.OK},
		{"wrong type", voRule, as("x", map[string]any{"eduperson_entitlement": 7}, identity.AccessAll), codes.PermissionDenied},
		{"non-string element", voRule, as("x", map[string]any{"eduperson_entitlement": []any{subgroup, 7}}, identity.AccessAll), codes.PermissionDenied},
		{"Basic user has no claims", voRule, identity.WithUser(context.Background(), &identity.UserInfo{Username: "u"}), codes.PermissionDenied},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Case 5b: no decision service and no claims allowlist.
			ts := newAuthzService(t, "boltdb", withRule(tt.rule))
			_, err := ts.CreateTask(tt.ctx, simpleTask())
			if code(err) != tt.want {
				t.Fatalf("CreateTask = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAuthzUserinfoClaims(t *testing.T) {
	// Case 6b: a claim only in userinfo counts; in both, the token wins,
	// for the rule and for the claims sent to the decision service.
	pdp := newStubPDP(t)
	server := withPDP(pdp, &config.AuthzDecisionService{Claims: []string{"eduperson_entitlement", "ctx.groups"}})
	server.Authz.RequiredClaim = voRule
	ts := newAuthzService(t, "boltdb", server)
	withUserinfo := func(token, userinfo map[string]any) context.Context {
		ctx := as("u", token, identity.AccessAll)
		var claims identity.Claims
		roundTrip(userinfo, &claims)
		identity.GetUser(ctx).Userinfo = &claims
		return ctx
	}
	only := withUserinfo(nil, map[string]any{"eduperson_entitlement": []string{subgroup}, "ctx": map[string]any{"groups": "g"}})
	if _, err := ts.CreateTask(only, simpleTask()); err != nil {
		t.Fatalf("claim only in userinfo: %v", err)
	}
	claims := pdp.take()[0].body["subject"].(map[string]any)["properties"].(map[string]any)["claims"]
	if !reflect.DeepEqual(claims, map[string]any{"eduperson_entitlement": []any{subgroup}, "ctx.groups": "g"}) {
		t.Fatalf("claims = %v", claims)
	}
	both := withUserinfo(map[string]any{"eduperson_entitlement": nearMiss}, map[string]any{"eduperson_entitlement": subgroup})
	if _, err := ts.CreateTask(both, simpleTask()); code(err) != codes.PermissionDenied {
		t.Fatalf("token value must win: %v", err)
	}
}

func TestAuthzRuleFailsOnEveryActionWithoutAskingThePDP(t *testing.T) {
	// Cases 5 and 16.
	pdp := newStubPDP(t)
	server := withPDP(pdp, &config.AuthzDecisionService{})
	server.Authz.RequiredClaim = voRule
	ts := newAuthzService(t, "boltdb", server)
	id := create(t, ts, alice)
	pdp.take()
	_, errCreate := ts.CreateTask(carol, simpleTask())
	_, errGet := ts.GetTask(carol, &tes.GetTaskRequest{Id: id})
	_, errList := ts.ListTasks(carol, &tes.ListTasksRequest{})
	_, errCancel := ts.CancelTask(carol, &tes.CancelTaskRequest{Id: id})
	for _, err := range []error{errCreate, errGet, errList, errCancel} {
		if code(err) != codes.PermissionDenied {
			t.Errorf("err = %v, want PermissionDenied", err)
		}
	}
	if got := pdp.take(); len(got) != 0 {
		t.Fatalf("PDP called %d times, want 0", len(got))
	}
}

func TestAuthzCreateRequestMatchesGolden(t *testing.T) {
	// Cases 7, 7b, 18 and 19.
	raw, err := os.ReadFile("testdata/authz/create.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Request map[string]any
		Submit  json.RawMessage
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	fill := strings.NewReplacer("{{subject_id}}", "alice-sub", "{{sub}}", "alice-sub", "{{iss}}", testIssuer, "{{client_id}}", "tes-client")
	var filled string
	roundTrip(golden.Request, &filled)
	var want map[string]any
	if err := json.Unmarshal([]byte(fill.Replace(filled)), &want); err != nil {
		t.Fatal(err)
	}
	submitted := &tes.Task{}
	if err := protojson.Unmarshal(golden.Submit, submitted); err != nil {
		t.Fatal(err)
	}
	submitted.Logs = []*tes.TaskLog{{Outputs: []*tes.OutputFileLog{{Url: "client-chosen"}}}}

	pdp := newStubPDP(t)
	ts := newAuthzService(t, "boltdb", withPDP(pdp, &config.AuthzDecisionService{Claims: []string{"eduperson_entitlement"}}))
	who := as("alice-sub", map[string]any{"eduperson_entitlement": []string{subgroup}, "email": "a@example.org"}, identity.AccessAll)
	resp, err := ts.CreateTask(who, submitted)
	if err != nil {
		t.Fatal(err)
	}
	requests := pdp.take()
	if len(requests) != 1 {
		t.Fatalf("PDP calls = %d, want 1", len(requests))
	}
	got := requests[0]
	if !reflect.DeepEqual(got.body, want) {
		t.Fatalf("request differs from golden:\n%v", got.body)
	}
	if text := fmt.Sprint(got.body); strings.Contains(text, "do-not-send") || strings.Contains(text, "token-alice-sub") || strings.Contains(text, "a@example.org") {
		t.Fatalf("request leaks secrets or unlisted claims: %s", text)
	}
	if got.headers.Get("Authorization") != "" || len(got.headers.Get("X-Request-ID")) != 36 {
		t.Fatalf("headers = %v, want no Authorization and a generated X-Request-ID", got.headers)
	}
	task, err := ts.GetTask(who, &tes.GetTaskRequest{Id: resp.Id, View: tes.View_FULL.String()})
	if err != nil {
		t.Fatal(err)
	}
	if task.Id == "client-chosen-id" || task.State != tes.Queued || strings.Contains(protojson.Format(task), "client-chosen") {
		t.Fatalf("stored task keeps client-chosen fields: %s", protojson.Format(task))
	}
}

func TestAuthzDecisions(t *testing.T) {
	backends(t, func(t *testing.T, backend string) {
		pdp := newStubPDP(t)
		ts := newAuthzService(t, backend, withPDP(pdp, &config.AuthzDecisionService{}))
		bobTask := create(t, ts, bob)

		// Case 9: the PDP may allow reading another user's task.
		pdp.take()
		if _, err := ts.GetTask(alice, &tes.GetTaskRequest{Id: bobTask, View: "BASIC"}); err != nil {
			t.Fatalf("case 9: %v", err)
		}
		get := pdp.take()[0].body
		wantResource := map[string]any{"type": "tes_task", "id": bobTask, "properties": map[string]any{"owner": "bob-sub", "state": "QUEUED", "tags": map[string]any{}}}
		if !reflect.DeepEqual(get["resource"], wantResource) || !reflect.DeepEqual(get["action"], map[string]any{"name": "GetTask", "properties": map[string]any{"view": "BASIC"}}) {
			t.Fatalf("case 9 request = %v", get)
		}

		// Case 10: deny on get and cancel gives 404; the task is unchanged.
		pdp.allow(false)
		_, errGet := ts.GetTask(alice, &tes.GetTaskRequest{Id: bobTask})
		_, errCancel := ts.CancelTask(alice, &tes.CancelTaskRequest{Id: bobTask})
		if code(errGet) != codes.NotFound || code(errCancel) != codes.NotFound {
			t.Fatalf("case 10: get %v, cancel %v; want NotFound", errGet, errCancel)
		}
		pdp.allow(true)
		if task, err := ts.GetTask(bob, &tes.GetTaskRequest{Id: bobTask}); err != nil || task.State != tes.Queued {
			t.Fatalf("case 10: state %v, want QUEUED", task.State)
		}

		// Case 10b: cancel denied, get allowed gives 403.
		pdp.script(func(body map[string]any) bool { return action(body) != "CancelTask" })
		pdp.take()
		if _, err := ts.CancelTask(alice, &tes.CancelTaskRequest{Id: bobTask}); code(err) != codes.PermissionDenied {
			t.Fatalf("case 10b: %v, want PermissionDenied", err)
		}
		requests := pdp.take()
		if len(requests) != 2 || !reflect.DeepEqual(requests[1].body["action"], map[string]any{"name": "GetTask", "properties": map[string]any{}}) {
			t.Fatalf("case 10b requests = %v", requests)
		}

		// Cancel allowed: the task is canceled although Bob owns it.
		pdp.allow(true)
		if _, err := ts.CancelTask(alice, &tes.CancelTaskRequest{Id: bobTask}); err != nil {
			t.Fatalf("allowed cancel: %v", err)
		}
		if task, err := ts.GetTask(bob, &tes.GetTaskRequest{Id: bobTask}); err != nil || task.State != tes.Canceled {
			t.Fatalf("allowed cancel: state %v, want CANCELED", task.State)
		}
	})
}

func TestAuthzMissingTask(t *testing.T) {
	for _, decision := range []bool{true, false} {
		t.Run(fmt.Sprint(decision), func(t *testing.T) {
			pdp := newStubPDP(t)
			ts := newAuthzService(t, "boltdb", withPDP(pdp, &config.AuthzDecisionService{}))
			pdp.allow(decision)
			// Case 11: 404; the PDP is asked with empty properties.
			if _, err := ts.GetTask(alice, &tes.GetTaskRequest{Id: "no-such-task"}); code(err) != codes.NotFound {
				t.Fatalf("case 11: %v, want NotFound", err)
			}
			requests := pdp.take()
			if len(requests) != 1 || !reflect.DeepEqual(requests[0].body["resource"], map[string]any{"type": "tes_task", "id": "no-such-task", "properties": map[string]any{}}) {
				t.Fatalf("case 11 requests = %v", requests)
			}
			// Case 11c: cancel asks CancelTask, then GetTask, both with empty
			// properties and distinct request IDs.
			if _, err := ts.CancelTask(alice, &tes.CancelTaskRequest{Id: "no-such-task"}); code(err) != codes.NotFound {
				t.Fatalf("case 11c: %v, want NotFound", err)
			}
			requests = pdp.take()
			if len(requests) != 2 || action(requests[0].body) != "CancelTask" || action(requests[1].body) != "GetTask" ||
				requests[0].headers.Get("X-Request-ID") == requests[1].headers.Get("X-Request-ID") {
				t.Fatalf("case 11c requests = %v", requests)
			}
			for _, r := range requests {
				if !reflect.DeepEqual(r.body["resource"].(map[string]any)["properties"], map[string]any{}) || !reflect.DeepEqual(r.body["action"].(map[string]any)["properties"], map[string]any{}) {
					t.Fatalf("case 11c request = %v", r.body)
				}
			}
		})
	}
}

func TestAuthzListScopes(t *testing.T) {
	backends(t, func(t *testing.T, backend string) {
		pdp := newStubPDP(t)
		ts := newAuthzService(t, backend, withPDP(pdp, &config.AuthzDecisionService{}))
		own := []string{}
		all := []string{}
		for i, who := range []context.Context{alice, bob, alice, bob, alice} {
			id := create(t, ts, who)
			all = append(all, id)
			if i%2 == 0 {
				own = append(own, id)
			}
		}
		pages := func(who context.Context) []string {
			ids, token := []string{}, ""
			for range 10 {
				page, err := ts.ListTasks(who, &tes.ListTasksRequest{PageSize: 2, PageToken: token})
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Tasks) > 2 {
					t.Fatalf("page size %d > 2", len(page.Tasks))
				}
				for _, task := range page.Tasks {
					ids = append(ids, task.Id)
				}
				if token = page.NextPageToken; token == "" {
					break
				}
			}
			slices.Sort(ids)
			return ids
		}
		slices.Sort(own)
		slices.Sort(all)
		// Case 12: all.
		if got := pages(alice); !slices.Equal(got, all) {
			t.Fatalf("case 12: %v, want %v", got, all)
		}
		// Case 13: own only, even with TaskAccess All.
		pdp.script(func(body map[string]any) bool { return resourceID(body) != "all" })
		if got := pages(alice); !slices.Equal(got, own) {
			t.Fatalf("case 13: %v, want %v", got, own)
		}
		// Case 14: both denied gives 403 after asking for both sets.
		pdp.allow(false)
		pdp.take()
		if _, err := ts.ListTasks(alice, &tes.ListTasksRequest{View: "FULL"}); code(err) != codes.PermissionDenied {
			t.Fatalf("case 14: %v, want PermissionDenied", err)
		}
		requests := pdp.take()
		if len(requests) != 2 || resourceID(requests[0].body) != "all" || resourceID(requests[1].body) != "own" {
			t.Fatalf("case 14 requests = %v", requests)
		}
		for _, r := range requests {
			if _, ok := r.body["resource"].(map[string]any)["properties"]; ok || r.body["action"].(map[string]any)["properties"].(map[string]any)["view"] != "FULL" {
				t.Fatalf("list request shape = %v", r.body)
			}
		}
	})
}

func TestAuthzDecisionServiceFailures(t *testing.T) {
	// Cases 11b and 15: every failure is a 503 and executes nothing.
	for _, tt := range []struct {
		name string
		set  func(*stubPDP)
	}{
		{"timeout", func(p *stubPDP) {
			p.mu.Lock()
			p.answer = func(map[string]any) (int, string) {
				time.Sleep(500 * time.Millisecond)
				return 200, `{"decision": true}`
			}
			p.mu.Unlock()
		}},
		{"500", func(p *stubPDP) { p.respond(500, `{"decision": true}`) }},
		{"string true", func(p *stubPDP) { p.respond(200, `{"decision": "true"}`) }},
		{"no decision", func(p *stubPDP) { p.respond(200, `{}`) }},
		{"not JSON", func(p *stubPDP) { p.respond(200, `not json`) }},
		{"down", func(p *stubPDP) { p.Close() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pdp := newStubPDP(t)
			ts := newAuthzService(t, "boltdb", withPDP(pdp, &config.AuthzDecisionService{Timeout: durationpb.New(200 * time.Millisecond)}))
			id := create(t, ts, alice)
			tt.set(pdp)
			_, errCreate := ts.CreateTask(alice, simpleTask())
			_, errGet := ts.GetTask(alice, &tes.GetTaskRequest{Id: id})
			_, errMissing := ts.GetTask(alice, &tes.GetTaskRequest{Id: "no-such-task"})
			_, errCancel := ts.CancelTask(alice, &tes.CancelTaskRequest{Id: id})
			_, errList := ts.ListTasks(alice, &tes.ListTasksRequest{})
			for _, err := range []error{errCreate, errGet, errMissing, errCancel, errList} {
				if code(err) != codes.Unavailable {
					t.Errorf("err = %v, want Unavailable", err)
				}
			}
			ts.Authz = nil
			list, err := ts.ListTasks(alice, &tes.ListTasksRequest{View: "BASIC"})
			if err != nil || len(list.Tasks) != 1 || list.Tasks[0].State != tes.Queued {
				t.Fatalf("tasks after failures = %v, want one queued task", list.Tasks)
			}
		})
	}
}

func TestAuthzRulePassesPDPDenies(t *testing.T) {
	// Case 17.
	pdp := newStubPDP(t)
	server := withPDP(pdp, &config.AuthzDecisionService{})
	server.Authz.RequiredClaim = voRule
	ts := newAuthzService(t, "boltdb", server)
	pdp.allow(false)
	if _, err := ts.CreateTask(alice, simpleTask()); code(err) != codes.PermissionDenied {
		t.Fatalf("case 17: %v, want PermissionDenied", err)
	}
	if got := len(pdp.take()); got != 1 {
		t.Fatalf("PDP calls = %d, want 1", got)
	}
}

func TestAuthzDeniedCreateStoresNothing(t *testing.T) {
	// Case 8: a denied CreateTask gives 403 and stores no task.
	backends(t, func(t *testing.T, backend string) {
		pdp := newStubPDP(t)
		ts := newAuthzService(t, backend, withPDP(pdp, &config.AuthzDecisionService{}))
		pdp.allow(false)
		if _, err := ts.CreateTask(alice, simpleTask()); code(err) != codes.PermissionDenied {
			t.Fatalf("CreateTask = %v, want PermissionDenied", err)
		}
		pdp.allow(true)
		if list, err := ts.ListTasks(alice, &tes.ListTasksRequest{}); err != nil || len(list.Tasks) != 0 {
			t.Fatalf("ListTasks = %v, %v; want no tasks", list, err)
		}
	})
}

func TestAuthzBuiltInDefaultKeepsTaskAccess(t *testing.T) {
	// Case 22: without a decision service, TaskAccess decides as today.
	for _, tt := range []struct {
		mode    identity.AccessMode
		want    codes.Code
		listLen int
	}{{identity.AccessAll, codes.OK, 2}, {identity.AccessOwner, codes.PermissionDenied, 1}} {
		t.Run(string(tt.mode), func(t *testing.T) {
			ts := newAuthzService(t, "boltdb", withRule(voRule))
			bobTask := create(t, ts, as("bob-sub", map[string]any{"eduperson_entitlement": subgroup}, tt.mode))
			who := as("alice-sub", map[string]any{"eduperson_entitlement": subgroup}, tt.mode)
			create(t, ts, who)
			if _, err := ts.GetTask(who, &tes.GetTaskRequest{Id: bobTask}); code(err) != tt.want {
				t.Fatalf("GetTask = %v, want %v", err, tt.want)
			}
			if list, err := ts.ListTasks(who, &tes.ListTasksRequest{}); err != nil || len(list.Tasks) != tt.listLen {
				t.Fatalf("ListTasks = %d tasks, want %d", len(list.Tasks), tt.listLen)
			}
		})
	}
}

func TestAuthzSkipsWorkerPaths(t *testing.T) {
	pdp := newStubPDP(t)
	server := withPDP(pdp, &config.AuthzDecisionService{})
	server.Authz.RequiredClaim = voRule
	ts := newAuthzService(t, "boltdb", server)
	id := create(t, ts, alice)
	pdp.allow(false)
	pdp.take()
	worker := identity.WithUser(context.Background(), &identity.UserInfo{Username: "worker", IsAdmin: true, AccessMode: identity.AccessOwnerOrAdmin})
	internal := context.WithValue(as("carol-sub", nil, identity.AccessAll), InternalCallKey, true)
	for name, ctx := range map[string]context.Context{"Basic admin": worker, "event write check": internal} {
		if _, err := ts.GetTask(ctx, &tes.GetTaskRequest{Id: id}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	oidcAdmin := as("admin", map[string]any{"eduperson_entitlement": subgroup}, identity.AccessAll)
	identity.GetUser(oidcAdmin).IsAdmin = true
	if _, err := ts.GetTask(oidcAdmin, &tes.GetTaskRequest{Id: id}); code(err) != codes.NotFound {
		t.Errorf("OIDC admin: %v, want NotFound (the PDP decides)", err)
	}
	if got := len(pdp.take()); got != 1 {
		t.Fatalf("PDP calls = %d, want 1 (OIDC admin only)", got)
	}
}

func TestAuthzStartupChecks(t *testing.T) {
	// Case 23 and the fail-safe checks of spec section 4.2.
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	credential := filepath.Join(dir, "credential")
	writeFile(t, empty, " \n")
	writeFile(t, credential, "pep-secret\n")
	basic := []*config.BasicCredential{{User: "u", Password: "p"}}
	pdpAt := func(conf *config.AuthzDecisionService) *config.Server {
		return &config.Server{BasicAuth: basic, Authz: &config.Authz{DecisionService: conf}}
	}
	for _, tt := range []struct {
		name string
		conf *config.Server
		ok   bool
	}{
		{"nothing set", &config.Server{}, true},
		{"auth disabled", withRule(voRule), false},
		{"rule without values", &config.Server{BasicAuth: basic, Authz: &config.Authz{RequiredClaim: &config.AuthzRequiredClaim{Name: "x"}}}, false},
		{"values without name", &config.Server{BasicAuth: basic, Authz: &config.Authz{RequiredClaim: &config.AuthzRequiredClaim{Values: []string{"a"}}}}, false},
		{"empty prefix", &config.Server{BasicAuth: basic, Authz: &config.Authz{RequiredClaim: &config.AuthzRequiredClaim{Name: "x", Prefixes: []string{""}}}}, false},
		{"decision service without URL", pdpAt(&config.AuthzDecisionService{Claims: []string{"x"}}), false},
		{"URL without host", pdpAt(&config.AuthzDecisionService{URL: "http:///access/v1/evaluation"}), false},
		{"URL not http", pdpAt(&config.AuthzDecisionService{URL: "ftp://pdp/access/v1/evaluation"}), false},
		{"empty credential file", pdpAt(&config.AuthzDecisionService{URL: "https://pdp/e", CredentialFile: empty}), false},
		{"missing credential file", pdpAt(&config.AuthzDecisionService{URL: "https://pdp/e", CredentialFile: filepath.Join(dir, "nope")}), false},
		{"zero timeout", pdpAt(&config.AuthzDecisionService{URL: "https://pdp/e", Timeout: durationpb.New(0)}), false},
		{"negative timeout", pdpAt(&config.AuthzDecisionService{URL: "https://pdp/e", Timeout: durationpb.New(-time.Second)}), false},
		{"valid", pdpAt(&config.AuthzDecisionService{URL: "https://pdp/e", CredentialFile: credential}), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthz(tt.conf, testLogger())
			if (err == nil) != tt.ok {
				t.Fatalf("NewAuthz() error = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestAuthzSendsTheCredential(t *testing.T) {
	pdp := newStubPDP(t)
	credential := filepath.Join(t.TempDir(), "credential")
	writeFile(t, credential, "pep-secret\n")
	ts := newAuthzService(t, "boltdb", withPDP(pdp, &config.AuthzDecisionService{CredentialFile: credential}))
	create(t, ts, alice)
	if got := pdp.take()[0].headers.Get("Authorization"); got != "Bearer pep-secret" {
		t.Fatalf("Authorization = %q", got)
	}
}

// testLogger logs errors only, so test output stays readable.
func testLogger() *logger.Logger {
	conf := logger.DefaultConfig()
	conf.Level = "error"
	return logger.NewLogger("authz-test", conf)
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// roundTrip converts a value through JSON into out; a *string gets the JSON text.
func roundTrip(value any, out any) {
	raw, err := json.Marshal(value)
	if text, ok := out.(*string); ok && err == nil {
		*text = string(raw)
		return
	}
	if err == nil {
		err = json.Unmarshal(raw, out)
	}
	if err != nil {
		panic(err)
	}
}
