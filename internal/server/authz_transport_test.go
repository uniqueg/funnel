package server_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/calypr/funnel/api/config"
	"github.com/calypr/funnel/api/tes"
	"github.com/calypr/funnel/internal/compute/noop"
	"github.com/calypr/funnel/internal/database/boltdb"
	"github.com/calypr/funnel/internal/events"
	"github.com/calypr/funnel/internal/identity"
	"github.com/calypr/funnel/internal/logger"
	"github.com/calypr/funnel/internal/server"
	"github.com/calypr/funnel/internal/server/taskservice"
	"github.com/calypr/funnel/internal/tesrpc"
)

// authzFixture is a running server whose TES API asks a stub decision
// service; decide answers each evaluation, calls counts them.
type authzFixture struct {
	mu       sync.Mutex
	decide   func(action, resource, subject string) (int, bool)
	calls    int
	grpc     tesrpc.TaskServiceClient
	events   events.EventServiceClient
	httpBase string
}

func (f *authzFixture) script(decide func(action, resource, subject string) (int, bool)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decide, f.calls = decide, 0
}

func (f *authzFixture) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func basic(user string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":synthetic"))
}

func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close() //nolint:errcheck // Only the port number is needed.
	return lis.Addr().(*net.TCPAddr).Port
}

func startAuthzServer(t *testing.T) *authzFixture {
	t.Helper()
	f := &authzFixture{}
	f.script(func(string, string, string) (int, bool) { return http.StatusOK, true })
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Subject  struct{ ID string }
			Action   struct{ Name string }
			Resource struct{ ID string }
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		f.mu.Lock()
		f.calls++
		code, decision := f.decide(body.Action.Name, body.Resource.ID, body.Subject.ID)
		f.mu.Unlock()
		w.WriteHeader(code)
		if _, err := fmt.Fprintf(w, `{"decision": %v}`, decision); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(pdp.Close)

	db, err := boltdb.NewBoltDB(&config.BoltDB{Path: filepath.Join(t.TempDir(), "tasks.db")})
	if err == nil {
		err = db.Init()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	log := logger.NewLogger("authz-transport", logger.DefaultConfig())
	log.Discard()
	users := []*config.BasicCredential{{User: "alice", Password: "synthetic"}, {User: "bob", Password: "synthetic"}, {User: "worker", Password: "synthetic", Admin: true}}
	serverConf := &config.Server{BasicAuth: users, Authz: &config.Authz{DecisionService: &config.AuthzDecisionService{URL: pdp.URL}}}
	authz, err := taskservice.NewAuthz(serverConf, log)
	if err != nil {
		t.Fatal(err)
	}
	rpcAddress := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	httpPort := strconv.Itoa(freePort(t))
	srv := &server.Server{
		RPCAddress: rpcAddress, HTTPPort: httpPort, Log: log, BasicAuth: users, TaskAccess: identity.AccessOwnerOrAdmin,
		Tasks:  &taskservice.Service{Read: db, Event: db, Compute: noop.NewBackend(), Log: log, Config: &config.Config{Server: serverConf}, Authz: authz},
		Events: &events.Service{Writer: db, Claimer: db},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("server did not stop")
		}
	})
	conn, err := grpc.NewClient(rpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	f.grpc, f.events = tesrpc.NewTaskServiceClient(conn), events.NewEventServiceClient(conn)
	f.httpBase = "http://127.0.0.1:" + httpPort + "/ga4gh/tes/v1"
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := http.Get(f.httpBase + "/service-info")
		if err == nil {
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			return f
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// transport runs one TES call over gRPC or the HTTP gateway and returns
// the HTTP status (gRPC codes mapped as the gateway maps them) and body.
type transport func(t *testing.T, f *authzFixture, user, method, path string, body any) (int, map[string]any)

var httpOf = map[codes.Code]int{codes.OK: 200, codes.PermissionDenied: 403, codes.NotFound: 404, codes.Unavailable: 503}

func overGRPC(t *testing.T, f *authzFixture, user, method, path string, body any) (int, map[string]any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", basic(user))), 10*time.Second)
	defer cancel()
	var result any
	var err error
	switch {
	case method == http.MethodPost && path == "/tasks":
		result, err = f.grpc.CreateTask(ctx, body.(*tes.Task))
	case method == http.MethodGet && path == "/tasks":
		result, err = f.grpc.ListTasks(ctx, &tes.ListTasksRequest{})
	case method == http.MethodPost:
		result, err = f.grpc.CancelTask(ctx, &tes.CancelTaskRequest{Id: path[len("/tasks/") : len(path)-len(":cancel")]})
	default:
		result, err = f.grpc.GetTask(ctx, &tes.GetTaskRequest{Id: path[len("/tasks/"):]})
	}
	if err != nil {
		return httpOf[status.Code(err)], nil
	}
	raw, err := json.Marshal(result)
	var out map[string]any
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 200, out
}

func overHTTP(t *testing.T, f *authzFixture, user, method, path string, body any) (int, map[string]any) {
	t.Helper()
	raw := []byte("{}")
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, f.httpBase+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", basic(user))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close() //nolint:errcheck // Test response cleanup.
	var out map[string]any
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, out
}

func TestAuthzSameResultsOverGRPCAndHTTP(t *testing.T) {
	// Spec case 24: cases 7, 10 and 13 (plus 15) over gRPC as over HTTP.
	f := startAuthzServer(t)
	for name, call := range map[string]transport{"gRPC": overGRPC, "HTTP": overHTTP} {
		t.Run(name, func(t *testing.T) {
			task := &tes.Task{Name: "t", Executors: []*tes.Executor{{Image: "alpine", Command: []string{"true"}}}}
			f.script(func(string, string, string) (int, bool) { return http.StatusOK, true })
			// Case 7: create allowed.
			code, aliceTask := call(t, f, "alice", http.MethodPost, "/tasks", task)
			_, bobTask := call(t, f, "bob", http.MethodPost, "/tasks", task)
			if code != 200 || aliceTask["id"] == nil || bobTask["id"] == nil || f.callCount() != 2 {
				t.Fatalf("case 7: %d %v, PDP calls %d", code, aliceTask, f.callCount())
			}
			bobID := bobTask["id"].(string)
			// Case 10: denied get and cancel are 404.
			f.script(func(string, string, string) (int, bool) { return http.StatusOK, false })
			if code, _ := call(t, f, "alice", http.MethodGet, "/tasks/"+bobID, nil); code != 404 {
				t.Fatalf("case 10 get: %d", code)
			}
			if code, _ := call(t, f, "alice", http.MethodPost, "/tasks/"+bobID+":cancel", nil); code != 404 {
				t.Fatalf("case 10 cancel: %d", code)
			}
			// Case 13: own scope lists only Alice's tasks, although the
			// built-in TaskAccess would not filter at all for "worker".
			f.script(func(action, resource, _ string) (int, bool) { return http.StatusOK, resource != "all" })
			_, list := call(t, f, "alice", http.MethodGet, "/tasks", nil)
			for _, item := range list["tasks"].([]any) {
				if item.(map[string]any)["id"] == bobID {
					t.Fatalf("case 13: own scope lists Bob's task: %v", list)
				}
			}
			// Case 15: a failure is one 503, not retried by the gateway.
			f.script(func(string, string, string) (int, bool) { return http.StatusInternalServerError, true })
			if code, _ := call(t, f, "alice", http.MethodGet, "/tasks/"+bobID, nil); code != 503 || f.callCount() != 1 {
				t.Fatalf("case 15: %d after %d PDP calls, want 503 after 1", code, f.callCount())
			}
		})
	}
}

func TestAuthzLeavesWorkerPathsAlone(t *testing.T) {
	f := startAuthzServer(t)
	_, created := overGRPC(t, f, "alice", http.MethodPost, "/tasks", &tes.Task{Name: "t", Executors: []*tes.Executor{{Image: "alpine", Command: []string{"true"}}}})
	id := created["id"].(string)
	f.script(func(string, string, string) (int, bool) { return http.StatusOK, false })
	// Workers read tasks over the TES API with Basic admin credentials.
	if code, _ := overGRPC(t, f, "worker", http.MethodGet, "/tasks/"+id, nil); code != 200 {
		t.Fatalf("worker GetTask: %d", code)
	}
	// Event writes need worker credentials and never ask the decision
	// service: the owner, whom the hook may reject, cannot write events.
	write := func(user string) error {
		ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", basic(user))), 10*time.Second)
		defer cancel()
		_, err := f.events.WriteEvent(ctx, events.NewSystemLog(id, 0, 0, "info", "marker", nil))
		return err
	}
	if err := write("worker"); err != nil {
		t.Fatalf("worker event write: %v", err)
	}
	if err := write("alice"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("owner event write = %v, want PermissionDenied", err)
	}
	if f.callCount() != 0 {
		t.Fatalf("PDP calls on worker paths = %d, want 0", f.callCount())
	}
}
