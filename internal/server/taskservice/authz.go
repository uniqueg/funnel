package taskservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/calypr/funnel/api/config"
	"github.com/calypr/funnel/api/tes"
	"github.com/calypr/funnel/internal/identity"
	"github.com/calypr/funnel/internal/logger"
	taskpolicy "github.com/calypr/funnel/internal/task"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Authz is the TES AuthZ hook (profile tes-authzen/1): a claim rule and,
// if configured, an OpenID AuthZEN 1.0 decision service that decides
// instead of TaskAccess. When both are set, both must allow.
type Authz struct {
	rule       *config.AuthzRequiredClaim
	url        string
	timeout    time.Duration
	claims     []string
	credential string
	client     *http.Client
	log        *logger.Logger
}

const authzProfile = "tes-authzen/1"

var (
	errAuthzForbidden   = status.Error(codes.PermissionDenied, "forbidden")
	errAuthzUnavailable = status.Error(codes.Unavailable, "authorization service unavailable")
)

// NewAuthz validates Server.Authz and returns the hook, or nil if unset.
func NewAuthz(conf *config.Server, log *logger.Logger) (*Authz, error) {
	rule, pdp := conf.GetAuthz().GetRequiredClaim(), conf.GetAuthz().GetDecisionService()
	if rule.GetName() == "" && len(rule.GetValues())+len(rule.GetPrefixes()) == 0 {
		rule = nil
	}
	if rule == nil && pdp == nil {
		return nil, nil
	}
	switch {
	case len(conf.GetBasicAuth()) == 0 && conf.GetOidcAuth().GetServiceConfigURL() == "":
		return nil, errors.New("Server.Authz requires Server.BasicAuth or Server.OidcAuth")
	case rule != nil && (rule.Name == "" || len(rule.Values)+len(rule.Prefixes) == 0):
		return nil, errors.New("Server.Authz.RequiredClaim needs a Name and Values or Prefixes")
	case rule != nil && (slices.Contains(rule.Values, "") || slices.Contains(rule.Prefixes, "")):
		return nil, errors.New("Server.Authz.RequiredClaim must not contain empty values or prefixes")
	}
	a := &Authz{rule: rule, log: log}
	if pdp == nil {
		return a, nil
	}
	u, err := url.Parse(pdp.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("Server.Authz.DecisionService.URL must be an http(s) URL with a host")
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Warn("Server.Authz.DecisionService.URL uses plain http to a non-loopback host; secure the connection, e.g. with mesh mTLS")
	}
	a.url, a.claims, a.timeout = pdp.URL, pdp.Claims, 2*time.Second
	if pdp.Timeout != nil {
		a.timeout = pdp.Timeout.AsDuration()
	}
	if a.timeout <= 0 {
		return nil, errors.New("Server.Authz.DecisionService.Timeout must be positive")
	}
	if pdp.CredentialFile != "" {
		raw, err := os.ReadFile(pdp.CredentialFile)
		if a.credential = strings.TrimSpace(string(raw)); err != nil || a.credential == "" {
			return nil, fmt.Errorf("Server.Authz.DecisionService.CredentialFile is empty or unreadable: %v", err)
		}
	}
	a.client = &http.Client{Timeout: a.timeout}
	return a, nil
}

// skip reports whether the hook leaves the call alone: no hook, in-process
// worker checks (EventWriteInterceptor), and Basic-auth administrators
// (admins without token claims), the service identities of workers and
// schedulers. They are exempt from all four actions.
func (a *Authz) skip(ctx context.Context) bool {
	user := identity.GetUser(ctx)
	return a == nil || ctx.Value(InternalCallKey) != nil || user.IsAdmin && user.Claims == nil && !user.IsPublic
}

// lookup finds a claim: exact name before dotted path, token before
// userinfo at each step.
func lookup(user *identity.UserInfo, name string) (any, bool) {
	views := []map[string]any{}
	for _, claims := range []*identity.Claims{user.Claims, user.Userinfo} {
		if claims != nil {
			views = append(views, *claims)
		}
	}
	for _, view := range views {
		if value, ok := view[name]; ok {
			return value, true
		}
	}
	for _, view := range views {
		var value any = view
		ok := true
		for _, part := range strings.Split(name, ".") {
			object, isObject := value.(map[string]any)
			if value, ok = object[part]; !isObject || !ok {
				break
			}
		}
		if ok {
			return value, true
		}
	}
	return nil, false
}

// admit runs the checks before a decision: it reports whether the
// decision service must be asked, or the claim rule's error.
func (a *Authz) admit(ctx context.Context) (bool, error) {
	if a.skip(ctx) {
		return false, nil
	}
	if err := a.gate(ctx); err != nil {
		return false, err
	}
	return a.url != "", nil
}

// gate applies the claim rule.
func (a *Authz) gate(ctx context.Context) error {
	if a.rule == nil {
		return nil
	}
	value, _ := lookup(identity.GetUser(ctx), a.rule.Name)
	if s, ok := value.(string); ok {
		value = []any{s}
	}
	values, _ := value.([]any)
	match := false
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			return errAuthzForbidden
		}
		match = match || slices.Contains(a.rule.Values, s) || slices.ContainsFunc(a.rule.Prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
	}
	if !match {
		return errAuthzForbidden
	}
	return nil
}

// subject is the AuthZEN subject: the validated identity, never the token.
func (a *Authz) subject(user *identity.UserInfo) map[string]any {
	claims := map[string]any{}
	for _, name := range a.claims {
		if value, ok := lookup(user, name); ok {
			claims[name] = value
		}
	}
	properties := map[string]any{"claims": claims}
	t := identity.Claims{}
	if user.Claims != nil {
		t = *user.Claims
	}
	first := func(key string, names ...string) {
		for _, name := range names {
			if value, ok := t[name]; ok && value != nil {
				properties[key] = value
				return
			}
		}
	}
	first("iss", "iss")
	first("sub", "sub")
	first("client_id", "azp", "client_id")
	first("scope", "scope", "scp")
	if s, ok := properties["scope"].(string); ok {
		properties["scope"] = strings.Fields(s)
	}
	return map[string]any{"type": "user", "id": user.Username, "properties": properties}
}

// ask asks the decision service once; any failure is a 503 that the
// gateway must not retry (negative gRPC retry pushback).
func (a *Authz) ask(ctx context.Context, action string, resource, properties map[string]any) (bool, error) {
	requestID := uuid.NewString()
	body, err := json.Marshal(map[string]any{
		"subject":  a.subject(identity.GetUser(ctx)),
		"action":   map[string]any{"name": action, "properties": properties},
		"resource": resource,
		"context":  map[string]any{"tes": map[string]any{"profile": authzProfile, "service_id": serviceID}},
	})
	var decision *bool
	if err == nil {
		decision, err = a.post(ctx, body, requestID)
	}
	if err != nil {
		a.log.Error("decision service failed", "action", action, "resource", resource["id"], "requestID", requestID, "error", err)
		// Without this, the HTTP gateway's retry policy for UNAVAILABLE
		// (server.go) repeats the call up to four times.
		_ = grpc.SetTrailer(ctx, metadata.Pairs("grpc-retry-pushback-ms", "-1")) //nolint:errcheck // No gRPC stream in direct calls.
		return false, errAuthzUnavailable
	}
	a.log.Info("decision", "decision", *decision, "action", action, "resource", resource["id"], "requestID", requestID)
	return *decision, nil
}

// post sends one evaluation and returns the boolean decision.
func (a *Authz) post(ctx context.Context, body []byte, requestID string) (*bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", requestID)
	if a.credential != "" {
		request.Header.Set("Authorization", "Bearer "+a.credential)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close() //nolint:errcheck // Read-only response cleanup cannot change the decision.
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", response.Status)
	}
	var answer struct{ Decision *bool }
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&answer); err != nil {
		return nil, err
	}
	if answer.Decision == nil {
		return nil, errors.New("no boolean decision")
	}
	return answer.Decision, nil
}

// taskResource reads a task's owner, state and tags without an owner
// filter; properties are empty for a missing task, owner left out if unknown.
func taskResource(ctx context.Context, read taskpolicy.ReadOnlyServer, id string) (map[string]any, bool, error) {
	probe, owner := identity.WithOwnerProbe(ctx)
	task, err := read.GetTask(probe, &tes.GetTaskRequest{Id: id, View: tes.View_BASIC.String()})
	if errors.Is(err, taskpolicy.ErrNotFound) {
		return map[string]any{"type": "tes_task", "id": id, "properties": map[string]any{}}, false, nil
	} else if err != nil {
		return nil, false, err
	}
	tags := task.GetTags()
	if tags == nil {
		tags = map[string]string{}
	}
	properties := map[string]any{"state": task.GetState().String(), "tags": tags}
	if name, seen := owner(); seen && name != "" {
		properties["owner"] = name
	}
	return map[string]any{"type": "tes_task", "id": id, "properties": properties}, true, nil
}

// authorizeTask decides GetTask and CancelTask (spec section 6) and returns
// a context in which the backends no longer filter by owner.
func (a *Authz) authorizeTask(ctx context.Context, read taskpolicy.ReadOnlyServer, action, id, view string) (context.Context, error) {
	if decide, err := a.admit(ctx); !decide {
		return ctx, err
	}
	resource, exists, err := taskResource(ctx, read, id)
	if err != nil {
		return ctx, err
	}
	properties := map[string]any{}
	if action == "GetTask" {
		properties["view"] = view
	}
	allowed, err := a.ask(ctx, action, resource, properties)
	if err != nil {
		return ctx, err
	}
	if exists && allowed {
		return identity.WithAccess(ctx, identity.AccessAll), nil
	}
	if action == "CancelTask" {
		readable, err := a.ask(ctx, "GetTask", resource, map[string]any{})
		if err != nil {
			return ctx, err
		}
		if exists && readable {
			return ctx, errAuthzForbidden
		}
	}
	return ctx, status.Errorf(codes.NotFound, "%v: taskID: %s", taskpolicy.ErrNotFound, id)
}

// authorizeList asks for the task sets "all" and "own" and returns a
// context that lists all tasks or only the caller's.
func (a *Authz) authorizeList(ctx context.Context, view string) (context.Context, error) {
	if decide, err := a.admit(ctx); !decide {
		return ctx, err
	}
	askSet := func(set string) (bool, error) {
		return a.ask(ctx, "ListTasks", map[string]any{"type": "tes_task_set", "id": set}, map[string]any{"view": view})
	}
	all, err := askSet("all")
	if err != nil {
		return ctx, err
	}
	own, err := askSet("own")
	switch {
	case err != nil:
		return ctx, err
	case all:
		return identity.WithAccess(ctx, identity.AccessAll), nil
	case own:
		return identity.WithAccess(ctx, identity.AccessOwner), nil
	}
	return ctx, errAuthzForbidden
}

// authorizeCreate decides CreateTask on the caller's task set.
func (a *Authz) authorizeCreate(ctx context.Context, task *tes.Task) (context.Context, error) {
	if decide, err := a.admit(ctx); !decide {
		return ctx, err
	}
	resource := map[string]any{"type": "tes_task_set", "id": "own", "properties": map[string]any{"task": project(task)}}
	allowed, err := a.ask(ctx, "CreateTask", resource, map[string]any{})
	if err == nil && !allowed {
		err = errAuthzForbidden
	}
	return ctx, err
}

// project is the fixed projection of a submitted task: no commands,
// environments, input contents, backend parameters or URL credentials.
func project(task *tes.Task) map[string]any {
	out := map[string]any{}
	if task.Name != "" {
		out["name"] = task.Name
	}
	if task.Tags != nil {
		out["tags"] = task.Tags
	}
	if r := task.Resources; r != nil {
		zones := r.Zones
		if zones == nil {
			zones = []string{}
		}
		out["resources"] = map[string]any{"cpu_cores": r.CpuCores, "ram_gb": r.RamGb, "disk_gb": r.DiskGb, "preemptible": r.Preemptible, "zones": zones}
	}
	if task.Volumes != nil {
		out["volumes"] = task.Volumes
	}
	executors := []any{}
	for _, e := range task.Executors {
		executors = append(executors, map[string]any{"image": e.Image})
	}
	out["executors"] = executors
	file := func(u, path string, t tes.FileType) map[string]any {
		f := map[string]any{"path": path, "type": t.String()}
		if stripped, ok := stripURL(u); ok && u != "" {
			f["url"] = stripped
		}
		return f
	}
	if task.Inputs != nil {
		inputs := []any{}
		for _, i := range task.Inputs {
			inputs = append(inputs, file(i.Url, i.Path, i.Type))
		}
		out["inputs"] = inputs
	}
	if task.Outputs != nil {
		outputs := []any{}
		for _, o := range task.Outputs {
			outputs = append(outputs, file(o.Url, o.Path, o.GetType()))
		}
		out["outputs"] = outputs
	}
	return out
}

// stripURL removes credentials, query and fragment from a URL with the
// plain string algorithm of spec section 3.3; ok is false to omit it.
func stripURL(u string) (string, bool) {
	scheme := 0
	for i, c := range u {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || strings.ContainsRune("+-.", c)) {
			continue
		}
		if i > 0 && strings.HasPrefix(u[i:], "://") {
			scheme = i + 3
		}
		break
	}
	if scheme == 0 {
		return u, !strings.ContainsAny(u, "@?")
	}
	rest := u[scheme:]
	w := rest
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		w = rest[:slash]
	}
	end := strings.IndexAny(w, "?#")
	if strings.ContainsRune(w, '\\') || end >= 0 && strings.LastIndexByte(w, '@') > end {
		return "", false
	}
	if end < 0 {
		end = len(w)
	}
	authority := w[:end][strings.LastIndexByte(w[:end], '@')+1:]
	path := rest[end:]
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
	}
	return u[:scheme] + authority + path, true
}
