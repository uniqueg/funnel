# External authorization (AuthZEN)

Funnel can delegate task authorization to an external decision service and
can admit callers by a token claim. Both are off by default; without them,
`TaskAccess` decides as before. The behaviour follows the TES AuthZ profile
`tes-authzen/1`, which uses OpenID AuthZEN 1.0 Access Evaluation requests.

```yaml
Server:
  Authz:
    # Optional claim rule: admit a caller only if this claim (exact top-level
    # name first, else a dotted path) holds one of Values or starts with one
    # of Prefixes. Prefixes are raw strings, so include the delimiter.
    RequiredClaim:
      Name: eduperson_entitlement
      Values:
        - "urn:geant:lifescience-ri.eu:group:example-vo#login.aai.lifescience-ri.eu"
      Prefixes:
        - "urn:geant:lifescience-ri.eu:group:example-vo:"

    # Optional decision service: when URL is set, it decides CreateTask,
    # GetTask, CancelTask and ListTasks instead of TaskAccess.
    DecisionService:
      URL: "https://pdp.example.org/access/v1/evaluation"
      # Positive; default 2s.
      Timeout: 2s
      # Claims passed to the decision service, from the token and, if
      # enabled, userinfo (default: none).
      Claims:
        - eduperson_entitlement
      # Optional file with a bearer credential that Funnel sends to the
      # decision service. The access token itself is never sent.
      CredentialFile: /run/secrets/pdp-token
```

How it works:

- The claim rule and the decision service are combined with AND: when both
  are set, both must allow. A failing rule gives 403 on every task call.
  Service clients without the claim (such as client-credentials tokens) are
  rejected by the rule; leave the rule unset and admit them in the decision
  service instead. Basic-auth users who are not administrators carry no
  claims, so the rule rejects them too.
- The decision service gets one evaluation per decision: the caller
  (subject ID = the task owner Funnel stores, i.e. the token `sub` or the
  Basic username, plus `iss`, `sub`, `client_id`, `scope` and the listed
  claims), the TES operation, and the task (owner, state and tags) or a task
  set (`own` for CreateTask; `all` and `own` for ListTasks). On CreateTask, it
  sees a fixed projection of the task without commands, environment,
  input contents, backend parameters or URL credentials.
- A denied GetTask gives 404, a denied CancelTask 404 (403 if the caller may
  read the task), a denied CreateTask or ListTasks 403. ListTasks lists all
  tasks if the set `all` is allowed, else only the caller's tasks if `own`
  is allowed.
- Any failure of the decision service (timeout, connection error, non-200
  status, a body without a boolean `decision`) gives 503 and is not retried.
  The decision service and OIDC timeouts must be positive.
- Funnel refuses to start if `Authz` is set without `BasicAuth` or
  `OidcAuth`, if `RequiredClaim` has no `Name` or no values and prefixes, or
  contains an empty value or prefix, if `DecisionService` lacks a valid
  `http(s)` URL, or if the credential file is empty or unreadable. Plain
  `http` to a non-loopback host only logs a warning: secure the connection,
  e.g. with a service mesh.
- Basic-auth administrators bypass the rule and the decision service for all
  four operations: they are the service identities of workers and
  schedulers, whose task reads use these credentials. Give Basic admin
  credentials only to Funnel's own components.
- With `Authz` set, event writes and execution claims (the gRPC
  `EventService`) accept only Basic-auth administrators, so callers the
  hook rejects cannot change tasks through it; `TaskAccess` still checks
  the task. Scheduler calls are unchanged.
- The claim rule and `Claims` read the access token's claims and, with
  `Server.OidcAuth.Userinfo.Enabled`, the userinfo claims too (the token's
  value wins). See [OAuth2](oauth2.md).
- The subject ID is the task owner, which is only safe as the token `sub`;
  never derive owners from mutable claims such as `email`.
