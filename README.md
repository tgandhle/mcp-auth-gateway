# MCP Auth Gateway

An OAuth 2.1 / JWT-enforcing reverse proxy that sits in front of a Model
Context Protocol (MCP) server. It authenticates inbound requests, enforces
per-method scopes, and forwards verified identity to the upstream MCP server.

The MCP transport is JSON-RPC 2.0 over HTTP. MCP servers themselves usually do
no authorization. This gateway adds that layer without modifying the server:
point your MCP clients at the gateway, point the gateway at the server.

## What it does

- **Token verification.** Validates inbound bearer JWTs against a JWKS
  (RFC 7517) published by your authorization server. Enforces `iss`, `aud`,
  `exp`, `iat` (and `nbf` when present). Pins acceptable signing algorithms to asymmetric only
  (RS/ES/PS); `none` and HMAC algs are refused at construction time, which
  closes the algorithm-confusion class of bypass.
- **Key rotation.** Selects the verification key by the token's `kid`. On a
  `kid` miss it force-refreshes the JWKS once before failing closed, and rebuilds
  its JWKS client at most once per cooldown window. Known limitation: the
  cooldown caps client *rebuilds*, not the underlying JWKS-library fetch on an
  unknown `kid`, so unknown-`kid` traffic is not yet fully bounded against the
  authorization server. Fully capping outbound fetches (an explicitly owned
  `kid`->key map with single-flight refresh, and moving JWKS I/O off the request
  event loop) is a tracked hardening item.
- **Per-method scope enforcement.** MCP methods (`tools/call`, `tools/list`,
  `resources/read`, ...) are mapped to required scopes by a policy. Read vs.
  invoke is separated by default. Unknown methods are denied by default.
- **Protected-resource metadata.** Serves RFC 9728
  `/.well-known/oauth-protected-resource` so spec-compliant MCP clients can
  discover which authorization server guards this resource. 401 responses
  carry a `WWW-Authenticate` header pointing at it.
- **Identity forwarding.** Strips the inbound `Authorization` header before
  proxying and passes verified `sub` / scopes to the upstream via
  `X-Forwarded-Sub` / `X-Forwarded-Scopes`. The upstream trusts these only
  because it sits behind this gateway on a private network.
- **PKCE helper.** RFC 7636 verifier/challenge generation and authorization-URL
  building, for clients that need to acquire tokens.
- **Audit logging.** Every authorization decision emits one structured JSON line
  on the `mcp_gateway.audit` logger: request id, subject, method, decision,
  required scopes, held-scope count, upstream status, latency, source IP. Raw
  tokens and PKCE verifiers are never logged. Scope *values* appear only at
  DEBUG; INFO logs the count.
- **Resilience guards.** Configurable max request body size (default 5 MiB,
  returns `413`) and per-phase upstream timeouts (connect/read/write/pool).

## Why these choices

The gateway verifies tokens; it does not issue them. In an enterprise setup an
IdP (PingFederate, Entra, Auth0, Okta) runs the authorization-code + PKCE flow
and issues the JWT. The gateway's job is the resource-server half of OAuth:
verify the token and enforce scope. That separation is deliberate and matches
how this is deployed in practice.

## Configuration

All config is environment-driven (prefix `GATEWAY_`) or via a `.env` file.

| Variable | Required | Meaning |
|---|---|---|
| `GATEWAY_UPSTREAM_URL` | yes | Backend MCP server URL, e.g. `http://127.0.0.1:9000/mcp` |
| `GATEWAY_ISSUER` | yes | Required `iss` claim; also the auth-server id in metadata |
| `GATEWAY_AUDIENCE` | yes | Required `aud` claim; this gateway's resource id |
| `GATEWAY_JWKS_URL` | yes (if auth on) | JWKS endpoint of the authorization server |
| `GATEWAY_JWKS_MIN_REFRESH_INTERVAL` | no | Min seconds between forced JWKS client rebuilds on a `kid` miss; default `10`. Caps rebuild cadence (see the key-rotation note on its limits, it does not yet fully bound outbound fetches) |
| `GATEWAY_ALLOWED_ALGORITHMS` | no | Default `["RS256","ES256"]` |
| `GATEWAY_SCOPE_POLICY_FILE` | no | JSON scope policy; built-in default if unset |
| `GATEWAY_TOOL_POLICY_FILE` | no | JSON tool allow-list; enables per-tool authorization on `tools/call`. Unset means tool authorization is off (scope only) |
| `GATEWAY_REQUIRE_AUTH` | no | Default `true`; set `false` only for local dev |
| `GATEWAY_HOST` / `GATEWAY_PORT` | no | Default `127.0.0.1:8080` |
| `GATEWAY_PUBLIC_BASE_URL` | no | External URL (e.g. `https://mcp.example.com`) for metadata/`WWW-Authenticate` when behind TLS or a load balancer |
| `GATEWAY_MAX_REQUEST_BYTES` | no | Reject bodies larger than this; default 5 MiB, `0` disables |
| `GATEWAY_MAX_RESPONSE_BYTES` | no | Cap upstream response size; default 10 MiB, `0` disables. Over-cap `Content-Length` returns `413`; mid-stream overflow is truncated |
| `GATEWAY_CONNECT_TIMEOUT` / `_READ_TIMEOUT` / `_WRITE_TIMEOUT` / `_POOL_TIMEOUT` | no | Per-phase upstream timeouts; fall back to `GATEWAY_UPSTREAM_TIMEOUT` |

## Run

```bash
pip install -e ".[dev]"

export GATEWAY_UPSTREAM_URL=http://127.0.0.1:9000/mcp
export GATEWAY_ISSUER=https://login.example.com/
export GATEWAY_AUDIENCE=mcp-gateway
export GATEWAY_JWKS_URL=https://login.example.com/.well-known/jwks.json

mcp-gateway
```

The gateway validates its configuration at startup and refuses to run on an
unsafe or unusable config (auth enabled with no JWKS URL, a symmetric or `none`
signing algorithm, a missing scope-policy file, out-of-range port or timeouts,
a `public_base_url` with no scheme). All problems are reported together and the
process exits non-zero, so misconfiguration is caught at boot rather than on the
first request.

## Scope policy file format

```json
{
  "rules": {
    "initialize": [],
    "tools/list": ["mcp:read"],
    "tools/call": ["mcp:invoke"],
    "resources/": ["mcp:read"]
  },
  "default": [],
  "deny_by_default": true
}
```

A key ending in `/` is a prefix rule covering every method beneath it. An exact
method rule overrides a prefix rule. All scopes listed for a rule are required
(AND).

## Tool-call authorization

Scope policy controls whether a token may call `tools/call` at all. Tool-call
authorization is a second, narrower axis: given that a caller may invoke tools,
*which* tools may it invoke? It enforces per-tool authorization on the proxy
boundary at the point the gateway parses a `tools/call` request.

The policy is an allow-list. A tool is permitted only if its name appears in
`allowed_tools`; every other tool is denied. Allow-list-only is deliberate: it
makes deny-by-default total and verifiable by reading the file, which is the
posture you want for autonomous agents (enumerate what may run, refuse the
rest).

```json
{
  "allowed_tools": [
    "read_file",
    "list_directory",
    "search_documents"
  ]
}
```

Point the gateway at it with `GATEWAY_TOOL_POLICY_FILE=examples/tool-policy.json`.

Behavior, when a tool policy is configured:

- A `tools/call` naming an allow-listed tool is forwarded (subject to scope
  passing first).
- A `tools/call` naming a tool not on the allow-list is denied with
  `403 tool_not_allowed` and never forwarded.
- A `tools/call` whose `params.name` is missing or not a string cannot be
  resolved to a tool and is rejected with `400 invalid_tool_call`. This is a
  malformed request, distinct from an authorization denial.
- Matching is exact and case-sensitive: `read_file` and `Read_File` are
  different tools.

This layer is **opt-in and backward-compatible**. With `GATEWAY_TOOL_POLICY_FILE`
unset, tool-call authorization is not applied and `tools/call` is governed by
scope alone, exactly as before. Enabling it is a deliberate act; upgrading
without setting the variable changes nothing.

The check runs after the scope check, so scope is the outer gate: a token
lacking `mcp:invoke` is stopped with `insufficient_scope` before the tool
allow-list is consulted. Every tool decision is written to the audit log with
the `tool_name` and the decision, alongside the existing scope decision fields.

## Tests

```bash
pytest
```

Tests sign real RS256 JWTs with a generated RSA key and exercise the verifier,
the scope policy, the PKCE helper, and the full proxy path (including that the
`Authorization` header is not forwarded upstream and that a read-scoped token
cannot invoke a tool).

## Status and limits

- JSON-RPC batch requests (arrays) are rejected with `400 batch_not_supported`,
  because per-item authorization is not implemented and forwarding an
  unchecked batch would let a caller smuggle a method past the scope check.
  Malformed JSON and JSON-RPC objects without a string `method` are likewise
  rejected with `400` rather than proxied. The authorization path fails closed.
- Streaming (SSE) MCP responses are proxied as true streams: the gateway streams
  the upstream response through chunk by chunk rather than buffering it. The
  upstream response body is capped (`GATEWAY_MAX_RESPONSE_BYTES`, default 10 MiB):
  an over-cap `Content-Length` is rejected with `413` before streaming, and a
  stream that exceeds the cap mid-flight is truncated and terminated.
- The protected-resource metadata and `WWW-Authenticate` URLs honor
  `GATEWAY_PUBLIC_BASE_URL` when set, and fall back to the bind host/port. Set
  it when running behind TLS or a load balancer.

### Known limitations (tracked hardening items)

These are known gaps, stated plainly so the security posture isn't overstated.
Each is a tracked item, not a claimed guarantee.

- **JWKS fetch bounding.** The `kid`-miss cooldown caps how often the gateway
  rebuilds its JWKS client, but the underlying JWKS library still fetches on an
  unknown `kid` within the window, so outbound JWKS requests under a flood of
  distinct bogus `kid` values are not yet fully bounded. JWKS verification also
  runs synchronously on the request path, so a slow authorization server can
  block the event loop. Fix: an explicitly owned `kid`->key map with
  single-flight refresh, and async/off-loop JWKS I/O.
- **Request-size limit.** An oversized numeric `Content-Length` is rejected
  before the body is read, but a chunked or unlabeled body is buffered fully
  before the size check, so the limit is not a hard memory bound in those cases.
  Fix: enforce the cap while streaming the request. Pair with an ingress body
  limit regardless.
- **Outbound identity headers.** Inbound identity headers are stripped via a
  denylist of known conventions, which is not exhaustive. An upstream that
  trusts a header outside that set could be misled. Configure the upstream to
  trust only the gateway-generated `X-Forwarded-*` identity headers. Fix: an
  outbound allowlist forwarding only transport-required headers.
- **MCP Origin validation.** The gateway does not yet validate the `Origin`
  header (the MCP spec's DNS-rebinding defense for Streamable HTTP). Fix: an
  allowed-origins check returning `403` on an unapproved present origin.
- **Plaintext JWKS URL.** `GATEWAY_JWKS_URL` currently permits `http://`. Use
  an `https://` endpoint; a future change will require TLS by default and allow
  plaintext only for loopback/dev.
- **Readiness vs. liveness.** `/healthz` serves both and always returns ok, so a
  pod can be marked ready before it can retrieve verification keys. Fix: split
  `/livez` (process alive) from `/readyz` (config, policy, and a recent JWKS
  retrieval).
- **Kubernetes trust boundary.** The sample `NetworkPolicy` selects on the pod
  label `app: gateway`; it authenticates labels, not workload identity. Anyone
  able to create pods in the namespace with that label could reach the upstream.
  Treat it as network segmentation, not workload authentication; pair with
  namespace RBAC, admission control, and mesh mTLS/SPIFFE for real workload
  identity.
- **Tool policy is opt-in.** With no `GATEWAY_TOOL_POLICY_FILE` set, a token
  holding `mcp:invoke` may call any tool the upstream exposes. This is a
  deliberate backward-compatible default, not a defect; configure a tool policy
  to enforce per-tool least privilege.

## Security

The [threat model](docs/THREAT-MODEL.md) states what the gateway defends
against, what it does not, and the preconditions its security depends on (most
importantly, that the upstream is not reachable directly by clients). Each
defense points at the code or CI that backs it.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

MIT. See `LICENSE`.
