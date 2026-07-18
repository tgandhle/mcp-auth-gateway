# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow semantic versioning once a tagged release is cut.

## [Unreleased]

### Fixed

- MCP lifecycle coverage in the scope policies. The builtin policy (and
  `examples/scope-policy.json`) had no rule for the `notifications/*` family,
  so deny-by-default returned 403 on the mandatory `notifications/initialized`
  notification and killed every spec-compliant client session immediately
  after the handshake. Verified end to end with the official MCP SDK as both
  client and upstream (Linux and Windows): the session died before the first
  post-handshake call, and a `notifications/` rule restored the full flow.
  The builtin policy now covers the complete client-to-server surface:
  `notifications/` (scope-free; token still required), `resources/` as a
  prefix (adds `resources/templates/list` and `resources/unsubscribe`),
  `prompts/` as a prefix, and `logging/setLevel` (gated as `mcp:invoke`, it
  mutates server state). `tests/test_mcp_method_surface.py` walks the spec's
  client-to-server method list against both policies so the gap cannot
  reopen. (`verification/run_e2e.ps1` is the end-to-end regression harness.)
- Audit events now reach output as shipped. The `mcp_gateway.audit` logger had
  no handler when run via the entrypoint, so INFO events (every allowed
  decision and every stream-completion event) were dropped; only WARNING+
  leaked to stderr via Python's last-resort handler. Verified empirically: a
  fully successful end-to-end session produced zero visible audit lines. The
  entrypoint now attaches a stdout handler at INFO (idempotent, and deferential
  to operator-configured handlers or levels). (`tests/test_audit_logging.py`.)
- Non-finite JSON constants are rejected. `json.loads` accepts
  `NaN`/`Infinity`/`-Infinity` and `json.dumps` re-emits them, so the
  canonical body could carry non-RFC 8259 tokens: a lax upstream parses them,
  a strict one rejects the request, which is the parser-family divergence
  canonicalization exists to eliminate. The parser now refuses them with
  `400 nonstandard_json_constant`. (`tests/test_parser_differential.py`.)

### Changed

- README corrected to match the PR #19 implementation: the key-rotation
  bullet, the `GATEWAY_JWKS_MIN_REFRESH_INTERVAL` row, and the first Known
  limitations entry still described the pre-#19 design (client rebuilds,
  unbounded library fetches). The remaining true limitation, synchronous JWKS
  I/O on the request event loop, is now stated on its own, including that the
  refresh is triggerable without a valid signature.

### Added

- End-to-end verification harness (`verification/run_e2e.ps1`,
  `verification/real_upstream.py`, `verification/e2e_client.py`): a real MCP
  SDK server and client driven through the gateway, exercising the full
  lifecycle under the builtin policy and under a policy file.

## [0.2.0] - 2026-07-17

Security-hardening release. Consolidates the work since v0.1.0 and addresses two
external security reviews. See `docs/SECURITY-REVIEW-HISTORY.md` for the
finding-by-finding evidence index, and the v0.2.0 release notes for a summary
organized by security outcome. Verified from a clean clone at commit
`937eb904ee223f139326c4d4fd7f06f85e82d694`: 113 tests pass, ruff/mypy/bandit
clean, and a dependency audit of the locked runtime dependencies reports no known
vulnerabilities.

### Security

- Duplicate-key authorization bypass closed (#20). `json.loads` silently keeps
  the last value for a duplicate object member; a first-wins upstream parser
  would keep a different one, which could let the gateway authorize one method
  or tool while the upstream executed another. The parser now rejects any object
  with duplicate member names (recursively) and forwards a canonical
  re-serialization of the validated object instead of the original bytes, so the
  upstream parses exactly what the gateway authorized. Regression test includes
  the reviewer's proof-of-concept and asserts the request never reaches the
  upstream. (`tests/test_parser_differential.py`.)
- Bounded JWKS fetches (#19). Verification now resolves a token's `kid` from an
  explicitly owned `kid`->key cache and touches the network only on a miss, where
  a single-flight refresh is gated by a cooldown window. A flood of distinct
  bogus `kid` values can no longer amplify into one outbound JWKS request per
  token. This replaces the previous approach, which capped client rebuilds but
  left the underlying library free to fetch per unknown `kid`. A regression test
  counts fetches at the network seam (not client rebuilds) and asserts the bound
  holds across 100 distinct bogus kids. (`tests/test_verifier.py`.) `verify()`
  remains synchronous; moving JWKS I/O off the request event loop is tracked.

### Changed

- RFC 9728 resource metadata (#21). `/.well-known/oauth-protected-resource` now
  returns the resource's absolute URL as `resource`, not the opaque audience
  string, so a conforming client no longer discards the metadata.
  (`tests/test_app.py`.)
- Stream-completion audit accuracy (#21). The stream-exit audit event now
  distinguishes a clean completion from a truncated response, a client
  disconnect, and an upstream read error, instead of labeling every
  non-truncation exit "completed". (`tests/test_stream_audit_and_limits.py`.)
- Dependency audit targets the locked set (#22). CI now exports the locked,
  non-dev dependencies (`uv export --frozen --no-dev --no-emit-project`) and
  audits that explicit set, instead of `uvx pip-audit`, which audits an isolated
  temporary environment unrelated to the project.
- Corrected security-claim language (#18) to match what the code enforces, and
  added a "Known limitations" section to the README. Two documentation claims
  were overstated: the JWKS `kid`-miss cooldown caps client rebuilds, not the
  underlying library's fetch on an unknown `kid`, and inbound identity headers
  are stripped via a non-exhaustive denylist rather than "every" identity header.

### Added

- Identifier length limits (#21). Method and tool names are bounded to 256
  characters; an oversized identifier is rejected with `400 identifier_too_long`
  rather than echoed into logs and error responses.
  (`tests/test_stream_audit_and_limits.py`.)
- Reduced pod credential surface (#22). The gateway pod sets
  `automountServiceAccountToken: false`; the gateway makes no Kubernetes API
  calls, so no service-account token is mounted.
- Tool-call authorization (#16, #17): per-tool allow-list enforcement on
  `tools/call` at the proxy boundary, deny-by-default, with every decision logged
  (`tool_name`). Configured via `GATEWAY_TOOL_POLICY_FILE` pointing at a JSON
  `allowed_tools` list. An allow-listed tool is forwarded; an unlisted tool is
  denied with `403 tool_not_allowed`; a `tools/call` with no string `params.name`
  is rejected with `400 invalid_tool_call`. The check runs after the scope check
  (scope is the outer gate). Opt-in and backward-compatible: with the variable
  unset the layer is inactive and `tools/call` is governed by scope alone. Backed
  by unit tests (`ToolPolicy`) and end-to-end proxy tests covering allow, deny,
  unknown-tool, malformed-name, case-sensitivity, scope-precedence, and the
  opt-in default.
- Local verification harness (`verification/`) and results doc (`VERIFICATION.md`)
  (#14, #15): scripts to stand up a local JWKS, stub upstream, and gateway with
  auth enabled, and mint test tokens, plus a record of a manual run confirming
  the four documented auth controls on `POST /mcp` (missing/malformed/expired
  token -> 401, read-scoped token calling `tools/call` -> 403) and two positive
  controls. The doc states plainly that this is local manual verification with
  self-issued tokens against a dev instance, not an audit.
- Stream-completion audit event (#13): after a streamed response finishes, the
  gateway emits a second audit event recording whether the body completed cleanly
  or was truncated for exceeding the response cap (`stream_result`,
  `bytes_streamed`). (`tests/test_app.py`.)
- CI lockfile drift check (#13): CI runs `uv lock --check` before installing, so
  a lockfile that has drifted from `pyproject.toml` fails the build.
- Streaming response pass-through with a size cap (#10): upstream responses are
  streamed through chunk by chunk instead of buffered (fixes SSE/chunked
  upstreams). A configurable cap (`GATEWAY_MAX_RESPONSE_BYTES`, default 10 MiB)
  rejects an over-cap `Content-Length` with 413 before streaming and truncates a
  stream that exceeds the cap mid-flight. (`tests/test_app.py`.)

## [0.1.0] - 2026-06-29

First tagged release. Establishes the gateway and its security posture:
token verification with algorithm pinning, per-method scope enforcement,
fail-closed JSON-RPC parsing, verified identity forwarding, a CI-proven
deployment trust boundary, a published container image, and the hardening
items below.

### Added
- JWKS refresh cooldown: a `kid` miss now forces at most one JWKS refresh per
  `GATEWAY_JWKS_MIN_REFRESH_INTERVAL` (default 10s). Genuine key rotation is
  still picked up promptly, but tokens with bogus or distinct `kid` values can
  no longer amplify into repeated JWKS fetches against the authorization server.
  (`tests/test_verifier.py`.)
- Startup configuration validation: the gateway now validates its config at
  boot (`Settings.validate_runtime`) and exits non-zero with all problems listed
  before serving traffic, rather than failing on the first request. Catches auth
  enabled with no JWKS URL, symmetric/`none` algorithms, empty issuer/audience,
  a missing scope-policy file, out-of-range port/timeouts, and a schemeless
  `public_base_url`. (`tests/test_config.py`.)
- Audit correlation integrity: the gateway now always generates its own
  request id for the audit record and the upstream `X-Request-Id`. A
  client-supplied `X-Request-Id` is stripped before forwarding and recorded
  separately as `client_request_id`, so a caller cannot choose, collide with,
  or forge the audit correlation id. (`tests/test_app.py`.)
- Threat model (`docs/THREAT-MODEL.md`): documents what the gateway defends
  against, what it does not, and the preconditions its security depends on. Each
  defense points at the code or CI that backs it.
- Security policy (`SECURITY.md`): private vulnerability reporting process and
  scope, linked from the README.
- Image publishing (`.github/workflows/publish-image.yml`): builds the
  `Dockerfile` and pushes to GHCR (`ghcr.io/tgandhle/mcp-auth-gateway`) on
  pushes to main (`:main`, `:sha-<short>`) and on `vX.Y.Z` tags (`:X.Y.Z`,
  `:X.Y`, `:latest`). Makes `deploy/k8s/gateway.yaml` runnable against a real
  published image.
- Deployment artifacts (`deploy/`): multi-stage non-root `Dockerfile` built from
  `uv.lock`, and Kubernetes manifests for the gateway, an example upstream, and
  a `NetworkPolicy` that makes the upstream reachable only from gateway pods.
- Trust-boundary CI (`.github/workflows/trust-boundary.yml`): spins up a kind
  cluster with Calico (an enforcing CNI), applies the manifests, and runs a
  bypass-prevention test asserting that a non-gateway pod cannot reach the
  upstream directly. Proves the policy is enforced, not merely valid YAML.
- `deploy/README.md` documenting the trust model, the enforcement caveat (a
  NetworkPolicy is inert under a non-enforcing CNI such as kindnet), and the
  recommendation to add mTLS for high-sensitivity deployments.
- Continuous integration (`.github/workflows/ci.yml`): ruff lint, mypy
  type-check, bandit SAST, pytest, and pip-audit dependency scan, all installed
  from a pinned `uv.lock` for reproducible builds.
- `uv.lock` with hash-pinned dependencies.
- Property-based fuzzing of the JSON-RPC parser (`tests/test_parser_fuzz.py`),
  asserting the fail-closed contract over ~6k generated inputs.
- `CONTRIBUTING.md` documenting the local quality gate.
- Ruff, mypy, and bandit configuration in `pyproject.toml`.
