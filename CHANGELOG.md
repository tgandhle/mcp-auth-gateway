# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow semantic versioning once a tagged release is cut.

## [Unreleased]

### Changed
- JWKS handling now owns an explicit `kid`->key cache. Verification resolves the
  token's `kid` from that in-memory map and touches the network only on a miss,
  where a single-flight refresh is gated by the cooldown window. A flood of
  distinct bogus `kid` values can no longer amplify into one outbound JWKS fetch
  per token: fetches are bounded to the cold-start populate plus at most one
  forced refresh per window. This replaces the previous approach, which capped
  client rebuilds but left the underlying library free to fetch per unknown
  `kid`. A new test counts fetches at the network seam (not client rebuilds) and
  asserts the bound holds across 100 distinct bogus kids. `verify()` remains
  synchronous; moving JWKS I/O off the request event loop is a separate change.
- Corrected security-claim language to match what the code actually enforces,
  and added a "Known limitations" section to the README. Two docstring/comment
  claims were overstated: the JWKS `kid`-miss cooldown caps client *rebuilds*,
  not the underlying library's fetch on an unknown `kid` (so unknown-`kid`
  traffic is not yet fully bounded), and inbound identity headers are stripped
  via a non-exhaustive denylist rather than "every" identity header. No behavior
  change; this aligns the documentation with the implementation ahead of the
  hardening fixes that address the underlying gaps.

### Added
- Tool-call authorization: per-tool allow-list enforcement on `tools/call` at
  the proxy boundary, deny-by-default, with every decision logged (`tool_name`).
  Configured via `GATEWAY_TOOL_POLICY_FILE` pointing at a JSON `allowed_tools`
  list. An allow-listed tool is forwarded; an unlisted tool is denied with
  `403 tool_not_allowed`; a `tools/call` with no string `params.name` is
  rejected with `400 invalid_tool_call`. The check runs after the scope check
  (scope is the outer gate). Opt-in and backward-compatible: with the variable
  unset the layer is inactive and `tools/call` is governed by scope alone, so
  upgrading without configuring a policy changes nothing. Backed by unit tests
  (`ToolPolicy`) and end-to-end proxy tests covering allow, deny, unknown-tool,
  malformed-name, case-sensitivity, scope-precedence, and the opt-in default.
- Local verification harness (`verification/`) and results doc (`VERIFICATION.md`):
  scripts to stand up a local JWKS, stub upstream, and gateway with auth enabled,
  and mint test tokens, plus a record of a manual run confirming the four
  documented auth controls on `POST /mcp` (missing/malformed/expired token -> 401,
  read-scoped token calling `tools/call` -> 403) and two positive controls. The
  doc states plainly that this is local manual verification with self-issued
  tokens against a dev instance, not an audit.
- Stream-completion audit event: after a streamed response finishes, the gateway
  emits a second audit event recording whether the body completed cleanly or was
  truncated for exceeding the response cap (`stream_result`, `bytes_streamed`).
  This lets a SIEM distinguish a capped/truncated response from a clean one,
  which the initial "allowed" event cannot convey on its own. (`tests/test_app.py`.)
- CI now runs `uv lock --check` before installing, so a lockfile that has drifted
  from `pyproject.toml` fails the build rather than shipping silently.

## [0.2.0] - 2026-06-29

Hardening release: response-path streaming and an upstream response-size cap.

### Added
- Streaming response pass-through with a size cap: upstream responses are now
  streamed through chunk by chunk instead of buffered (fixes SSE/chunked
  upstreams). A configurable cap (`GATEWAY_MAX_RESPONSE_BYTES`, default 10 MiB)
  rejects an over-cap `Content-Length` with 413 before streaming and truncates
  a stream that exceeds the cap mid-flight. (`tests/test_app.py`.)

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

### Changed
- `build()` in `__main__.py` now has a precise return type
  (`tuple[FastAPI, Settings]`), removing an incorrect `type: ignore` and making
  the source mypy-clean.
- Package author metadata corrected to `T. Gandhle`.
- Minor lint cleanups in the test suite (unused imports, import grouping).
