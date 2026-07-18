# Security review history

This document is an evidence index, not a summary or a marketing page. It records
the external security reviews this project has received, each confirmed finding,
the change that resolved it, the regression test that keeps it resolved, and the
commit at which the resolved state was independently verified. Deferred items are
listed with the reason they were deferred rather than omitted.

Every row is meant to survive a click-through: the PR, the test, and the
verification commit are all public and checkable.

## How to read this

- **Finding**: the issue as the reviewer stated it.
- **Severity**: the reviewer's classification.
- **Resolution**: the PR that fixed it, or the decision if it was not a code fix.
- **Regression test**: the test that fails if the fix regresses.
- **Status**: fixed, deferred (with reason), or a documented decision.

Commits and PRs refer to the public history of `tgandhle/mcp-auth-gateway`.

---

## Review 1

- **Review basis**: GitHub repository review of the JWT verification and
  proxy-boundary controls.
- **Primary outcome**: the JWKS refresh path was found to cap client *rebuilds*
  but not the underlying library's fetch on an unknown `kid`, so unknown-`kid`
  traffic was not fully bounded. Two documentation claims were also found to
  overstate what the code enforced.

| Finding | Severity | Resolution | Regression test | Status |
|---|---|---|---|---|
| JWKS refresh capped client rebuilds, not fetches; unknown-`kid` traffic could still drive per-token fetches | High | Owned `kid`->key cache with single-flight, cooldown-gated refresh (PR #19) | `test_bogus_kid_flood_bounds_fetches` counts fetches at the network seam and asserts <=2 across 100 distinct bogus kids | Fixed |
| Docstring/README claimed unknown-`kid` traffic "cannot amplify" and that "every" identity header is stripped | Docs (accuracy) | Corrected claim language and added a README "Known limitations" section (PR #18) | N/A (documentation); language now matches enforced behavior | Fixed |
| `verify()` performs JWKS network I/O synchronously on the request path | High (availability) | Not fixed in this cycle | N/A | Deferred: off-event-loop JWKS retrieval is tracked as a backlog item; the fetch is bounded, but a slow IdP can still block the loop during a refresh |

Building the JWKS fetch-bound test surfaced and fixed a real clock bug: the
cooldown had compared elapsed time against a timestamp captured before the
cold-start fetch, which suppressed the first legitimate refresh. The test caught
it because it counts fetches at the network seam rather than counting client
rebuilds; a rebuild-counting test would have stayed green.

## Review 2

- **Review basis**: static source and architecture review of the uploaded
  snapshot at commit `576cbe23bc2b8ec609bb16e1e292aa8584965df9`.
- **Primary outcome**: a JSON duplicate-key parser differential that could
  bypass the authorization boundary, plus a set of standards, audit-integrity,
  input-bounding, CI, and deployment findings.

| # | Finding | Severity | Resolution | Regression test | Status |
|---|---|---|---|---|---|
| 1 | Duplicate JSON keys create a parser differential: the gateway authorizes the last value while a first-wins upstream may execute the first, bypassing method/tool authorization | High | Reject objects with duplicate member names (recursively) and forward a canonical re-serialization instead of the original bytes (PR #20) | `test_parser_differential.py`, including the reviewer's exact proof-of-concept body; asserts 400 and that the request never reaches the upstream | Fixed |
| 2 | Protected-resource metadata returned the opaque audience as `resource`, not the RFC 9728 resource URL | High | Return the resource's base URL as `resource` (PR #21) | Updated metadata assertion in `test_app.py`; asserts an absolute URL | Fixed |
| 3 | Stream-completion audit labeled every non-truncation exit "completed", including client disconnect and upstream read error | Medium | Distinguish `completed` / `truncated_response_too_large` / `client_disconnected` / `upstream_read_error` on stream exit (PR #21) | `test_stream_audit_and_limits.py`; asserts an upstream read error is not reported as completed | Fixed |
| 4 | Method and tool identifiers were unbounded; an oversized identifier lands verbatim in logs and error responses | Medium | Bound method and tool names to 256 characters, rejecting longer with `400 identifier_too_long` (PR #21) | `test_stream_audit_and_limits.py`; asserts over-limit method and tool names are rejected | Fixed |
| 5 | The gateway rejects JSON-RPC response messages, so full bidirectional MCP flows are unsupported | Medium | Not a code fix | N/A | Documented decision pending: the gateway is a client-initiated request proxy; the supported MCP profile should be documented explicitly, or bidirectional support added |
| 6 | The dependency audit ran `uvx pip-audit`, which audits an isolated temp environment, not the project's locked dependencies | Medium | Export the locked, non-dev dependencies (`uv export --frozen --no-dev --no-emit-project`) and audit that set (PR #22) | CI runs the corrected audit on every build | Fixed |
| 7 | The Kubernetes upstream trust boundary is label-based; a pod with the gateway label can reach the upstream | Medium | Documented as an inherent property of `NetworkPolicy` (authenticates labels, not workload identity) in the README "Known limitations"; deployment guidance (namespace RBAC, admission control, mesh mTLS/SPIFFE) provided | N/A | Documented limitation |
| 8 | The sample deployment used a mutable image tag and mounted a service-account token the gateway does not use | Low | Set `automountServiceAccountToken: false` on the gateway pod (PR #22); digest pinning deferred (see below) | Manifest schema check in CI | Partially fixed (token mount closed; digest pinning deferred) |

The pip-audit fix (#6) initially failed CI because `uv export` includes the
project itself as an editable requirement, which pip-audit cannot install under
hash-checking. The follow-up added `--no-emit-project` so only third-party
dependencies are exported and audited. This is noted because the corrected form
is the one to reuse.

---

## Independent verification

The resolved state was reproduced from a clean clone, not inferred from
branch-level results.

- **Verification commit**: `937eb904ee223f139326c4d4fd7f06f85e82d694`
  (merge of the final review-fix PR into `main`).
- **Method**: fresh `git clone`, `uv sync --frozen --all-extras` (locked
  install), then the full local gate.
- **Result**:
  - `pytest`: 113 passed.
  - `ruff check src/ tests/`: clean.
  - `mypy src/mcp_gateway/`: clean (9 source files).
  - `bandit -c pyproject.toml -r src`: 0 issues at every severity.
  - `pip-audit` against the exported locked dependencies: no known
    vulnerabilities.
  - Verification-harness key generation (`verification/gen_keys.py`): runs
    cleanly against the clean checkout.

What this verification does and does not cover: it covers source-level tests and
static analysis of the merged commit. It does not cover a deployed gateway
exercising a real identity provider, a real MCP upstream, TLS termination,
Kubernetes networking, or ingress controls. Those are the subject of the planned
deployed-verification milestone and are required before describing any specific
deployment as production-ready.

---

## Deferred items and rationale

These are tracked, not dropped. Each is a backlog item with its own acceptance
criteria.

| Item | Why deferred |
|---|---|
| Off-event-loop JWKS retrieval | The fetch is bounded; moving I/O off the request loop is a separate change with its own slow-IdP and timeout tests |
| Incremental inbound request-body limit | The cap is enforced after buffering for chunked/unlabeled bodies; enforcing it during streaming is a distinct change |
| Outbound header allowlist | The current denylist covers common identity conventions; an allowlist is defense-in-depth over an already-working control |
| MCP Origin validation | Not yet implemented; the DNS-rebinding defense is a tracked item |
| HTTPS-only JWKS configuration | Plaintext JWKS URLs are permitted; requiring TLS by default is a config change |
| Separate readiness and liveness | `/healthz` serves both; splitting `/livez` and `/readyz` is a tracked item |
| Immutable action/image digest pinning | Requires verified SHA digests; these must be looked up and recorded, not fabricated, and are deferred rather than guessed |
| JSON-RPC response-message proxy profile | A design decision (document the client-initiated profile, or build bidirectional support) |
| Test-client deprecation (`starlette.testclient` / `httpx`) | Non-blocking; resolve via a supported FastAPI/Starlette upgrade when available |

## Review 3

- **Review basis**: static source and architecture review of the repository at
  v0.2.0, followed by end-to-end dynamic verification with the official MCP
  SDK (`mcp` 1.28.1) as both the client and the upstream server, driven
  through the gateway. Reproduced independently on Linux (Python 3.12) and
  Windows (Python 3.14). The reproduction harness is committed at
  `verification/run_e2e.ps1` (with `verification/real_upstream.py` and
  `verification/e2e_client.py`) and doubles as the permanent regression check:
  both phases passing is the healthy outcome.
- **Primary outcome**: the builtin scope policy denied the mandatory
  `notifications/initialized` lifecycle notification, breaking every
  spec-compliant client session immediately after the handshake; separately,
  audit events never reached output as shipped. Both fail in the safe
  direction (fail-closed; nothing was wrongly authorized), but the first made
  the default configuration unable to serve a conforming client and the second
  contradicted the audit module's contract.

| # | Finding | Severity | Resolution | Regression test | Status |
|---|---|---|---|---|---|
| 1 | Builtin and example scope policies had no rule for the `notifications/*` family (and lacked `resources/templates/list`, `resources/unsubscribe`, `logging/setLevel`), so deny-by-default returned 403 on `notifications/initialized`; a real SDK client completed `initialize` and then died before its first post-handshake call | High (interop/availability; fail-closed, no authorization bypass) | Builtin and `examples/scope-policy.json` now cover the full client-to-server MCP surface: `notifications/` scope-free (token still required), `resources/` and `prompts/` as prefix rules, `logging/setLevel` gated as `mcp:invoke` (commit `84f642d`) | `tests/test_mcp_method_surface.py` walks the spec's client-to-server method list against both policies and asserts unknown methods stay denied; `verification/run_e2e.ps1` reproduces the original failure end to end if the policy regresses | Fixed |
| 2 | Audit events were dropped as shipped: the `mcp_gateway.audit` logger had no handler via the entrypoint, so INFO events (every allowed decision and every stream-completion event) vanished and only WARNING+ leaked to stderr through Python's last-resort handler. Verified empirically: a fully successful end-to-end session produced zero visible audit lines | Medium (audit integrity) | The entrypoint attaches a stdout handler at INFO; idempotent and deferential to operator-configured handlers and levels (commit `84f642d`). A successful end-to-end session now shows 8 audit lines where it previously showed 0 | `tests/test_audit_logging.py` (allowed decisions reach stdout, no duplicate emits, idempotency, operator config untouched); the harness verdict counts allowed-decision lines | Fixed |
| 3 | `json.loads` accepts `NaN`/`Infinity`/`-Infinity` and `json.dumps` re-emits them, so the canonical body could carry non-RFC 8259 tokens: a lax upstream parses them, a strict one rejects the request. No authorization bypass (method and tool resolution only touch strings), but the parser-differential guarantee was incomplete | Low (parser-differential completeness) | `parse_constant` hook refuses the constants with `400 nonstandard_json_constant`, mirroring the duplicate-key posture (commit `84f642d`) | Non-finite constant cases in `tests/test_parser_differential.py`, including one asserting ordinary floats still parse | Fixed |
| 4 | README still described the pre-#19 JWKS design (client rebuilds; fetch bounding listed as a tracked hardening item) in three places, contradicting the code, CHANGELOG, and Review 1's own Fixed status. Conservative-direction drift, but drift regardless | Docs (accuracy) | Key-rotation bullet, `GATEWAY_JWKS_MIN_REFRESH_INTERVAL` row, and the first Known-limitations entry rewritten to match the implemented design; the remaining true limitation (synchronous JWKS I/O) restated on its own (commit `84f642d`) | N/A (documentation); language again matches enforced behavior | Fixed |
| 5 | The deferred synchronous-JWKS-I/O finding from Review 1 is reachable by an unauthenticated caller: the token header is peeked before any signature check, so a garbage JWT with an allowed `alg` and a bogus `kid` can trigger a refresh once per cooldown window, stalling every in-flight request for up to the fetch timeout whenever the authorization server is slow | High (availability); severity restated with the unauthenticated trigger quantified | Not fixed in this cycle | N/A | Deferred (pre-existing backlog item); this review recommends prioritizing it ahead of Origin validation |
| 6 | 401 response bodies echo the verifier's error detail (`str(exc)`, including PyJWT messages), a mild fingerprinting aid; most gateways return a generic `invalid_token` and keep detail in the audit log | Low (information disclosure) | Not fixed in this cycle | N/A | Deferred |
| 7 | Workflow actions are pinned by mutable tag (`actions/checkout@v4`, `astral-sh/setup-uv@v5`, `docker/*`, `helm/kind-action@v1`) and one by a mutable Docker tag (`ghcr.io/yannh/kubeconform:latest`), inconsistent with the hash-pinned `uv.lock` posture | Low (supply chain) | Not fixed in this cycle | N/A | Deferred: SHA-pin third-party actions and pin the kubeconform image by digest |
| 8 | `/.well-known/oauth-protected-resource` builds `scopes_supported` from `rules` only, omitting scopes named in a policy's `default` set | Low (metadata completeness) | Not fixed in this cycle | N/A | Deferred |

The lifecycle finding was located statically (executing the builtin policy
against the spec's method list) and then proven end to end: with the official
SDK on both sides, `session.initialize()` succeeded, the SDK's automatic
`notifications/initialized` POST received 403, the transport's writer task
died, and the next call failed; the gateway's own audit line
(`"decision":"denied"`, `"held_scope_count":2`, empty `required_scopes`)
confirmed that no scope could have satisfied the check. Verifying that finding
end to end is also what surfaced finding 2: the successful post-fix session
made it observable that no allowed-decision audit lines were being emitted at
all, which a static read of `audit.py` alone does not reveal because the
module's own logic is correct; the gap was in the entrypoint's logging wiring.

