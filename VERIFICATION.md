# Local verification

This file records what a local, manual run of the gateway's auth controls
actually demonstrated. It is not an audit, a penetration test, or a
production-readiness statement. The tokens were self-issued against a throwaway
local keypair and the upstream was a stub. Read every claim as "this specific
request produced this specific status code on a dev instance," nothing wider.

The runnable harness that reproduces this is in [`verification/`](verification/).

## What was exercised

A subset of the gateway's documented behavior: the four auth-boundary controls
on `POST /mcp`, plus two positive controls. This run does not re-verify the rest
of the README (key rotation, JWKS refresh cooldown, PKCE, audit logging, identity
forwarding, response-size cap, batch rejection); those are covered by the unit
and integration tests, not by this manual run. See "What this does not show."

## Setup

- Gateway version 0.2.0, run via `python -m mcp_gateway`.
- `GATEWAY_REQUIRE_AUTH=true` (auth enforced).
- JWKS served locally from a throwaway RSA-2048 keypair (`kid` `local-verify-1`),
  algorithm RS256.
- Issuer and audience were local test values matching the gateway's
  `GATEWAY_ISSUER` / `GATEWAY_AUDIENCE`.
- Upstream was a local stub returning a fixed JSON-RPC result, so a forwarded
  request is observable as `{"result":{"upstream":"reached"}}`.
- Tokens minted locally with PyJWT, signed by the private key whose public half
  is in the served JWKS.

Request flow in the code, for reference: body-size guard, then authentication,
then JSON-RPC parse, then scope-policy check, then reverse-proxy.

## Controls exercised

Each row is one curl request and the raw status code it returned.

| # | Request | Result |
|---|---------|--------|
| 1 | `POST /mcp`, no `Authorization` header, method `tools/call` | 401, body `{"error":"unauthorized","detail":"missing bearer token"}` |
| 2 | `POST /mcp`, `Authorization: Bearer not-a-jwt`, method `tools/call` | 401, body `{"error":"unauthorized","detail":"malformed token header: Not enough segments"}` |
| 3 | `POST /mcp`, expired but correctly-signed token, method `tools/call` | 401, body `{"error":"unauthorized","detail":"token rejected: Signature has expired"}` |
| 4 | `POST /mcp`, read-only token (`mcp:read` only), method `tools/call` | 403, body `{"error":"insufficient_scope","detail":"missing scope(s): ['mcp:invoke']","required_scopes":["mcp:invoke"]}` |

## Positive controls

These confirm the four results above are authorization decisions, not a gateway
that rejects all input.

| # | Request | Result |
|---|---------|--------|
| A | Valid token holding `mcp:read mcp:invoke`, method `tools/call` | 200, upstream reached (`{"result":{"upstream":"reached"}}`) |
| B | Read-only token (`mcp:read`), method `tools/list` | 200, upstream reached |

The same read-only token denied on `tools/call` (row 4) succeeded on `tools/list`
(row B), so the scope check discriminates by method rather than blanket-denying.

## Relationship to the automated tests

Rows 4 and B manually reproduce a control the test suite already covers
(a read-scoped token cannot invoke a tool, per the README "Tests" section). This
is a manual confirmation of documented, already-tested behavior, not independent
evidence of anything untested.

## What this does and does not show

- Shows: on this dev instance with these self-issued tokens, the four documented
  auth controls returned the documented status codes, and two authorized requests
  were forwarded to the upstream.
- Does not show: behavior against a real authorization server, key rotation,
  JWKS refresh under load, concurrency, batch handling, response-size capping, or
  any production configuration or deployment. None of those were exercised here.

## Findings

No control deviated from its documented behavior in this run.

## Reproducing

See [`verification/README.md`](verification/README.md). The harness generates a
throwaway key, serves a local JWKS and stub upstream, starts the gateway with
auth enabled, mints the three test tokens, and lets you drive the six requests
above with curl.
