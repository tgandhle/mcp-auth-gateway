# Threat model

This document states what the MCP auth gateway defends against, what it does
not, and the preconditions its security depends on. It is deliberately explicit
about its boundaries: a control that is assumed but not enforced is written down
as an assumption, not implied to be a guarantee.

Every "defends against" item below maps to behavior that exists in the code or
is proven in CI. Pointers are given so a reader can verify rather than trust.

## What this is

The gateway is the resource-server half of OAuth 2.1. It sits in front of a
Model Context Protocol (MCP) server, which typically performs no authorization
of its own. The gateway verifies inbound bearer JWTs, enforces per-method
scopes, and forwards a verified identity to the upstream. It does not issue
tokens; an external authorization server (IdP) does that.

```
client ──(JWT)──> gateway ──(X-Forwarded-Sub, verified)──> upstream MCP server
                     │
                     └── verifies JWT against the IdP's JWKS, enforces scope
```

## Assets being protected

- The upstream MCP server's tools, resources, and the actions they can take.
- The integrity of the identity the upstream acts on. The upstream makes
  authorization decisions based on `X-Forwarded-Sub`; if that value can be
  forged, every downstream decision is compromised.

## Trust boundaries

1. **Client → gateway.** Untrusted. Anything a client sends (headers, body,
   token) is treated as hostile until verified.
2. **Gateway → upstream.** The upstream trusts the gateway's injected
   `X-Forwarded-Sub` / `X-Forwarded-Scopes`. This trust is only safe under a
   network precondition (see Preconditions).
3. **Gateway → authorization server (IdP).** The gateway trusts the IdP's JWKS
   to verify signatures. A compromised IdP is out of scope.

## What the gateway defends against

Each item names the threat, the defense, and where to verify it.

### Forged or unsigned tokens
A caller presenting a token signed with `none`, or with a symmetric key, or with
an algorithm the gateway did not expect. **Defense:** acceptable algorithms are
pinned to asymmetric families (RS/ES/PS) and `none`/HMAC are refused at verifier
construction time, which closes the algorithm-confusion bypass class. The
verifier checks `iss`, `aud`, `exp`, `iat`, and the signature, and rejects a
token with no `sub`. **Verify:** `src/mcp_gateway/verifier.py`;
`tests/test_verifier.py`.

### Scope escalation / using a read token to invoke
A caller with a validly issued but under-privileged token trying to call a
method it lacks the scope for. **Defense:** MCP methods are mapped to required
scopes by a policy; read and invoke are separated, and unknown methods are
denied by default. **Verify:** `src/mcp_gateway/policy.py`;
`tests/test_policy_pkce.py`; the proxy test asserts a read-scoped token cannot
invoke a tool.

### Client-supplied identity spoofing
A caller sending its own `X-Forwarded-Sub` / `Authorization` header to
pre-set or leak identity. **Defense:** the gateway strips inbound identity
headers before proxying and injects only the `sub`/scopes it verified itself.
The inbound `Authorization` header is not forwarded upstream. **Verify:**
`src/mcp_gateway/app.py`; `tests/test_app.py` asserts the `Authorization`
header is not forwarded.

### Parser-level authorization bypass
A caller smuggling a method past the scope check via a batch array, malformed
JSON, or a JSON-RPC object with no string `method`. **Defense:** the
authorization path fails closed. Batches are rejected with
`400 batch_not_supported` (per-item authorization is not implemented, so a batch
is refused rather than forwarded unchecked); malformed bodies and method-less
objects are rejected with `400` rather than proxied. **Verify:**
`src/mcp_gateway/app.py`; `tests/test_parser_fuzz.py` exercises the parser with
~6k generated inputs and asserts no input produces a fail-open.

### Stale signing keys after rotation
A token signed with a newly rotated key whose `kid` the gateway has not seen.
**Defense:** the verifier selects the key by `kid` and, on a miss, force-
refreshes the JWKS once before failing closed. **Verify:**
`src/mcp_gateway/verifier.py`; `tests/test_verifier.py`.

### Oversized request bodies
A caller sending a very large body to exhaust memory. **Defense:** a configurable
max body size (default 5 MiB) returns `413`; the limit is checked before the body
is read in full. **Verify:** `src/mcp_gateway/app.py`;
`tests/test_hardening.py`.

### Token leakage via logs
Operational logs accidentally capturing bearer tokens or PKCE verifiers.
**Defense:** the audit logger emits one structured line per decision and never
logs raw tokens or PKCE verifiers; scope values appear only at DEBUG. **Verify:**
`src/mcp_gateway/audit.py`; tests assert tokens are absent from log output.

### Direct client-to-upstream bypass (deployment-enforced)
A caller routing to the upstream directly, skipping the gateway, and sending a
forged `X-Forwarded-Sub`. **Defense:** this is a deployment-level property, not
something the gateway code can enforce alone. The provided Kubernetes
`NetworkPolicy` makes the upstream reachable only from gateway pods. CI installs
an enforcing CNI (Calico) into a kind cluster and runs a bypass test proving a
non-gateway pod cannot reach the upstream. **Verify:**
`deploy/k8s/network-policy.yaml`; `.github/workflows/trust-boundary.yml`;
`deploy/k8s/test-bypass-prevention.sh`. **Important:** this proves the policy
*artifact* is enforceable, not that your production cluster enforces it. See
Preconditions.

## What the gateway does not defend against

These are out of scope by design. They are listed so the boundary is explicit.

- **A compromised or misconfigured authorization server.** The gateway trusts
  the IdP's JWKS. A token that is maliciously issued but correctly signed by a
  trusted key will verify. Defending the IdP is the IdP's job.
- **An upstream reachable directly by clients.** If the network does not isolate
  the upstream, a client can forge `X-Forwarded-Sub` and impersonate any user.
  The gateway cannot self-enforce this; it is a required precondition below.
- **Authorization of individual items inside a JSON-RPC batch.** Batches are
  refused, not inspected. This is a deliberate fail-closed choice, not a
  per-item authorization feature.
- **Denial of service from traffic volume.** The gateway has per-request guards
  (body-size limit, upstream timeouts) but no built-in rate limiting yet. Edge
  rate limiting is assumed.
- **Upstream response-side abuse.** The request body is size-capped; an explicit
  cap on the *upstream's* response size is a known gap, relevant when streaming
  pass-through is added.
- **TLS termination.** The gateway expects TLS to be terminated at an ingress or
  load balancer in front of it. It does not itself manage certificates.
- **Confused-deputy via the upstream's own outbound actions.** Once the upstream
  receives a verified identity, what it does with it is the upstream's
  responsibility.

## Preconditions (the security depends on these)

1. **The upstream MUST NOT be reachable directly by clients.** This is the
   single most important precondition. The gateway's identity forwarding is only
   safe because a client cannot route to the upstream and forge identity. Enforce
   it with the provided `NetworkPolicy` *and confirm your production CNI actually
   enforces NetworkPolicy* (some, including kind's default kindnet, silently do
   not). For high-sensitivity or shared-cluster deployments, prefer mTLS between
   gateway and upstream so the upstream cryptographically verifies the caller
   rather than trusting network position. mTLS is recommended but not included.
2. **TLS in front of the gateway.** Inbound client traffic should be TLS, with
   `GATEWAY_PUBLIC_BASE_URL` set so RFC 9728 metadata and `WWW-Authenticate`
   URLs are correct.
3. **A trustworthy authorization server.** The IdP issuing tokens, the JWKS
   endpoint, and `iss`/`aud` configuration must be correct. The gateway is only
   as trustworthy as the keys it verifies against.
4. **Scope policy reflects real privilege.** The method-to-scope mapping must
   actually match the privilege of each MCP method. A policy that under-specifies
   required scopes will pass requests the operator intended to block.

## Known gaps / roadmap

These are acknowledged, not yet implemented:

- Streaming (SSE) pass-through with an upstream response-size cap. The current
  build buffers responses.
- Per-client and per-JWKS-refresh rate limiting.
- mTLS between gateway and upstream for deployments stronger than network-
  position trust.

If you find an issue not covered here, see `SECURITY.md` for how to report it.
