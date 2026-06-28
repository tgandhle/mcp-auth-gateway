# Deployment

This directory contains container and Kubernetes artifacts for running the MCP
auth gateway, plus a CI-verified proof that the gateway-to-upstream trust
boundary is enforced.

## The trust model (read this first)

The gateway authenticates inbound requests, strips any client-supplied identity
headers, and injects a **verified** `X-Forwarded-Sub` (and `X-Forwarded-Scopes`)
before forwarding to the upstream MCP server. The upstream is expected to trust
those forwarded headers.

That trust is only safe under one precondition:

> **The upstream MUST NOT be reachable directly by clients.**

If a client can route to the upstream without passing through the gateway, it
can send a forged `X-Forwarded-Sub` and impersonate any user, defeating
authentication entirely. The gateway cannot enforce this on its own. It is a
**deployment-level** property, enforced here by a Kubernetes `NetworkPolicy`.

## Files

| File | Purpose |
|------|---------|
| `../Dockerfile` | Multi-stage, non-root, minimal runtime image built from `uv.lock`. |
| `k8s/gateway.yaml` | Gateway Deployment (2 replicas), Service, namespace, example ConfigMap. |
| `k8s/upstream.yaml` | Example upstream MCP server (stand-in) Deployment + Service. |
| `k8s/network-policy.yaml` | Default-deny ingress to the upstream + allow only from gateway pods. **The security control.** |
| `k8s/kind-calico.yaml` | kind config that disables kindnet so an enforcing CNI can be installed. |
| `k8s/test-bypass-prevention.sh` | Asserts the gateway path works and a direct bypass is refused. |

## Enforcement caveat (important)

A `NetworkPolicy` is only enforced if the cluster's CNI supports and enforces
it. Some CNIs ignore NetworkPolicy silently, including kind's default
**kindnet**. In that case the policy YAML is inert and the upstream is reachable
by anything in the cluster.

This means:

- The CI job (`.github/workflows/trust-boundary.yml`) installs **Calico** into a
  kind cluster specifically so the policy is enforced, then proves it with the
  bypass test. That validates the **policy artifact**.
- It does **not** prove your production cluster enforces the policy. You must
  confirm your production CNI (Calico, Cilium, etc.) supports and enforces
  NetworkPolicy. Applying this YAML is necessary but not sufficient on its own.

## Stronger isolation (beyond NetworkPolicy)

NetworkPolicy is network-position trust: it restricts *which pods* can connect.
For high-sensitivity, regulated, or shared-cluster deployments, prefer adding
**mTLS** between gateway and upstream (e.g. via a service mesh) so the upstream
cryptographically verifies it is talking to the gateway, not merely trusting
network position. NetworkPolicy is the minimum boundary; mTLS is expected where
the threat model is stronger. mTLS is not included in this PR.

## Building and running locally

The image is published to GHCR by `.github/workflows/publish-image.yml`:
`ghcr.io/tgandhle/mcp-auth-gateway`. Tags: `:main` (latest commit on main),
`:sha-<short>` (immutable per-commit), and on a `vX.Y.Z` release tag, `:X.Y.Z`,
`:X.Y`, and `:latest`. `deploy/k8s/gateway.yaml` references `:main`; pin to a
release tag or `:sha-<short>` for production.

To build locally instead of pulling:

```bash
# Build the image (CI also builds and pushes to ghcr).
docker build -t mcp-auth-gateway:dev .

# Run it (auth on; point it at your IdP and upstream).
docker run --rm -p 8080:8080 \
  -e GATEWAY_UPSTREAM_URL="http://your-mcp-server:9000/mcp" \
  -e GATEWAY_ISSUER="https://issuer.example.com/" \
  -e GATEWAY_AUDIENCE="mcp-gateway" \
  -e GATEWAY_JWKS_URL="https://issuer.example.com/.well-known/jwks.json" \
  mcp-auth-gateway:dev

# Liveness:
curl -fsS http://127.0.0.1:8080/healthz   # -> {"status":"ok"}
```

## Applying to a cluster

```bash
kubectl apply -f deploy/k8s/upstream.yaml        # your real MCP server in practice
kubectl apply -f deploy/k8s/gateway.yaml
kubectl apply -f deploy/k8s/network-policy.yaml  # the trust boundary
```

TLS termination for inbound client traffic is assumed to happen at an ingress or
load balancer in front of the gateway Service; set `GATEWAY_PUBLIC_BASE_URL`
accordingly so RFC 9728 metadata and `WWW-Authenticate` URLs are correct.
