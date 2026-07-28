# Production readiness

The repository provides application controls and deployment examples. A
specific environment is production-ready only after its owners record evidence
for every applicable item below.

## Identity and authorization

- Confirm tokens are user-scoped and carry the expected issuer, audience,
  subject, scopes, and group claim.
- Confirm the JWKS endpoint uses HTTPS, the gateway trusts its CA chain, and key
  rotation succeeds without an outage.
- Configure a claim-bound tool policy and test representative allow and deny
  cases with real tokens.
- Confirm the upstream cannot be reached without traversing the gateway.

## Platform controls

- Terminate inbound TLS using an approved certificate and set
  `GATEWAY_PUBLIC_BASE_URL`.
- Pin the container to an immutable release or digest.
- Verify the production CNI enforces `NetworkPolicy`; use workload-identity mTLS
  when network-position trust is insufficient.
- Keep `/livez` for liveness and `/readyz` for readiness.
- Set ingress request limits in addition to the application limits.

## Operations

- Define availability and latency SLOs and load-test at the expected peak plus
  failure headroom.
- Alert on readiness failures, JWKS retrieval failures, elevated 401/403/413/502
  rates, response truncation, and audit-pipeline loss.
- Ship structured audit events to controlled storage with documented retention
  and access rules.
- Assign service ownership, on-call escalation, rollback, key-compromise, and
  incident-response procedures.
- Exercise backup/restore or redeployment, issuer outage, key rotation, upstream
  outage, and rollback scenarios.

## Release evidence

- CI, tests, lint, type checking, SAST, and dependency audit are green for the
  exact commit and image being deployed.
- The threat model and known limitations match the deployed architecture.
- Security and platform owners approve the environment-specific residual risk.
