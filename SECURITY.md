# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in this project, please
report it privately rather than opening a public issue.

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/tgandhle/mcp-auth-gateway/security/advisories/new)**
(the "Report a vulnerability" button under the repository's **Security** tab).

Please include, where you can:

- A description of the issue and the security impact you believe it has.
- The component involved (token verification, scope policy, request parsing,
  identity forwarding, the deployment trust boundary, etc.).
- Steps to reproduce, or a proof-of-concept request.
- The affected version, commit SHA, or image tag.

You will get an acknowledgement of the report. If the issue is confirmed, the
fix and disclosure timeline will be discussed with you before any public
advisory is published.

Please do not include real bearer tokens, private keys, or other live secrets
in a report. A redacted token or a self-signed test key is enough to
demonstrate almost any issue here.

## Scope

In scope:

- The gateway's authorization logic: JWT verification, algorithm pinning, JWKS
  handling, scope enforcement, and the fail-closed request-parsing path.
- Identity forwarding: header stripping and the `X-Forwarded-*` injection.
- The deployment artifacts in `deploy/` insofar as they describe or weaken the
  documented trust boundary.

Out of scope (see `docs/THREAT-MODEL.md` for why):

- Compromise of the authorization server / IdP that issues tokens. This gateway
  verifies tokens; it does not issue them and cannot detect a maliciously issued
  but validly signed token.
- An upstream that is directly reachable by clients, bypassing the gateway. That
  is a deployment misconfiguration the gateway cannot self-enforce; it is
  documented as a required precondition.
- Denial of service from raw traffic volume. The gateway has per-request guards
  (body-size limit, upstream timeouts) but no built-in rate limiting yet; edge
  rate limiting is assumed.

## Supported versions

This project has not yet cut a tagged release. Until a `vX.Y.Z` tag exists,
security fixes land on `main`. Once releases begin, this section will state which
versions receive fixes.
