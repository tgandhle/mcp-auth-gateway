# Main branch protection evidence

## Provenance

- Repository: `tgandhle/mcp-auth-gateway`
- Branch: `main`
- Verified (UTC): 2026-07-29
- Verification interface: GitHub REST API
- Command: `gh api repos/tgandhle/mcp-auth-gateway/branches/main/protection`

## Verified controls

| Control | Readback |
|---|---|
| Required status checks | `quality`, `audit`, `collect` |
| Require branch up to date | Enabled (`strict: true`) |
| Required approving reviews | 1 |
| Code Owner review | Enabled |
| Dismiss stale reviews | Enabled |
| Approval required after last push | Enabled |
| Enforce for administrators | Enabled |
| Linear history | Enabled |
| Conversation resolution | Enabled |
| Force pushes | Disabled |
| Branch deletion | Disabled |

`shumba-ux` accepted write access and is listed with `tgandhle` in
`.github/CODEOWNERS`, allowing a review independent of the pull-request author.

## Scope note

The path-triggered `trust-boundary` workflow is not a global required context
because GitHub does not emit it for unrelated pull requests. Deploy changes
must still run and pass it before approval. The globally required checks are
the three contexts that report on every pull request.
