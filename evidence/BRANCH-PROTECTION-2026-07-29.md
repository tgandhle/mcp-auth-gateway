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

## Amendment (2026-07-29)

The original record stated that `shumba-ux` allows a review independent of the
pull-request author. That is incorrect. `shumba-ux` is a secondary account
controlled by the same individual as `tgandhle` and provides no separation of
duties. The claim is withdrawn, the account has been removed from `CODEOWNERS`
and from repository access, and branch protection was reconfigured to require
pull requests and passing status checks with no required approving review.
Corrected readback follows.

Command:
`gh api repos/tgandhle/mcp-auth-gateway/branches/main/protection`

| Control | Corrected readback |
|---|---|
| Required status checks | `quality`, `audit`, `collect` |
| Require branch up to date | Enabled (`strict: true`) |
| Required approving reviews | 0 |
| Code Owner review | Disabled |
| Dismiss stale reviews | Enabled |
| Approval required after last push | Disabled |
| Enforce for administrators | Enabled |
| Linear history | Enabled |
| Conversation resolution | Enabled |
| Force pushes | Disabled |
| Branch deletion | Disabled |

Repository-access verification:
`gh api 'repos/tgandhle/mcp-auth-gateway/collaborators?affiliation=direct&per_page=100'`
returned only `tgandhle`; `shumba-ux` has no direct collaborator access.
