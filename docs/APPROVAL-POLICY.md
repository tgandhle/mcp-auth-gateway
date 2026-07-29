# Approval policy

This policy defines the evidence and human decisions required before describing
a specific deployment of the gateway as production-ready or an enterprise
standard.

## Roles

| Role | Responsibility | Current assignee |
|---|---|---|
| Service owner | Accepts service lifecycle, roadmap, and rollback responsibility | `@tgandhle` |
| Code owner | Reviews changes to enforcement and release controls | `@tgandhle` |
| Security approver | Reviews the threat model, evidence, and residual risk | `@shumba-ux` |
| Platform approver | Confirms cluster, network, ingress, certificates, and observability | Pending organizational assignment |
| Operations owner | Owns SLOs, alerts, on-call response, and audit retention | Pending organizational assignment |

One person may fill multiple roles only when organizational policy permits it.
Automated checks and AI assistants produce evidence but cannot grant human
approval.

## Required gates

1. The exact commit and deployable image are identified immutably.
2. Unit/integration tests, Ruff, mypy, Bandit, dependency audit, and applicable
   deployment tests pass.
3. Real-environment checks in `docs/PRODUCTION-READINESS.md` have evidence, not
   assumptions.
4. Open findings and skipped checks are listed with owners and disposition.
5. Security, platform, and operations approvers record an identity, date,
   decision, and scope.

## Decision states

- `APPROVED`: every required gate passed and required humans signed.
- `CONDITIONALLY_APPROVED`: named exceptions have owners and expiration dates.
- `REJECTED`: a required control failed or residual risk was not accepted.
- `PENDING`: evidence or human decisions remain outstanding.

Repository CI success alone is always `PENDING` for a production environment.

## GitHub settings

For `main`, enable branch protection or a ruleset requiring:

- pull requests rather than direct pushes;
- at least one approving review;
- review from Code Owners;
- dismissal of stale approvals after new commits;
- successful `ci / quality`, `ci / audit`, and `trust-boundary` checks;
- conversation resolution;
- no force pushes or branch deletion.

These server-side settings must be confirmed in GitHub; committing a
`CODEOWNERS` file does not enable them by itself.

**Current enforcement status (verified 2026-07-28): NOT ENABLED.** GitHub
reported `main` as unprotected, and the approval-framework commits were pushed
directly rather than merged through pull requests. The controls above are
documented target state until a repository administrator enables and verifies
the ruleset. No approval claim may treat them as enforced before that evidence
is recorded.

## Approval record

Copy this table into the environment-specific evidence record. Never pre-fill a
decision on someone else's behalf.

| Role | Name/account | Decision | Date (UTC) | Scope/conditions |
|---|---|---|---|---|
| Service owner |  | PENDING |  |  |
| Security approver |  | PENDING |  |  |
| Platform approver |  | PENDING |  |  |
| Operations owner |  | PENDING |  |  |
