# Current technical evidence

> Technical evidence only. Overall repository gates may pass while production
> approval remains pending external validation and human sign-off.

## Provenance

- Generated (UTC): 2026-07-29T00:11:39Z
- Commit: d85508de2909cbc4d29d2d160f98c57295a04711
- Branch: main
- Worktree: clean
- Platform: Microsoft Windows NT 10.0.26100.0
- Python: Python 3.12.13
- Local gate result: **PASS**

## Repository gates

| Gate | Command | Status | Exit | Evidence |
|---|---|---|---:|---|
| Tests | .\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider | PASS | 0 | ........................................................................ [ 76%] / ............................................                             [100%] / 188 passed in 41.33s |
| Lint | .\.venv\Scripts\python.exe -m ruff check src tests | PASS | 0 | All checks passed! |
| Type check | .\.venv\Scripts\python.exe -m mypy src | PASS | 0 | Success: no issues found in 9 source files |
| SAST | .\.venv\Scripts\python.exe -m bandit -c pyproject.toml -r src -q | PASS | 0 | no output |
| Official MCP SDK 1.28.1 end-to-end | verification/run_e2e.ps1 | PASS | - |  / === VERDICT === /   Audit (phase A): no denial recorded (expected after the lifecycle fix; a denial here means the builtin policy regressed). /   Audit (phase B): allowed-decision audit lines visible: 8 /     (a successful session should show several; 0 means the audit handler regressed) /  /   FINDING NOT REPRODUCED: both phases succeeded. Either the policy has been /   fixed or this client SDK version tolerates the failed notification. |

## External environment evidence

| Evidence | State | Required next action |
|---|---|---|
| Real issuer/JWKS and CA chain | NOT_RUN | Validate reachability, trust, rotation, issuer, and audience in the target environment |
| Real user-scoped claims | NOT_RUN | Exercise representative allow/deny cases with sanitized test identities |
| Production ingress TLS and DNS | NOT_RUN | Record certificate, route, and protected-resource metadata checks |
| Kubernetes trust boundary | NOT_RUN | Run the bypass test on the target CNI and record cluster/version context |
| Load, soak, and failure testing | NOT_RUN | Record workload model, SLO thresholds, and results |
| Audit delivery and alerting | NOT_RUN | Prove events reach controlled storage and alerts fire |
| Rollback and incident exercise | NOT_RUN | Record owner, procedure, timestamps, and outcome |

## Approval state

**PENDING.** Technical automation cannot grant production approval.

| Role | Name/account | Decision | Date (UTC) | Scope/conditions |
|---|---|---|---|---|
| Service owner |  | PENDING |  |  |
| Security approver |  | PENDING |  |  |
| Platform approver |  | PENDING |  |  |
| Operations owner |  | PENDING |  |  |