param(
    [string]$OutputPath = "evidence/CURRENT.md",
    [switch]$RunE2E
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repo
$testTemp = Join-Path $repo ".evidence-tmp"
if (-not (Test-Path $testTemp)) { New-Item -ItemType Directory -Path $testTemp | Out-Null }
$env:TEMP = $testTemp
$env:TMP = $testTemp

$python = if (Test-Path ".venv/Scripts/python.exe") {
    (Resolve-Path ".venv/Scripts/python.exe").Path
} elseif (Test-Path ".venv/bin/python") {
    (Resolve-Path ".venv/bin/python").Path
} else {
    "python"
}
$pythonDisplay = if ($python -ne "python" -and $python.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) {
    "." + $python.Substring($repo.Length)
} else {
    $python
}

function Invoke-Gate([string]$Name, [string[]]$Arguments) {
    $text = (& $python @Arguments 2>&1 | Out-String).Trim()
    $code = $LASTEXITCODE
    $summary = if ($text) { ($text -split "\r?\n" | Select-Object -Last 3) -join " / " } else { "no output" }
    [pscustomobject]@{
        Name = $Name
        Command = "$pythonDisplay $($Arguments -join ' ')"
        ExitCode = $code
        Status = if ($code -eq 0) { "PASS" } else { "FAIL" }
        Summary = $summary.Replace("|", "\|")
    }
}

$commit = (git rev-parse HEAD).Trim()
$branch = (git branch --show-current).Trim()
$dirty = @((git status --porcelain))
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$platform = [System.Environment]::OSVersion.VersionString
$pythonVersion = (& $python --version 2>&1 | Out-String).Trim()

$gates = @(
    (Invoke-Gate "Tests" @("-m", "pytest", "-q", "-p", "no:cacheprovider")),
    (Invoke-Gate "Lint" @("-m", "ruff", "check", "src", "tests")),
    (Invoke-Gate "Type check" @("-m", "mypy", "src")),
    (Invoke-Gate "SAST" @("-m", "bandit", "-c", "pyproject.toml", "-r", "src", "-q"))
)

$e2eStatus = "NOT_RUN"
$e2eSummary = "Use -RunE2E when the official MCP SDK is installed and loopback ports are available."
if ($RunE2E) {
    $e2eText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot "run_e2e.ps1") -PythonPath $python 2>&1 |
        Out-String).Trim()
    $e2eCode = $LASTEXITCODE
    $positiveVerdict = $e2eText -match "FINDING NOT REPRODUCED"
    $e2eStatus = if ($e2eCode -eq 0 -and $positiveVerdict) { "PASS" } else { "FAIL" }
    $e2eSummary = (($e2eText -split "\r?\n" | Select-Object -Last 8) -join " / ").Replace("|", "\|")
}

$overall = if (($gates.Status -contains "FAIL") -or $e2eStatus -eq "FAIL") { "FAIL" } else { "PASS" }
$dirtyText = if ($dirty.Count -eq 0) { "clean" } else { "dirty (collector/report changes may be present)" }
$rows = ($gates | ForEach-Object {
    "| $($_.Name) | $($_.Command) | $($_.Status) | $($_.ExitCode) | $($_.Summary) |"
}) -join [Environment]::NewLine

$report = @"
# Current technical evidence

> Technical evidence only. Overall repository gates may pass while production
> approval remains pending external validation and human sign-off.

## Provenance

- Generated (UTC): $timestamp
- Commit: $commit
- Branch: $branch
- Worktree: $dirtyText
- Platform: $platform
- Python: $pythonVersion
- Local gate result: **$overall**

## Repository gates

| Gate | Command | Status | Exit | Evidence |
|---|---|---|---:|---|
$rows
| Official MCP SDK 1.28.1 end-to-end | verification/run_e2e.ps1 | $e2eStatus | - | $e2eSummary |

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
"@

$resolvedOutput = Join-Path $repo $OutputPath
$parent = Split-Path -Parent $resolvedOutput
if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
[System.IO.File]::WriteAllText($resolvedOutput, $report, [System.Text.UTF8Encoding]::new($false))
Remove-Item -LiteralPath $testTemp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Wrote $resolvedOutput"
if ($overall -ne "PASS") { exit 1 }
