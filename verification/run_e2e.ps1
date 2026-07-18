# run_e2e.ps1 v3 -- end-to-end MCP client verification of mcp-auth-gateway.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.
#
# Committed as a regression harness for the lifecycle-coverage fix: with the
# current builtin policy BOTH phases are expected to pass and the verdict
# prints "FINDING NOT REPRODUCED" (that is the healthy outcome). A Phase A
# failure with a denied notifications/initialized audit line means the builtin
# policy has regressed. Prints a version banner as its first line, and runs
# the MCP client via Start-Process with file redirection so native stderr can
# never surface as a NativeCommandError on Windows PowerShell 5.1.
#
# Run as a saved file from the repo's verification\ directory, venv active:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\run_e2e.ps1
#
# Phase A: gateway with the BUILTIN scope policy; a real MCP SDK client talks
#          through the gateway to a real MCP SDK server. Expected: initialize
#          succeeds, then the SDK's mandatory notifications/initialized POST is
#          denied 403 and the session dies before tools/list.
# Phase B: same, plus one policy rule "notifications/": []. Expected: the full
#          flow (initialize, tools/list, tools/call) succeeds.

$ErrorActionPreference = "Continue"
Write-Host "run_e2e.ps1 v3"

$vdir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Set-Location $vdir

if (-not (Test-Path (Join-Path $vdir "gen_keys.py"))) {
  Write-Host "This script must sit in (and run from) the repo's verification\ directory."
  Write-Host "Current directory: $vdir  -- gen_keys.py not found here."
  exit 1
}

$Issuer   = "https://issuer.test"
$Audience = "mcp-gateway"
$GwUrl    = "http://127.0.0.1:8080/mcp"

# ---------------------------------------------------------------- preflight --
$null = & python -c "import mcp_gateway" 2>&1
if ($LASTEXITCODE -ne 0) {
  Write-Host "mcp_gateway is not importable by 'python'."
  Write-Host "Activate the venv, then from the repo root: pip install -e `".[dev]`""
  exit 1
}
$null = & python -c "import mcp" 2>&1
if ($LASTEXITCODE -ne 0) {
  Write-Host "Installing the official MCP SDK (pip install mcp)..."
  $null = & python -m pip install --quiet mcp 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host "pip install mcp failed; run it manually and retry."; exit 1 }
}

# ------------------------------------------------- write the helper scripts --
$u8 = New-Object System.Text.UTF8Encoding($false)

$upstreamPy = @'
"""A real MCP server (official SDK, Streamable HTTP) used as the gateway upstream."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "e2e-upstream",
    host="127.0.0.1",
    port=9000,
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
def echo(text: str) -> str:
    """Echo the input back."""
    return f"echo: {text}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
'@
if (-not (Test-Path (Join-Path $vdir "real_upstream.py"))) { [System.IO.File]::WriteAllText((Join-Path $vdir "real_upstream.py"), $upstreamPy, $u8) }

$clientPy = @'
"""Official MCP SDK client driven end to end through the gateway.

Usage: python e2e_client.py <gateway-mcp-url> <bearer-token>
Prints one OK/FAIL line per step; exit 0 only if every step succeeded.
"""
from __future__ import annotations

import sys
import traceback

import anyio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def run(url: str, token: str) -> int:
    headers = {"Authorization": f"Bearer {token}"}
    step = "connect"
    try:
        async with streamablehttp_client(url, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                step = "initialize"
                res = await session.initialize()
                print(f"OK initialize server={res.serverInfo.name}", flush=True)

                step = "tools/list"
                tools = await session.list_tools()
                print(f"OK tools/list tools={[t.name for t in tools.tools]}", flush=True)

                step = "tools/call"
                out = await session.call_tool("echo", {"text": "hello"})
                print(f"OK tools/call result={out.content[0].text}", flush=True)
        return 0
    except BaseException as exc:  # noqa: BLE001 - report anything, incl. ExceptionGroup
        print(f"FAIL step={step} exc={type(exc).__name__}: {exc}", flush=True)
        print("".join(traceback.format_exception(exc, limit=3)), file=sys.stderr, flush=True)
        return 1


def main() -> None:
    url, token = sys.argv[1], sys.argv[2]
    raise SystemExit(anyio.run(run, url, token))


if __name__ == "__main__":
    main()
'@
if (-not (Test-Path (Join-Path $vdir "e2e_client.py"))) { [System.IO.File]::WriteAllText((Join-Path $vdir "e2e_client.py"), $clientPy, $u8) }

$fixedPolicy = @'
{
  "rules": {
    "initialize": [],
    "ping": [],
    "notifications/": [],
    "tools/list": ["mcp:read"],
    "tools/call": ["mcp:invoke"],
    "resources/": ["mcp:read"],
    "prompts/": ["mcp:read"],
    "completion/complete": ["mcp:invoke"]
  },
  "default": [],
  "deny_by_default": true
}
'@
[System.IO.File]::WriteAllText((Join-Path $vdir "scope-policy-fixed.json"), $fixedPolicy, $u8)

# ------------------------------------------------------------------ helpers --
function Wait-Http($u, $tries = 30) {
  for ($i = 0; $i -lt $tries; $i++) {
    $code = & curl.exe -s -o NUL -w "%{http_code}" -m 2 $u 2>&1
    if ("$code" -ne "000") { return $true }   # any HTTP answer means the port is live
    Start-Sleep -Milliseconds 500
  }
  return $false
}

$script:started = @()
function Start-Tracked($arglist, $errFile) {
  $outFile = [System.IO.Path]::ChangeExtension($errFile, ".out")
  $p = Start-Process python -ArgumentList $arglist -WorkingDirectory $vdir `
        -WindowStyle Hidden -PassThru `
        -RedirectStandardError $errFile -RedirectStandardOutput $outFile
  $script:started += $p
  return $p
}

function Stop-Started {
  foreach ($p in $script:started) {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  }
}

try {
  # ------------------------------------------------------------ fixed infra --
  if (-not (Test-Path (Join-Path $vdir "private_key.pem"))) {
    $null = & python gen_keys.py 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host "gen_keys.py failed"; exit 1 }
  }

  $env:GATEWAY_UPSTREAM_URL = "http://127.0.0.1:9000/mcp"
  $env:GATEWAY_ISSUER       = $Issuer
  $env:GATEWAY_AUDIENCE     = $Audience
  $env:GATEWAY_JWKS_URL     = "http://127.0.0.1:9001/.well-known/jwks.json"
  $env:GATEWAY_REQUIRE_AUTH = "true"
  Remove-Item Env:\GATEWAY_SCOPE_POLICY_FILE -ErrorAction SilentlyContinue

  $null = Start-Tracked @("jwks_server.py")   (Join-Path $vdir "jwks.err")
  $null = Start-Tracked @("real_upstream.py") (Join-Path $vdir "upstream.err")

  if (-not (Wait-Http "http://127.0.0.1:9001/.well-known/jwks.json")) { Write-Host "JWKS never came up (see jwks.err)"; exit 1 }
  if (-not (Wait-Http "http://127.0.0.1:9000/mcp")) { Write-Host "MCP upstream never came up (see upstream.err)"; exit 1 }

  $Token = (& python mint_token.py valid --issuer $Issuer --audience $Audience 2>&1 | Select-Object -Last 1)
  if ($LASTEXITCODE -ne 0 -or -not $Token) { Write-Host "token minting failed"; exit 1 }
  $Token = "$Token".Trim()

  function Run-Phase($name, $policyFile) {
    if ($policyFile) { $env:GATEWAY_SCOPE_POLICY_FILE = $policyFile }
    else             { Remove-Item Env:\GATEWAY_SCOPE_POLICY_FILE -ErrorAction SilentlyContinue }

    $gwErr = Join-Path $vdir "gateway_$name.err"
    $gw = Start-Tracked @("-m", "mcp_gateway") $gwErr
    if (-not (Wait-Http "http://127.0.0.1:8080/healthz")) { Write-Host "gateway never came up (see $gwErr)"; Stop-Started; exit 1 }

    Write-Host ""
    Write-Host "=== PHASE $name ==="
    $clientOut = Join-Path $vdir "client_$name.out"
    $clientErr = Join-Path $vdir "client_$name.err"
    # Start-Process redirection: the client's stdout/stderr go straight to
    # files at the OS level. PowerShell's error stream is never involved, so
    # no NativeCommandError is possible here on any PS version.
    $cp = Start-Process python -ArgumentList @("e2e_client.py", $GwUrl, $Token) `
          -WorkingDirectory $vdir -WindowStyle Hidden -PassThru -Wait `
          -RedirectStandardOutput $clientOut -RedirectStandardError $clientErr
    $code = $cp.ExitCode
    if (Test-Path $clientOut) { Get-Content $clientOut | ForEach-Object { Write-Host "  $_" } }
    Write-Host "  client exit: $code"

    Stop-Process -Id $gw.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    return @{ exit = $code; gwErr = $gwErr }
  }

  $a = Run-Phase "A_builtin" $null
  $b = Run-Phase "B_fixed"   (Join-Path $vdir "scope-policy-fixed.json")

  # ------------------------------------------------------------------ verdict --
  Write-Host ""
  Write-Host "=== VERDICT ==="
  $denied = @()
  if (Test-Path $a.gwErr) {
    $denied = @(Select-String -Path $a.gwErr -Pattern 'notifications/initialized' -SimpleMatch |
                Where-Object { $_.Line -match '"decision":"denied"' })
  }
  if ($denied.Count -gt 0) {
    Write-Host "  Audit (phase A): gateway denied notifications/initialized under the builtin policy:"
    Write-Host "    $($denied[0].Line)"
  } else {
    Write-Host "  Audit (phase A): no denial recorded (expected after the lifecycle fix; a denial here means the builtin policy regressed)."
  }

  # Denials reach stderr only via Python's last-resort handler; allowed
  # decisions are INFO and are dropped because the audit logger has no handler
  # in the shipped entrypoint. Count what actually surfaced.
  $bOut = $b.gwErr -replace "\.err$", ".out"
  $bAudit = @()
  foreach ($f in @($bOut, $b.gwErr)) {
    if (Test-Path $f) { $bAudit += @(Select-String -Path $f -Pattern '"decision":"allowed"' -SimpleMatch) }
  }
  Write-Host "  Audit (phase B): allowed-decision audit lines visible: $($bAudit.Count)"
  Write-Host "    (a successful session should show several; 0 means the audit handler regressed)"

  if (($a.exit -ne 0) -and ($denied.Count -gt 0) -and ($b.exit -eq 0)) {
    Write-Host ""
    Write-Host "  FINDING CONFIRMED: the builtin scope policy 403s the mandatory"
    Write-Host "  notifications/initialized notification, breaking a spec-compliant MCP"
    Write-Host "  client immediately after the handshake. Adding a 'notifications/': []"
    Write-Host "  rule restores full end-to-end operation (initialize, tools/list, tools/call)."
    exit 0
  } elseif (($a.exit -eq 0) -and ($b.exit -eq 0)) {
    Write-Host ""
    Write-Host "  FINDING NOT REPRODUCED: both phases succeeded. Either the policy has been"
    Write-Host "  fixed or this client SDK version tolerates the failed notification."
    exit 0
  } else {
    Write-Host ""
    Write-Host "  INCONCLUSIVE: unexpected combination (A exit $($a.exit), B exit $($b.exit))."
    Write-Host "  Inspect client_*.err and gateway_*.err in $vdir."
    exit 1
  }
}
finally {
  Stop-Started
}

