# Local verification harness

Scripts to reproduce the manual auth-control checks recorded in
[`../VERIFICATION.md`](../VERIFICATION.md). Local dev only. Everything binds
loopback and uses a throwaway keypair generated at run time.

Nothing here is part of the shipped gateway. The generated `private_key.pem` and
`jwks.json` are disposable and git-ignored; do not commit them.

## Prerequisites

The gateway installed (`pip install -e ".[dev]"` from the repo root) plus
`pyjwt` and `cryptography`.

## Steps (bash)

Run these from this directory. Issuer, audience, and kid must be consistent
across the keygen, the gateway env, and the minter.

```bash
ISSUER=https://issuer.test
AUDIENCE=mcp-gateway

# 1. Throwaway key + JWKS (kid defaults to local-verify-1)
python gen_keys.py

# 2. Local JWKS server (127.0.0.1:9001) and stub upstream (127.0.0.1:9000)
python jwks_server.py &
python stub_upstream.py &

# 3. Gateway with auth enabled, pointed at the local JWKS and stub
export GATEWAY_UPSTREAM_URL=http://127.0.0.1:9000/mcp
export GATEWAY_ISSUER=$ISSUER
export GATEWAY_AUDIENCE=$AUDIENCE
export GATEWAY_JWKS_URL=http://127.0.0.1:9001/.well-known/jwks.json
export GATEWAY_REQUIRE_AUTH=true
mcp-gateway &

# 4. Mint tokens
python mint_token.py valid    --issuer $ISSUER --audience $AUDIENCE
python mint_token.py expired  --issuer $ISSUER --audience $AUDIENCE
python mint_token.py readonly --issuer $ISSUER --audience $AUDIENCE

# 5. Drive the controls with curl against http://127.0.0.1:8080/mcp
#    (see ../VERIFICATION.md for the exact requests and expected status codes)
```

## Steps (Windows / PowerShell)

Two things differ from bash and both break the naive translation. PowerShell
corrupts inline JSON passed to `curl.exe` (the embedded quotes get mangled, so
the gateway receives an unparseable body and returns 400), and `Start-Process`
does not inherit the current directory or environment the way bash `&` does.
The reliable approach is a single script that starts each server once, waits for
readiness, passes JSON from a file rather than inline, and runs the checks in
one process so no shell state is lost between windows.

Save the following as `run_verification.ps1` in this directory, then run it with
`.\run_verification.ps1`. If PowerShell blocks the script, first run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the same window.

```powershell
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$vdir = $PSScriptRoot

$Issuer   = "https://issuer.test"
$Audience = "mcp-gateway"
$Url      = "http://127.0.0.1:8080/mcp"

# Clear any stray servers so ports 8080/9001/9000 are free, then start fresh.
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# 1. Throwaway key + JWKS (kid defaults to local-verify-1)
python gen_keys.py | Out-Null

# 2. Gateway env, set before the servers start so the gateway process inherits it
$env:GATEWAY_UPSTREAM_URL = "http://127.0.0.1:9000/mcp"
$env:GATEWAY_ISSUER       = $Issuer
$env:GATEWAY_AUDIENCE     = $Audience
$env:GATEWAY_JWKS_URL     = "http://127.0.0.1:9001/.well-known/jwks.json"
$env:GATEWAY_REQUIRE_AUTH = "true"

# 3. Start each server exactly once. Do not relaunch a server that is already
#    up; a second process fighting for the same port takes down the working one.
#    If you installed into a venv, activate it first so 'python' and the
#    'mcp_gateway' module resolve to that environment.
Start-Process python -ArgumentList "jwks_server.py"   -WorkingDirectory $vdir -WindowStyle Minimized
Start-Process python -ArgumentList "stub_upstream.py" -WorkingDirectory $vdir -WindowStyle Minimized
Start-Process python -ArgumentList "-m","mcp_gateway" -WorkingDirectory $vdir -WindowStyle Minimized

# 4. Wait until the JWKS and the gateway both answer, so a slow start is not
#    mistaken for a failure. Fails loudly instead of returning silent 000s.
function Wait-Ok($u) {
  for ($i = 0; $i -lt 30; $i++) {
    if ((curl.exe -s -o NUL -w "%{http_code}" $u) -eq "200") { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}
if (-not (Wait-Ok "http://127.0.0.1:9001/.well-known/jwks.json")) { "JWKS never came up"; exit 1 }
if (-not (Wait-Ok "http://127.0.0.1:8080/healthz"))               { "gateway never came up"; exit 1 }
"servers ready"

# 5. Write JSON bodies to files so curl sends exact bytes (no quote mangling).
$u8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText("$vdir\call.json", '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"},"id":1}', $u8)
[System.IO.File]::WriteAllText("$vdir\list.json", '{"jsonrpc":"2.0","method":"tools/list","id":1}', $u8)

# 6. Mint tokens into variables
$Valid    = python mint_token.py valid    --issuer $Issuer --audience $Audience
$Expired  = python mint_token.py expired  --issuer $Issuer --audience $Audience
$ReadOnly = python mint_token.py readonly --issuer $Issuer --audience $Audience

# 7. Drive the six controls. -d "@call.json" reads the body from the file.
"1 no-token:      " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -d "@call.json") + "  (expect 401)"
"2 garbage:       " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer not-a-jwt" -d "@call.json") + "  (expect 401)"
"3 expired:       " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $Expired" -d "@call.json") + "  (expect 401)"
"4 readonly-call: " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $ReadOnly" -d "@call.json") + "  (expect 403)"
"A valid-call:    " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $Valid" -d "@call.json") + "  (expect 200)"
"B readonly-list: " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $ReadOnly" -d "@list.json") + "  (expect 200)"
```

Expected output: