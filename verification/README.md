# Local verification harness

Scripts to reproduce the manual auth-control checks recorded in
[`../VERIFICATION.md`](../VERIFICATION.md). Local dev only. Everything binds
loopback and uses a throwaway keypair generated at run time.

Nothing here is part of the shipped gateway. The generated `private_key.pem` and
`jwks.json` are disposable and git-ignored; do not commit them.

## Prerequisites

The gateway installed (`pip install -e ".[dev]"` from the repo root) plus
`pyjwt` and `cryptography`.

## Steps

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

## Windows / PowerShell

The steps above are bash. On PowerShell the Python is identical but the shell
syntax differs: environment variables use `$env:`, backgrounding uses
`Start-Process` rather than `&`, and requests use `curl.exe` (the real curl,
not the `Invoke-WebRequest` alias) so the flags below work unchanged.

Run from this directory. Adjust the `python` path if you use a venv.

```powershell
$Issuer   = "https://issuer.test"
$Audience = "mcp-gateway"
$Url      = "http://127.0.0.1:8080/mcp"

# 1. Throwaway key + JWKS (kid defaults to local-verify-1)
python gen_keys.py

# 2. Local JWKS server (9001) and stub upstream (9000), each in its own window
Start-Process python -ArgumentList "jwks_server.py"
Start-Process python -ArgumentList "stub_upstream.py"

# 3. Gateway with auth enabled, pointed at the local JWKS and stub.
#    Set env in THIS session, then start the gateway in a new window that
#    inherits it.
$env:GATEWAY_UPSTREAM_URL = "http://127.0.0.1:9000/mcp"
$env:GATEWAY_ISSUER       = $Issuer
$env:GATEWAY_AUDIENCE     = $Audience
$env:GATEWAY_JWKS_URL     = "http://127.0.0.1:9001/.well-known/jwks.json"
$env:GATEWAY_REQUIRE_AUTH = "true"
Start-Process mcp-gateway

# Wait for readiness
do { Start-Sleep -Milliseconds 500
     $code = (curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/healthz)
} until ($code -eq "200")
"healthz: $code"

# 4. Mint tokens into variables
$Valid    = python mint_token.py valid    --issuer $Issuer --audience $Audience
$Expired  = python mint_token.py expired  --issuer $Issuer --audience $Audience
$ReadOnly = python mint_token.py readonly --issuer $Issuer --audience $Audience

# 5. Drive the six controls. Bodies are single-quoted so PowerShell does not
#    interpolate the JSON.
$Call = '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"},"id":1}'
$List = '{"jsonrpc":"2.0","method":"tools/list","id":1}'

"1 no-token:      " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -d $Call) + "  (expect 401)"
"2 garbage:       " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer not-a-jwt" -d $Call) + "  (expect 401)"
"3 expired:       " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $Expired" -d $Call) + "  (expect 401)"
"4 readonly-call: " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $ReadOnly" -d $Call) + "  (expect 403)"
"A valid-call:    " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $Valid" -d $Call) + "  (expect 200)"
"B readonly-list: " + (curl.exe -s -m5 -o NUL -w "%{http_code}" -X POST $Url -H "Content-Type: application/json" -H "Authorization: Bearer $ReadOnly" -d $List) + "  (expect 200)"
```

To see the response bodies, not just status codes, drop `-o NUL -w "%{http_code}"`
from any line.

Notes specific to PowerShell:

- `curl.exe` is required. Bare `curl` is an alias for `Invoke-WebRequest`, which
  does not accept these flags. `curl.exe` ships with Windows 10 1803+ and
  Windows 11.
- `Start-Process` opens each server in its own process; close those windows to
  stop them, or track the returned objects with `-PassThru` and `Stop-Process`.
- If `python mint_token.py ...` returns an array instead of a string (rare, only
  if the script emits extra lines), force a string with `($Valid -join "")`.
- These commands were not executed on Windows during authoring; they are the
  PowerShell translation of the verified bash run. Confirm the six status codes
  match the table in `../VERIFICATION.md` on first run.

## UTF-8 BOM note

If you regenerate any config or YAML with PowerShell, avoid
`Set-Content -Encoding utf8`, which prepends a UTF-8 BOM that breaks YAML
parsers. Use `[System.IO.File]::WriteAllText` with `$PWD` full paths instead.
The `.py` files in this harness contain no BOM; keep them that way if you edit
them.
