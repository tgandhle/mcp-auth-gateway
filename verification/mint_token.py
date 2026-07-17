"""Mint a test JWT signed by the local throwaway key, for local verification.

Issuer, audience, and kid come from args or env (ISSUER / AUDIENCE / KID) and
must match the running gateway's GATEWAY_ISSUER / GATEWAY_AUDIENCE and the kid
in jwks.json. No values are hardcoded to any real environment.

Kinds:
  valid     sub set, scope "mcp:read mcp:invoke", exp in the future
  readonly  scope "mcp:read" only
  expired   scope "mcp:read mcp:invoke", exp in the past (beyond leeway)

Usage:
  python mint_token.py valid --issuer https://issuer.test --audience mcp-gateway
"""
from __future__ import annotations

import argparse
import os
import time

import jwt

SCOPES = {
    "valid": "mcp:read mcp:invoke",
    "readonly": "mcp:read",
    "expired": "mcp:read mcp:invoke",
}


def mint(kind: str, issuer: str, audience: str, kid: str, key_path: str) -> str:
    if kind not in SCOPES:
        raise SystemExit(f"unknown kind {kind!r}; choose from {sorted(SCOPES)}")
    with open(key_path) as f:
        priv = f.read()
    now = int(time.time())
    claims = {
        "sub": "test-user",
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "scope": SCOPES[kind],
    }
    if kind == "expired":
        claims["iat"] = now - 7200
        claims["exp"] = now - 3600  # past exp, beyond default 30s leeway
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid})


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a test JWT for local verification.")
    ap.add_argument("kind", choices=sorted(SCOPES))
    ap.add_argument("--issuer", default=os.environ.get("ISSUER"))
    ap.add_argument("--audience", default=os.environ.get("AUDIENCE"))
    ap.add_argument("--kid", default=os.environ.get("KID", "local-verify-1"))
    ap.add_argument("--key", default="private_key.pem")
    args = ap.parse_args()

    if not args.issuer or not args.audience:
        raise SystemExit("issuer and audience are required (via --issuer/--audience or ISSUER/AUDIENCE env)")

    print(mint(args.kind, args.issuer, args.audience, args.kid, args.key))


if __name__ == "__main__":
    main()
