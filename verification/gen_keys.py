"""Generate a throwaway RSA keypair and a matching JWKS for local verification.

Writes private_key.pem (the signing key) and jwks.json (the public key as a
JWKS). The key is disposable: it signs nothing real and is trusted only by the
local JWKS server you run for verification. Do not commit the outputs; see
.gitignore.

The kid is read from --kid or KID (default "local-verify-1") and must match the
kid used by mint_token.py.
"""
from __future__ import annotations

import argparse
import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a throwaway RSA keypair and JWKS.")
    ap.add_argument("--kid", default=os.environ.get("KID", "local-verify-1"),
                    help="Key id to embed in the JWKS (must match the token kid).")
    ap.add_argument("--key-out", default="private_key.pem")
    ap.add_argument("--jwks-out", default="jwks.json")
    args = ap.parse_args()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": args.kid,
        "n": b64url_uint(nums.n), "e": b64url_uint(nums.e),
    }]}

    with open(args.key_out, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(args.jwks_out, "w") as f:
        json.dump(jwks, f, indent=2)

    print(f"kid={args.kid}  wrote {args.key_out} and {args.jwks_out}")


if __name__ == "__main__":
    main()
