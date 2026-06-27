"""Shared test fixtures: a real RSA keypair, a JWKS exposing it, and helpers
to mint signed JWTs. No mocking of crypto, we sign and verify for real."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://issuer.test/"
AUDIENCE = "mcp-gateway"
KID = "test-key-1"


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(rsa_key: rsa.RSAPrivateKey) -> dict:
    pub = rsa_key.public_key()
    numbers = pub.public_numbers()

    def b64u_int(n: int) -> str:
        import base64
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": KID,
                "alg": "RS256",
                "n": b64u_int(numbers.n),
                "e": b64u_int(numbers.e),
            }
        ]
    }


def mint(
    rsa_key: rsa.RSAPrivateKey,
    *,
    scope: str = "mcp:read mcp:invoke",
    sub: str = "user-123",
    aud: str = AUDIENCE,
    iss: str = ISSUER,
    exp_delta: int = 300,
    kid: str = KID,
    alg: str = "RS256",
) -> str:
    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "iat": now,
        "exp": now + exp_delta,
        "scope": scope,
    }
    return jwt.encode(payload, rsa_key, algorithm=alg, headers={"kid": kid})
