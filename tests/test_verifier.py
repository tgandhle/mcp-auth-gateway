"""Verifier tests. We point PyJWKClient at a local file:// or patch its fetch
so no network is needed; here we inject the JWKS by monkeypatching the client's
key fetch."""

from __future__ import annotations

import jwt
import pytest

from conftest import AUDIENCE, ISSUER, KID, mint
from mcp_gateway.verifier import JwksVerifier, TokenError


def make_verifier(monkeypatch, jwks, algs=None) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=algs or ["RS256", "ES256"],
    )

    # Patch the PyJWKClient instance to serve our in-memory JWKS without HTTP.
    from jwt import PyJWKSet

    def fake_get_signing_key_from_jwt(token):
        keyset = PyJWKSet.from_dict(jwks)
        header = jwt.get_unverified_header(token)
        for k in keyset.keys:
            if k.key_id == header.get("kid"):
                return k
        raise jwt.PyJWKClientError("no kid match")

    monkeypatch.setattr(v._client, "get_signing_key_from_jwt", fake_get_signing_key_from_jwt)
    return v


def test_valid_token(monkeypatch, jwks, rsa_key):
    v = make_verifier(monkeypatch, jwks)
    result = v.verify(mint(rsa_key))
    assert result.subject == "user-123"
    assert "mcp:read" in result.scopes
    assert "mcp:invoke" in result.scopes


def test_expired_token(monkeypatch, jwks, rsa_key):
    v = make_verifier(monkeypatch, jwks)
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, exp_delta=-120))


def test_wrong_audience(monkeypatch, jwks, rsa_key):
    v = make_verifier(monkeypatch, jwks)
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, aud="some-other-resource"))


def test_wrong_issuer(monkeypatch, jwks, rsa_key):
    v = make_verifier(monkeypatch, jwks)
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, iss="https://evil.test/"))


def test_alg_none_rejected(monkeypatch, jwks, rsa_key):
    v = make_verifier(monkeypatch, jwks)
    # craft an alg=none token
    import base64
    import json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": KID}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "x", "iss": ISSUER, "aud": AUDIENCE}).encode()).rstrip(b"=").decode()
    token = f"{header}.{payload}."
    with pytest.raises(TokenError):
        v.verify(token)


def test_empty_token(monkeypatch, jwks):
    v = make_verifier(monkeypatch, jwks)
    with pytest.raises(TokenError):
        v.verify("")


def test_construction_rejects_symmetric():
    with pytest.raises(ValueError):
        JwksVerifier(
            jwks_url="https://issuer.test/jwks.json",
            issuer=ISSUER,
            audience=AUDIENCE,
            allowed_algorithms=["HS256"],
        )


def test_missing_sub(monkeypatch, jwks, rsa_key):
    import time
    now = int(time.time())
    bad = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 300, "scope": "mcp:read"},
        rsa_key, algorithm="RS256", headers={"kid": KID},
    )
    v = make_verifier(monkeypatch, jwks)
    with pytest.raises(TokenError):
        v.verify(bad)
