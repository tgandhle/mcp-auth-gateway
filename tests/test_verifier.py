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


# --- JWKS refresh cooldown ---------------------------------------------------
#
# A kid miss forces a JWKS refresh (to pick up rotation), but a flood of tokens
# with bogus/distinct kids must not be able to trigger an unbounded number of
# refreshes against the authorization server. The cooldown caps forced
# refreshes to at most one per min_refresh_interval.


class _CountingClient:
    """Stand-in for PyJWKClient that counts how many times it is constructed
    (each construction corresponds to a JWKS fetch) and never finds a key, so
    every lookup is a kid miss."""

    instances = 0

    def __init__(self, *args, **kwargs):
        type(self).instances += 1

    def get_signing_key_from_jwt(self, token):
        import jwt as _jwt
        raise _jwt.PyJWKClientError("no kid match")


def _make_counting_verifier(monkeypatch, min_interval):
    import mcp_gateway.verifier as vmod

    _CountingClient.instances = 0
    monkeypatch.setattr(vmod, "PyJWKClient", _CountingClient)
    v = vmod.JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
        cache_ttl=300,
        min_refresh_interval=min_interval,
    )
    return v, vmod


def test_bogus_kid_flood_is_rate_limited(monkeypatch, rsa_key):
    # Construction builds the client once. A flood of bogus-kid tokens within
    # the cooldown window must trigger at most one additional (forced) refresh.
    v, _ = _make_counting_verifier(monkeypatch, min_interval=10.0)
    assert _CountingClient.instances == 1  # the one built in __init__

    for _ in range(50):
        with pytest.raises(TokenError):
            v.verify(mint(rsa_key, kid="bogus-kid"))

    # 1 (construction) + at most 1 (a single forced refresh in the window).
    assert _CountingClient.instances <= 2


def test_forced_refresh_allowed_after_cooldown(monkeypatch, rsa_key):
    # With a zero cooldown, each kid miss is allowed to force a refresh, proving
    # the gate is the cooldown and not some other accidental cap.
    v, _ = _make_counting_verifier(monkeypatch, min_interval=0.0)
    start = _CountingClient.instances

    for _ in range(3):
        with pytest.raises(TokenError):
            v.verify(mint(rsa_key, kid="bogus-kid"))

    # Each verify forces a refresh because the cooldown is zero.
    assert _CountingClient.instances >= start + 3


def test_cooldown_window_resets(monkeypatch, rsa_key):
    # After the cooldown elapses, a new forced refresh is permitted. We simulate
    # time passing by rewinding _last_refresh past the interval.
    v, _ = _make_counting_verifier(monkeypatch, min_interval=10.0)

    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, kid="bogus-kid"))
    after_first = _CountingClient.instances

    # Another miss immediately: still within the window, no new refresh.
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, kid="bogus-kid"))
    assert _CountingClient.instances == after_first

    # Simulate the cooldown elapsing, then a miss is allowed to refresh again.
    import time as _t
    v._last_refresh = _t.monotonic() - 20.0
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, kid="bogus-kid"))
    assert _CountingClient.instances == after_first + 1
