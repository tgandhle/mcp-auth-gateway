"""Verifier tests. The verifier owns its kid->key cache and fetches the JWKS
through a single seam (_fetch_jwks). Tests override that seam to serve an
in-memory JWKS with no network, and to count fetches so the bogus-kid bound is
proved at the fetch layer (not merely at a rebuild counter)."""

from __future__ import annotations

import jwt
import pytest

from conftest import AUDIENCE, ISSUER, KID, mint
from mcp_gateway.verifier import JwksVerifier, TokenError


def make_verifier(monkeypatch, jwks, algs=None, **kw) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=algs or ["RS256", "ES256"],
        **kw,
    )
    # Serve the in-memory JWKS through the fetch seam; no HTTP.
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
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


def test_missing_kid_rejected(monkeypatch, jwks, rsa_key):
    # A token with no kid in its header cannot select a key and is rejected
    # before any network access.
    v = make_verifier(monkeypatch, jwks)
    import time
    now = int(time.time())
    tok = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": now, "exp": now + 300},
        rsa_key, algorithm="RS256",  # no kid header
    )
    with pytest.raises(TokenError):
        v.verify(tok)


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


# --- JWKS fetch bounding -----------------------------------------------------
#
# The security-critical property: a flood of tokens carrying distinct bogus
# kids must not turn the gateway into one outbound JWKS fetch per token. These
# tests count fetches at the network seam (_fetch_jwks), not client rebuilds, so
# they measure the thing the authorization server actually experiences.


def _counting_verifier(monkeypatch, jwks, min_interval):
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
        cache_ttl=300,
        min_refresh_interval=min_interval,
    )
    calls = {"n": 0}

    def counting_fetch():
        calls["n"] += 1
        return jwks

    monkeypatch.setattr(v, "_fetch_jwks", counting_fetch)
    return v, calls


def test_bogus_kid_flood_bounds_fetches(monkeypatch, jwks, rsa_key):
    # 100 distinct bogus kids within one cooldown window. Expect: one cold-start
    # fetch to populate the cache, plus at most one forced refresh for the first
    # miss. Every subsequent miss inside the window must perform NO fetch.
    v, calls = _counting_verifier(monkeypatch, jwks, min_interval=10.0)

    for i in range(100):
        with pytest.raises(TokenError):
            v.verify(mint(rsa_key, kid=f"bogus-{i}"))

    # cold-start populate (1) + single forced refresh in the window (1) = 2.
    assert calls["n"] <= 2, f"expected <=2 fetches for 100 bogus kids, got {calls['n']}"


def test_valid_kid_after_populate_uses_no_extra_fetch(monkeypatch, jwks, rsa_key):
    # The real key is served by the fetch. Verifying several valid tokens should
    # cost one fetch total (the cold-start populate), then pure cache hits.
    v, calls = _counting_verifier(monkeypatch, jwks, min_interval=10.0)
    for _ in range(5):
        v.verify(mint(rsa_key))
    assert calls["n"] == 1


def test_forced_refresh_after_cooldown(monkeypatch, jwks, rsa_key):
    # With a zero cooldown, each miss is allowed to refresh, proving the gate is
    # the cooldown and not an accidental cap. cold(1) + one per miss(3) = 4.
    v, calls = _counting_verifier(monkeypatch, jwks, min_interval=0.0)
    for _ in range(3):
        with pytest.raises(TokenError):
            v.verify(mint(rsa_key, kid="bogus"))
    assert calls["n"] >= 4


def test_cooldown_window_resets(monkeypatch, jwks, rsa_key):
    v, calls = _counting_verifier(monkeypatch, jwks, min_interval=10.0)

    # First miss: cold populate + one forced refresh.
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, kid="bogus"))
    after_first = calls["n"]

    # Second miss immediately: within the window, no new fetch.
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, kid="bogus"))
    assert calls["n"] == after_first

    # Simulate cooldown elapsing: a miss is allowed to refresh again.
    import time as _t
    v._last_fetch = _t.monotonic() - 20.0
    with pytest.raises(TokenError):
        v.verify(mint(rsa_key, kid="bogus"))
    assert calls["n"] == after_first + 1
