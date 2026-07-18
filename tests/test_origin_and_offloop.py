"""Origin validation, generic 401 detail, off-loop verification, and metadata
completeness at the proxy boundary.

Origin: the MCP Streamable HTTP transport requires validating Origin as the
DNS-rebinding defense. Semantics under test: absent Origin passes (non-browser
clients), listed Origin passes, anything else is 403 with the origin recorded
in the audit log, and the empty default rejects every present Origin.

401 detail: the verifier's specific failure reason must land in the audit
record only; the response body stays generic and the RFC 6750 error code rides
in WWW-Authenticate.

Off-loop: token verification runs in a worker thread, so a verifier stuck in
(for example) a slow JWKS fetch must not stall unrelated requests on the event
loop; previously a slow authorization server froze the whole gateway.
"""

from __future__ import annotations

import asyncio
import json
import threading

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from httpx import ASGITransport

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import create_app
from mcp_gateway.config import ConfigError, Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.verifier import JwksVerifier, TokenError, VerifiedToken

UPSTREAM = "http://upstream.test/mcp"


def make_settings(**overrides) -> Settings:
    values = {
        "upstream_url": UPSTREAM,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "https://issuer.test/jwks",
        "require_auth": True,
    }
    values.update(overrides)
    return Settings(**values)


def make_verifier(monkeypatch, jwks) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks",
        issuer=ISSUER,
        audience=AUDIENCE,
        allowed_algorithms=["RS256"],
    )
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
    return v


BODY = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1})


# --- Origin validation -------------------------------------------------------

def test_absent_origin_passes(monkeypatch, jwks, rsa_key):
    settings = make_settings()  # empty allow-list
    app = create_app(settings, make_verifier(monkeypatch, jwks), ScopePolicy.builtin())
    with respx.mock:
        respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"ok": True}))
        client = TestClient(app)
        r = client.post("/mcp", content=BODY, headers={"Authorization": f"Bearer {mint(rsa_key)}"})
    assert r.status_code == 200


def test_present_origin_rejected_by_default(monkeypatch, jwks, rsa_key):
    settings = make_settings()  # empty allow-list: deny-by-default for browsers
    app = create_app(settings, make_verifier(monkeypatch, jwks), ScopePolicy.builtin())
    client = TestClient(app)
    r = client.post(
        "/mcp",
        content=BODY,
        headers={"Authorization": f"Bearer {mint(rsa_key)}", "Origin": "https://evil.example"},
    )
    assert r.status_code == 403
    assert r.json()["error"] == "origin_not_allowed"
    # The origin value itself is not echoed to the caller.
    assert "evil.example" not in r.text


def test_listed_origin_passes_case_insensitively(monkeypatch, jwks, rsa_key):
    settings = make_settings(allowed_origins=["https://App.Example.com"])
    app = create_app(settings, make_verifier(monkeypatch, jwks), ScopePolicy.builtin())
    with respx.mock:
        respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"ok": True}))
        client = TestClient(app)
        r = client.post(
            "/mcp",
            content=BODY,
            headers={"Authorization": f"Bearer {mint(rsa_key)}", "Origin": "https://app.example.com"},
        )
    assert r.status_code == 200


def test_origin_checked_before_auth(monkeypatch, jwks):
    """A disallowed origin is rejected without reading the body or touching the
    verifier, so rebinding probes can't even exercise token validation."""
    settings = make_settings()
    verifier = make_verifier(monkeypatch, jwks)

    def explode(_token):  # pragma: no cover - must not be reached
        raise AssertionError("verifier must not run for a rejected origin")

    monkeypatch.setattr(verifier, "verify", explode)
    app = create_app(settings, verifier, ScopePolicy.builtin())
    client = TestClient(app)
    r = client.post("/mcp", content=BODY, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_config_rejects_malformed_origins():
    with pytest.raises(ConfigError) as exc:
        make_settings(allowed_origins=["app.example.com"]).validate_runtime()
    assert "GATEWAY_ALLOWED_ORIGINS" in str(exc.value)
    with pytest.raises(ConfigError):
        make_settings(allowed_origins=["https://app.example.com/path"]).validate_runtime()
    # Well-formed entries, including the literal "null", validate cleanly.
    make_settings(allowed_origins=["https://app.example.com", "null"]).validate_runtime()


# --- Generic 401 detail ------------------------------------------------------

def test_invalid_token_401_is_generic(monkeypatch, jwks, rsa_key):
    settings = make_settings()
    app = create_app(settings, make_verifier(monkeypatch, jwks), ScopePolicy.builtin())
    client = TestClient(app)
    expired = mint(rsa_key, exp_delta=-3600)
    r = client.post("/mcp", content=BODY, headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid bearer token"
    # No verifier internals leak into the body.
    assert "expired" not in r.text.lower()
    assert "signature" not in r.text.lower()
    # RFC 6750: coarse error code in the challenge, plus resource metadata.
    challenge = r.headers["WWW-Authenticate"]
    assert 'error="invalid_token"' in challenge
    assert "resource_metadata=" in challenge


# --- Off-loop verification ---------------------------------------------------

class _BlockingVerifier:
    """Stands in for a verifier stuck in a slow JWKS fetch."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def verify(self, token: str) -> VerifiedToken:
        self.entered.set()
        if not self.release.wait(timeout=10):
            raise TokenError("test verifier never released")
        return VerifiedToken(subject="user-123", scopes=frozenset({"mcp:read"}), claims={})


async def test_slow_verification_does_not_stall_the_event_loop():
    settings = make_settings()
    verifier = _BlockingVerifier()
    app = create_app(settings, verifier, ScopePolicy.builtin())  # type: ignore[arg-type]

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw.test") as client:
        mcp_task = asyncio.create_task(
            client.post("/mcp", content=BODY, headers={"Authorization": "Bearer x.y.z"})
        )
        # Wait until the request is genuinely inside the blocking verify call.
        await asyncio.get_running_loop().run_in_executor(None, verifier.entered.wait, 5)
        assert verifier.entered.is_set()

        # The loop must still serve other traffic while verify blocks.
        health = await asyncio.wait_for(client.get("/healthz"), timeout=1.0)
        assert health.status_code == 200

        verifier.release.set()
        with respx.mock:
            respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={"ok": True}))
            r = await asyncio.wait_for(mcp_task, timeout=5.0)
        assert r.status_code == 200


# --- Metadata completeness ---------------------------------------------------

def test_scopes_supported_includes_default_scopes(monkeypatch, jwks):
    settings = make_settings()
    policy = ScopePolicy(
        rules={"tools/list": frozenset({"mcp:read"})},
        default=frozenset({"mcp:fallback"}),
        deny_by_default=True,
    )
    app = create_app(settings, make_verifier(monkeypatch, jwks), policy)
    client = TestClient(app)
    meta = client.get("/.well-known/oauth-protected-resource").json()
    assert "mcp:read" in meta["scopes_supported"]
    assert "mcp:fallback" in meta["scopes_supported"]
