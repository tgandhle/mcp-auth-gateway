"""Tests for the second hardening pass: audit logging, request size limits,
policy file schema validation, and public-base-URL metadata."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import _base_url, create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.verifier import JwksVerifier

UPSTREAM = "http://upstream.test/mcp"


def _settings(**kw) -> Settings:
    base = {
        "upstream_url": UPSTREAM,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "https://issuer.test/jwks.json",
        "host": "127.0.0.1",
        "port": 8080,
    }
    base.update(kw)
    return Settings(**base)


def _verifier(monkeypatch, jwks) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER, audience=AUDIENCE, allowed_algorithms=["RS256", "ES256"],
    )
    # Serve the in-memory JWKS through the fetch seam; no HTTP.
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
    return v


def _client(monkeypatch, jwks, **kw) -> TestClient:
    s = _settings(**kw)
    return TestClient(create_app(s, _verifier(monkeypatch, jwks), ScopePolicy.builtin()))


def _rpc(method: str) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method}).encode()


# --- Audit logging ---

@respx.mock
def test_audit_logs_allowed_decision(monkeypatch, jwks, rsa_key, caplog):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read", sub="user-xyz")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    rec = json.loads(caplog.records[-1].message)
    assert rec["decision"] == "allowed"
    assert rec["subject"] == "user-xyz"
    assert rec["method"] == "tools/list"
    assert rec["upstream_status"] == 200
    assert "request_id" in rec
    # never log raw scope values at INFO
    assert "held_scopes" not in rec
    assert rec["held_scope_count"] == 1


@respx.mock
def test_audit_logs_denied_decision(monkeypatch, jwks, rsa_key, caplog):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    rec = json.loads(caplog.records[-1].message)
    assert rec["decision"] == "denied"
    assert rec["error_code"] == "insufficient_scope"
    assert "mcp:invoke" in rec["required_scopes"]


def test_audit_never_logs_token(monkeypatch, jwks, caplog):
    c = _client(monkeypatch, jwks)
    secret = "supersecrettokenvalue"
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {secret}"})
    for record in caplog.records:
        assert secret not in record.message


# --- Request size limit ---

def test_oversized_body_rejected(monkeypatch, jwks, rsa_key):
    c = _client(monkeypatch, jwks, max_request_bytes=100)
    token = mint(rsa_key, scope="mcp:read")
    big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"x": "A" * 500}}).encode()
    r = c.post("/mcp", content=big, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 413
    assert r.json()["error"] == "payload_too_large"


@respx.mock
def test_normal_body_under_limit_ok(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks, max_request_bytes=10000)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_streamed_body_is_capped_while_reading(monkeypatch, jwks, rsa_key):
    c = _client(monkeypatch, jwks, max_request_bytes=100)
    token = mint(rsa_key, scope="mcp:read")

    def chunks():
        yield b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"'
        yield b"A" * 200
        yield b'"}}'

    r = c.post("/mcp", content=chunks(), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 413
    assert r.json()["error"] == "payload_too_large"


@respx.mock
def test_unknown_client_headers_never_reach_upstream(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post(
        "/mcp",
        content=_rpc("tools/list"),
        headers={
            "Authorization": f"Bearer {token}",
            "Remote-User": "attacker",
            "X-Vendor-Identity": "attacker",
            "Baggage": "tenant=attacker-controlled",
            "Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "MCP-Protocol-Version": "2025-06-18",
        },
    )
    assert r.status_code == 200
    sent = route.calls.last.request.headers
    assert "remote-user" not in sent
    assert "x-vendor-identity" not in sent
    assert "baggage" not in sent
    assert "traceparent" in sent
    assert sent["mcp-protocol-version"] == "2025-06-18"


def test_liveness_does_not_depend_on_jwks(monkeypatch, jwks):
    verifier = _verifier(monkeypatch, jwks)
    monkeypatch.setattr(verifier, "ready", lambda: False)
    c = TestClient(create_app(_settings(), verifier, ScopePolicy.builtin()))
    assert c.get("/livez").status_code == 200
    assert c.get("/healthz").status_code == 200


def test_readiness_requires_usable_jwks(monkeypatch, jwks):
    verifier = _verifier(monkeypatch, jwks)
    c = TestClient(create_app(_settings(), verifier, ScopePolicy.builtin()))
    assert c.get("/readyz").json() == {"status": "ready"}
    monkeypatch.setattr(verifier, "ready", lambda: False)
    r = c.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "not_ready"}


# --- Policy schema validation ---

def test_policy_rejects_string_scope_value(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"rules": {"tools/call": "mcp:invoke"}}))  # string, not list
    with pytest.raises(ValueError):
        ScopePolicy.from_file(str(p))


def test_policy_rejects_non_bool_deny(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"rules": {}, "deny_by_default": "false"}))
    with pytest.raises(ValueError):
        ScopePolicy.from_file(str(p))


def test_policy_accepts_valid_file(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({
        "rules": {"tools/list": ["mcp:read"], "tools/call": ["mcp:invoke"]},
        "default": [],
        "deny_by_default": True,
    }))
    policy = ScopePolicy.from_file(str(p))
    assert policy.check("tools/call", ["mcp:invoke"]).allowed
    assert not policy.check("tools/call", ["mcp:read"]).allowed


# --- Public base URL ---

def test_base_url_uses_public_when_set():
    s = _settings(public_base_url="https://mcp.example.com/")
    assert _base_url(s) == "https://mcp.example.com"


def test_base_url_falls_back_to_host_port():
    s = _settings(public_base_url=None)
    assert _base_url(s) == "http://127.0.0.1:8080"


def test_unauthorized_uses_public_base_url(monkeypatch, jwks):
    c = _client(monkeypatch, jwks, public_base_url="https://mcp.example.com")
    r = c.post("/mcp", content=_rpc("tools/list"))
    assert r.status_code == 401
    assert "https://mcp.example.com/.well-known/oauth-protected-resource" in r.headers["www-authenticate"]


# --- Forwarded-identity header safety (review round 2) ---

@respx.mock
def test_non_ascii_sub_rejected_before_upstream(monkeypatch, jwks, rsa_key):
    """A valid but non-ASCII JWT sub yields a clean 401, never a 500 from a
    UnicodeEncodeError building X-Forwarded-Sub, and never calls upstream."""
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    client = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read", sub="caf\u00e9-user")
    r = client.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert not route.called


@respx.mock
def test_surrounding_whitespace_sub_rejected_before_upstream(monkeypatch, jwks, rsa_key):
    """A sub with leading/trailing whitespace is rejected at verification (401),
    so it can never reach h11 (which rejects such a field value) and 502."""
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    client = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read", sub=" user ")
    r = client.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert not route.called


@respx.mock
def test_crlf_sub_rejected_before_upstream(monkeypatch, jwks, rsa_key):
    """A sub with CR/LF (header-injection attempt) is rejected cleanly."""
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    client = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read", sub="evil\r\nX-Injected: 1")
    r = client.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert not route.called


@respx.mock
def test_scope_with_embedded_space_rejected_before_upstream(monkeypatch, jwks, rsa_key):
    """An scp array element containing a space ("admin super") is rejected at
    verification, so it can never reach the upstream as two forwarded scopes the
    gateway did not authorize.

    The token is built without a "scope" string so the scp array is the claim
    actually parsed (_parse_scopes prefers "scope" when present).
    """
    import time as _time

    import jwt as _jwt

    from conftest import AUDIENCE, ISSUER, KID

    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    client = _client(monkeypatch, jwks)
    now = int(_time.time())
    token = _jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "sub": "user-123",
            "iat": now, "exp": now + 300,
            "scp": ["mcp:read", "admin super"],  # embedded space in one element
        },
        rsa_key, algorithm="RS256", headers={"kid": KID},
    )
    r = client.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert not route.called


@respx.mock
def test_traversal_method_rejected_before_upstream(monkeypatch, jwks, rsa_key):
    """A method with a '..' segment is a 400 and never forwarded."""
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    client = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = client.post("/mcp", content=_rpc("resources/../tools/call"),
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert not route.called


@respx.mock
def test_invalid_scope_value_absent_from_logs(monkeypatch, jwks, rsa_key, caplog):
    """The rejected scope token value must never reach the audit log. The
    request is rejected, but the specific (possibly sensitive) scope string the
    caller supplied must not appear in any log record."""
    import time as _time

    import jwt as _jwt

    from conftest import AUDIENCE, ISSUER, KID

    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    client = _client(monkeypatch, jwks)
    now = int(_time.time())
    sentinel = "SENSITIVE_SCOPE admin"
    token = _jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "sub": "user-123",
            "iat": now, "exp": now + 300,
            "scp": ["mcp:read", sentinel],
        },
        rsa_key, algorithm="RS256", headers={"kid": KID},
    )
    with caplog.at_level(logging.DEBUG):
        r = client.post("/mcp", content=_rpc("tools/list"),
                        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert not route.called
    assert sentinel not in caplog.text
    # The word "SENSITIVE" alone should also not leak from the token value.
    assert "SENSITIVE" not in caplog.text
