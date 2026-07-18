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
