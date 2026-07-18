"""Duplicate-key parser-differential tests (security review finding #1).

Python's json.loads silently keeps the last value for a duplicate object key.
A first-wins upstream parser would keep a different value, letting an attacker
have the gateway authorize one method/tool while the upstream executes another.
The gateway now (a) rejects any object with duplicate member names and
(b) forwards a canonical re-serialization so the upstream cannot see bytes that
parse differently from what was authorized.
"""

from __future__ import annotations

import json

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import _parse_jsonrpc, create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.verifier import JwksVerifier

UPSTREAM = "http://upstream.test/mcp"


# --- Unit level: the parser rejects duplicates -------------------------------

def test_duplicate_method_rejected():
    # The review's exact proof-of-concept body.
    poc = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger"},"method":"tools/list"}'
    parsed = _parse_jsonrpc(poc)
    assert parsed.error is not None
    assert parsed.error_code == "duplicate_json_key"
    assert parsed.method is None  # never resolves to an authorizable method


def test_duplicate_params_name_rejected():
    poc = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"safe","name":"danger"},"id":1}'
    parsed = _parse_jsonrpc(poc)
    assert parsed.error is not None
    assert parsed.error_code == "duplicate_json_key"


def test_duplicate_params_object_rejected():
    poc = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"a"},"params":{"name":"b"},"id":1}'
    parsed = _parse_jsonrpc(poc)
    assert parsed.error is not None
    assert parsed.error_code == "duplicate_json_key"


def test_duplicate_in_nested_object_rejected():
    # Duplicate deep inside params must also be caught (recursive).
    poc = b'{"jsonrpc":"2.0","method":"tools/list","params":{"a":{"x":1,"x":2}},"id":1}'
    parsed = _parse_jsonrpc(poc)
    assert parsed.error is not None
    assert parsed.error_code == "duplicate_json_key"


def test_clean_request_still_parses_and_canonicalizes():
    body = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
    parsed = _parse_jsonrpc(body)
    assert parsed.error is None
    assert parsed.method == "tools/list"
    assert parsed.canonical_body is not None
    # Canonical body must be valid JSON parsing to the same object.
    assert json.loads(parsed.canonical_body) == {"jsonrpc": "2.0", "method": "tools/list", "id": 1}


# --- End to end: duplicate rejected with 400, clean request forwards canonical

def _verifier(monkeypatch, jwks) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER, audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
    )
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
    return v


def _client(monkeypatch, jwks) -> TestClient:
    app = create_app(
        Settings(
            upstream_url=UPSTREAM, issuer=ISSUER, audience=AUDIENCE,
            jwks_url="https://issuer.test/jwks.json", host="127.0.0.1", port=8080,
        ),
        _verifier(monkeypatch, jwks),
        ScopePolicy.builtin(),
    )
    return TestClient(app)


@respx.mock
def test_duplicate_method_returns_400_not_forwarded(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read mcp:invoke")
    poc = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger"},"method":"tools/list"}'
    r = c.post("/mcp", content=poc, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "duplicate_json_key"
    # Critically: the ambiguous request never reached the upstream.
    assert not route.called


@respx.mock
def test_clean_request_forwards_canonical_bytes(monkeypatch, jwks, rsa_key):
    captured = {}

    def capture(request):
        captured["body"] = request.content
        return httpx.Response(200, json={"ok": True})

    respx.post(UPSTREAM).mock(side_effect=capture)
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    # Send with odd spacing; upstream should receive the canonical compact form.
    sent = '{"jsonrpc": "2.0",  "method": "tools/list",   "id": 1}'
    r = c.post("/mcp", content=sent, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    # Upstream received canonical bytes (no extra spaces), parsing to same object.
    assert json.loads(captured["body"]) == {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
    assert b"  " not in captured["body"]  # compact separators, no double spaces


# --- Non-finite constants: not RFC 8259, refused at the source ---------------
# Python's json accepts NaN/Infinity and re-emits them, so the canonical body
# could carry tokens a strict upstream rejects and a lax one accepts, which is
# the parser-family divergence canonicalization exists to eliminate.

def test_nan_constant_rejected():
    body = b'{"jsonrpc":"2.0","method":"ping","x":NaN,"id":1}'
    parsed = _parse_jsonrpc(body)
    assert parsed.error is not None
    assert parsed.error_code == "nonstandard_json_constant"
    assert parsed.method is None


def test_infinity_constants_rejected():
    for body in (
        b'{"jsonrpc":"2.0","method":"ping","x":Infinity,"id":1}',
        b'{"jsonrpc":"2.0","method":"ping","x":-Infinity,"id":1}',
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{"n":NaN}},"id":1}',
    ):
        parsed = _parse_jsonrpc(body)
        assert parsed.error is not None
        assert parsed.error_code == "nonstandard_json_constant"


def test_finite_numbers_still_accepted():
    body = b'{"jsonrpc":"2.0","method":"ping","x":1.5e10,"y":-0.0,"id":1}'
    parsed = _parse_jsonrpc(body)
    assert parsed.error is None
    assert parsed.method == "ping"
