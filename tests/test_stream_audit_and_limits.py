"""Batch 2 tests: identifier length bounds (#4) and stream-audit truthfulness (#3)."""

from __future__ import annotations

import json

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import _MAX_IDENTIFIER_LEN, _parse_jsonrpc, create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.verifier import JwksVerifier

UPSTREAM = "http://upstream.test/mcp"


def test_overlong_method_rejected():
    huge = "a" * (_MAX_IDENTIFIER_LEN + 1)
    body = json.dumps({"jsonrpc": "2.0", "method": huge, "id": 1}).encode()
    parsed = _parse_jsonrpc(body)
    assert parsed.error is not None
    assert parsed.error_code == "identifier_too_long"


def test_method_at_limit_accepted():
    ok = "a" * _MAX_IDENTIFIER_LEN
    body = json.dumps({"jsonrpc": "2.0", "method": ok, "id": 1}).encode()
    parsed = _parse_jsonrpc(body)
    assert parsed.error is None
    assert parsed.method == ok


def test_overlong_tool_name_rejected():
    huge = "t" * (_MAX_IDENTIFIER_LEN + 1)
    body = json.dumps(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": huge}, "id": 1}
    ).encode()
    parsed = _parse_jsonrpc(body)
    assert parsed.error is not None
    assert parsed.error_code == "identifier_too_long"


class _IterStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self._chunks = chunks

    async def __aiter__(self):
        for c in self._chunks:
            if isinstance(c, Exception):
                raise c
            yield c


def _verifier(monkeypatch, jwks) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER, audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
    )
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
    return v


def _client(monkeypatch, jwks, events):
    from mcp_gateway import audit as audit_mod

    app = create_app(
        Settings(
            upstream_url=UPSTREAM, issuer=ISSUER, audience=AUDIENCE,
            jwks_url="https://issuer.test/jwks.json", host="127.0.0.1", port=8080,
        ),
        _verifier(monkeypatch, jwks),
        ScopePolicy.builtin(),
    )
    orig = audit_mod.AuditContext.emit_stream_event

    def capture(self, result, bytes_streamed):
        events.append({"result": result, "bytes": bytes_streamed})
        return orig(self, result, bytes_streamed)

    monkeypatch.setattr(audit_mod.AuditContext, "emit_stream_event", capture)
    return TestClient(app)


@respx.mock
def test_clean_stream_reports_completed(monkeypatch, jwks, rsa_key):
    events = []
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, content=b'{"jsonrpc":"2.0","result":"ok","id":1}')
    )
    c = _client(monkeypatch, jwks, events)
    token = mint(rsa_key, scope="mcp:read")
    body = '{"jsonrpc":"2.0","method":"tools/list","id":1}'
    with c.stream("POST", "/mcp", content=body, headers={"Authorization": f"Bearer {token}"}) as r:
        r.read()
    assert r.status_code == 200
    assert events
    assert events[-1]["result"] == "completed"


@respx.mock
def test_upstream_read_error_not_reported_completed(monkeypatch, jwks, rsa_key):
    events = []

    def erroring(request):
        return httpx.Response(
            200,
            stream=_IterStream([b'{"partial":', httpx.ReadError("upstream died")]),
            headers={"content-type": "application/json"},
        )

    respx.post(UPSTREAM).mock(side_effect=erroring)
    c = _client(monkeypatch, jwks, events)
    token = mint(rsa_key, scope="mcp:read")
    body = '{"jsonrpc":"2.0","method":"tools/list","id":1}'
    try:
        with c.stream("POST", "/mcp", content=body, headers={"Authorization": f"Bearer {token}"}) as r:
            r.read()
    except Exception:
        pass
    assert events
    assert events[-1]["result"] != "completed"
