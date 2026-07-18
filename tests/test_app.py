"""End-to-end app tests. Upstream MCP server is mocked with respx so we can
assert the gateway forwards correctly and strips the Authorization header."""

from __future__ import annotations

import json

import httpx
import respx
from fastapi.testclient import TestClient

from conftest import AUDIENCE, ISSUER, mint
from mcp_gateway.app import create_app
from mcp_gateway.config import Settings
from mcp_gateway.policy import ScopePolicy
from mcp_gateway.verifier import JwksVerifier

UPSTREAM = "http://upstream.test/mcp"


def _settings() -> Settings:
    return Settings(
        upstream_url=UPSTREAM,
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.test/jwks.json",
        host="127.0.0.1",
        port=8080,
    )


def _verifier(monkeypatch, jwks) -> JwksVerifier:
    v = JwksVerifier(
        jwks_url="https://issuer.test/jwks.json",
        issuer=ISSUER, audience=AUDIENCE,
        allowed_algorithms=["RS256", "ES256"],
    )
    # Serve the in-memory JWKS through the fetch seam; no HTTP.
    monkeypatch.setattr(v, "_fetch_jwks", lambda: jwks)
    return v


def _client(monkeypatch, jwks) -> TestClient:
    app = create_app(_settings(), _verifier(monkeypatch, jwks), ScopePolicy.builtin())
    return TestClient(app)


def _rpc(method: str) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()


def test_missing_token_401(monkeypatch, jwks):
    c = _client(monkeypatch, jwks)
    r = c.post("/mcp", content=_rpc("tools/list"))
    assert r.status_code == 401
    assert "resource_metadata" in r.headers.get("www-authenticate", "")


def test_invalid_token_401(monkeypatch, jwks):
    c = _client(monkeypatch, jwks)
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


@respx.mock
def test_valid_read_token_proxied(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    )
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert route.called
    # Authorization header must NOT be forwarded upstream; identity goes via X-Forwarded-*.
    sent = route.calls.last.request
    assert "authorization" not in {k.lower() for k in sent.headers}
    assert sent.headers.get("X-Forwarded-Sub") == "user-123"


@respx.mock
def test_read_token_cannot_invoke(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")  # lacks mcp:invoke
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers.get("www-authenticate", "")


@respx.mock
def test_invoke_token_can_invoke(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "done"})
    )
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert route.called


def test_metadata_endpoint_public(monkeypatch, jwks):
    c = _client(monkeypatch, jwks)
    r = c.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    body = r.json()
    # RFC 9728: resource is the protected resource's absolute URI, not the
    # opaque audience token. With no public_base_url set it falls back to the
    # bind address.
    assert body["resource"] == "http://127.0.0.1:8080"
    assert body["resource"].startswith(("http://", "https://"))
    assert ISSUER in body["authorization_servers"]


@respx.mock
def test_upstream_down_502(monkeypatch, jwks, rsa_key):
    respx.post(UPSTREAM).mock(side_effect=httpx.ConnectError("refused"))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=_rpc("tools/list"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 502


@respx.mock
def test_batch_rejected_not_forwarded(monkeypatch, jwks, rsa_key):
    # A batch containing tools/call must be refused, not proxied, even with a
    # valid token. This is the authorization-bypass case the review flagged.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")  # not even invoke scope
    batch = json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
    ]).encode()
    r = c.post("/mcp", content=batch, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "batch_not_supported"
    assert not route.called  # never reached upstream


@respx.mock
def test_malformed_json_rejected_not_forwarded(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=b"{not valid json", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_json"
    assert not route.called


@respx.mock
def test_object_without_method_rejected(monkeypatch, jwks, rsa_key):
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read")
    r = c.post("/mcp", content=b'{"jsonrpc":"2.0","id":1}', headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_jsonrpc"
    assert not route.called


@respx.mock
def test_inbound_identity_header_stripped(monkeypatch, jwks, rsa_key):
    # A client that sets X-Forwarded-Sub itself must not have it reach upstream;
    # the gateway overwrites it with the verified subject.
    route = respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:read", sub="real-user")
    r = c.post(
        "/mcp",
        content=_rpc("tools/list"),
        headers={
            "Authorization": f"Bearer {token}",
            "X-Forwarded-Sub": "admin-spoof",
            "X-User-Id": "spoof-2",
        },
    )
    assert r.status_code == 200
    sent = route.calls.last.request
    assert sent.headers.get("X-Forwarded-Sub") == "real-user"
    assert "x-user-id" not in {k.lower() for k in sent.headers}


@respx.mock
def test_client_request_id_not_trusted(monkeypatch, jwks, rsa_key, caplog):
    # A client-supplied X-Request-Id must not become the gateway's audit
    # correlation id, and must not leak upstream. The gateway mints its own id,
    # forwards that, and records the client's value separately as
    # client_request_id for tracing only.
    import logging

    route = respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "ok"})
    )
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:invoke")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post(
            "/mcp",
            content=_rpc("tools/call"),
            headers={"Authorization": f"Bearer {token}", "X-Request-Id": "client-chosen-id"},
        )
    assert r.status_code == 200

    sent = route.calls.last.request
    forwarded = sent.headers.get("X-Request-Id")
    # The gateway forwards its own id, never the client's.
    assert forwarded is not None
    assert forwarded != "client-chosen-id"
    assert len(forwarded) == 32  # uuid4().hex
    # The client's value must not survive anywhere in the upstream headers.
    assert "client-chosen-id" not in " ".join(sent.headers.values())

    # The audit record uses the gateway id as request_id and keeps the client's
    # value as a separate, clearly-labelled field.
    audit_line = [r.message for r in caplog.records if r.name == "mcp_gateway.audit"][-1]
    audit = json.loads(audit_line)
    assert audit["request_id"] == forwarded
    assert audit["request_id"] != "client-chosen-id"
    assert audit["client_request_id"] == "client-chosen-id"


@respx.mock
def test_request_id_minted_when_client_sends_none(monkeypatch, jwks, rsa_key, caplog):
    # With no inbound X-Request-Id, the gateway still mints one and does not
    # emit a client_request_id field.
    import logging

    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, json={}))
    c = _client(monkeypatch, jwks)
    token = mint(rsa_key, scope="mcp:invoke")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    audit_line = [r.message for r in caplog.records if r.name == "mcp_gateway.audit"][-1]
    audit = json.loads(audit_line)
    assert len(audit["request_id"]) == 32
    # client_request_id is dropped from output when None (to_dict strips None).
    assert "client_request_id" not in audit


# --- Streaming pass-through and response-size cap -----------------------------


def _settings_cap(max_response_bytes: int) -> Settings:
    return Settings(
        upstream_url=UPSTREAM,
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://issuer.test/jwks.json",
        host="127.0.0.1",
        port=8080,
        max_response_bytes=max_response_bytes,
    )


def _client_cap(monkeypatch, jwks, max_response_bytes: int) -> TestClient:
    app = create_app(
        _settings_cap(max_response_bytes), _verifier(monkeypatch, jwks), ScopePolicy.builtin()
    )
    return TestClient(app)


@respx.mock
def test_oversized_content_length_rejected_413(monkeypatch, jwks, rsa_key):
    # Upstream declares a Content-Length larger than the cap: clean 413 before
    # any body is streamed.
    big = b"x" * 100
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(
            200, content=big, headers={"content-length": str(len(big))}
        )
    )
    c = _client_cap(monkeypatch, jwks, max_response_bytes=10)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 413
    assert r.json()["error"] == "response_too_large"


@respx.mock
def test_under_cap_response_passes(monkeypatch, jwks, rsa_key):
    body = b'{"jsonrpc":"2.0","id":1,"result":"ok"}'
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, content=body, headers={"content-length": str(len(body))})
    )
    c = _client_cap(monkeypatch, jwks, max_response_bytes=10_000)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.content == body


@respx.mock
def test_streamed_response_passes_through(monkeypatch, jwks, rsa_key):
    # A multi-chunk upstream body is proxied through intact when under the cap.
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, content=b"chunk-a;chunk-b;chunk-c")
    )
    c = _client_cap(monkeypatch, jwks, max_response_bytes=10_000)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.content == b"chunk-a;chunk-b;chunk-c"


@respx.mock
def test_cap_zero_disables_limit(monkeypatch, jwks, rsa_key):
    big = b"y" * 5000
    respx.post(UPSTREAM).mock(
        return_value=httpx.Response(200, content=big, headers={"content-length": str(len(big))})
    )
    c = _client_cap(monkeypatch, jwks, max_response_bytes=0)
    token = mint(rsa_key, scope="mcp:invoke")
    r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert len(r.content) == 5000


@respx.mock
def test_midstream_cap_truncates(monkeypatch, jwks, rsa_key, caplog):
    # No Content-Length, body larger than the cap. The response starts (200,
    # headers already sent), so the cap is enforced by truncation: the client
    # receives at most cap-ish bytes, not the full body. A second audit event
    # must record the truncation so a SIEM can tell it from a clean response.
    import logging

    body = b"z" * 1000
    route_resp = httpx.Response(200, content=body)
    route_resp.headers.pop("content-length", None)
    respx.post(UPSTREAM).mock(return_value=route_resp)
    c = _client_cap(monkeypatch, jwks, max_response_bytes=100)
    token = mint(rsa_key, scope="mcp:invoke")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    # Status is 200 (already sent before truncation); body is truncated.
    assert r.status_code == 200
    assert len(r.content) < 1000

    # Two audit events: the initial "allowed", then a truncation follow-up.
    audit_events = [json.loads(rec.message) for rec in caplog.records if rec.name == "mcp_gateway.audit"]
    assert len(audit_events) >= 2
    last = audit_events[-1]
    assert last["stream_result"] == "truncated_response_too_large"
    assert last["bytes_streamed"] > 100


@respx.mock
def test_completed_stream_records_completion(monkeypatch, jwks, rsa_key, caplog):
    # An under-cap response streams to completion and the follow-up event
    # records a clean completion with the byte count.
    import logging

    body = b'{"jsonrpc":"2.0","id":1,"result":"ok"}'
    respx.post(UPSTREAM).mock(return_value=httpx.Response(200, content=body))
    c = _client_cap(monkeypatch, jwks, max_response_bytes=10_000)
    token = mint(rsa_key, scope="mcp:invoke")
    with caplog.at_level(logging.INFO, logger="mcp_gateway.audit"):
        r = c.post("/mcp", content=_rpc("tools/call"), headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    audit_events = [json.loads(rec.message) for rec in caplog.records if rec.name == "mcp_gateway.audit"]
    last = audit_events[-1]
    assert last["stream_result"] == "completed"
    assert last["bytes_streamed"] == len(body)
