"""The gateway application.

Flow for a proxied MCP request:

  client --(Bearer JWT)--> gateway --> [verify JWT] --> [parse JSON-RPC method]
        --> [check scope policy] --> reverse-proxy to upstream MCP server

Endpoints:
  POST /mcp                          the proxied MCP endpoint (protected)
  GET  /.well-known/oauth-protected-resource   RFC 9728 metadata (public)
  GET  /healthz                      liveness (public)

The 401 path returns a ``WWW-Authenticate`` header pointing at the
protected-resource metadata, which is how spec-compliant MCP clients learn
where to get a token.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .audit import AuditContext, new_request_id
from .config import Settings
from .policy import ScopePolicy
from .verifier import JwksVerifier, TokenError, VerifiedToken

# JSON-RPC / HTTP constants
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}

# Inbound headers a client could set to forge identity. Stripped before the
# gateway injects its own verified values, so they can never be trusted from
# the client side. Lowercased for case-insensitive matching.
_SPOOFABLE_IDENTITY_HEADERS = {
    "x-forwarded-sub", "x-forwarded-scopes", "x-user", "x-user-id",
    "x-principal", "x-authenticated-user", "x-forwarded-user",
}


@dataclass
class JsonRpcParse:
    method: str | None = None
    error: str | None = None
    error_code: str = "invalid_jsonrpc"


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return ""
    return header[7:].strip()


def _base_url(settings: Settings) -> str:
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    return f"http://{settings.host}:{settings.port}"


def _resource_metadata_url(settings: Settings) -> str:
    return f"{_base_url(settings)}/.well-known/oauth-protected-resource"


def _unauthorized(settings: Settings, detail: str) -> JSONResponse:
    meta = _resource_metadata_url(settings)
    return JSONResponse(
        status_code=401,
        content={"error": "unauthorized", "detail": detail},
        headers={"WWW-Authenticate": f'Bearer resource_metadata="{meta}"'},
    )


def _forbidden(detail: str, required: list[str]) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"error": "insufficient_scope", "detail": detail, "required_scopes": required},
        headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{" ".join(required)}"'},
    )


def _build_timeout(settings: Settings) -> httpx.Timeout:
    base = settings.upstream_timeout
    return httpx.Timeout(
        connect=settings.connect_timeout if settings.connect_timeout is not None else base,
        read=settings.read_timeout if settings.read_timeout is not None else base,
        write=settings.write_timeout if settings.write_timeout is not None else base,
        pool=settings.pool_timeout if settings.pool_timeout is not None else base,
    )


def create_app(
    settings: Settings,
    verifier: JwksVerifier | None,
    policy: ScopePolicy,
) -> FastAPI:
    client = httpx.AsyncClient(timeout=_build_timeout(settings))

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            await client.aclose()

    app = FastAPI(title="MCP Auth Gateway", version="0.1.0", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/oauth-protected-resource")
    async def protected_resource_metadata() -> dict[str, Any]:
        # RFC 9728: tell clients which authorization server guards this resource.
        return {
            "resource": settings.audience,
            "authorization_servers": [settings.issuer],
            "scopes_supported": sorted(
                {s for scopes in policy.rules.values() for s in scopes}
            ),
            "bearer_methods_supported": ["header"],
        }

    @app.post("/mcp")
    async def proxy_mcp(request: Request) -> Response:
        # Audit correlation id is always gateway-owned. A client-supplied
        # X-Request-Id is recorded separately as client_request_id for tracing,
        # but is never used as the primary audit id and is never forwarded as
        # if the gateway minted it. This keeps audit correlation under the
        # gateway's control: a caller cannot choose, collide, or forge it.
        client_rid = request.headers.get("x-request-id")
        audit = AuditContext(
            request_id=new_request_id(),
            source_ip=request.client.host if request.client else None,
        )
        audit.record.client_request_id = client_rid
        audit.record.issuer = settings.issuer
        audit.record.audience = settings.audience

        # 0. Body-size guard before reading the whole body into memory.
        if settings.max_request_bytes > 0:
            declared = request.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > settings.max_request_bytes:
                audit.record.decision = "rejected"
                audit.record.error_code = "payload_too_large"
                audit.emit()
                return JSONResponse(status_code=413, content={"error": "payload_too_large", "detail": "request body exceeds limit"})

        raw = await request.body()
        if settings.max_request_bytes > 0 and len(raw) > settings.max_request_bytes:
            audit.record.decision = "rejected"
            audit.record.error_code = "payload_too_large"
            audit.emit()
            return JSONResponse(status_code=413, content={"error": "payload_too_large", "detail": "request body exceeds limit"})

        # 1. Authenticate.
        verified: VerifiedToken | None = None
        if settings.require_auth:
            if verifier is None:
                audit.record.decision = "error"
                audit.record.error_code = "server_misconfigured"
                audit.emit()
                return JSONResponse(status_code=500, content={"error": "server_misconfigured", "detail": "auth required but no verifier"})
            token = _bearer_token(request)
            if not token:
                audit.record.decision = "rejected"
                audit.record.error_code = "missing_token"
                audit.emit()
                return _unauthorized(settings, "missing bearer token")
            try:
                verified = verifier.verify(token)
            except TokenError as exc:
                audit.record.decision = "rejected"
                audit.record.error_code = "invalid_token"
                audit.record.reason = str(exc)
                audit.emit()
                return _unauthorized(settings, str(exc))
            audit.record.subject = verified.subject
            audit.record.held_scope_count = len(verified.scopes)
            audit.record._scope_values = sorted(verified.scopes)

        # 2. Parse the JSON-RPC request and enforce scope. Fails closed:
        #    anything we cannot resolve to a single authorized method is
        #    rejected, never forwarded. Batches are refused because per-item
        #    authorization is not implemented.
        held = verified.scopes if verified else frozenset()
        parsed = _parse_jsonrpc(raw)
        if parsed.error is not None:
            audit.record.decision = "rejected"
            audit.record.error_code = parsed.error_code
            audit.record.reason = parsed.error
            audit.emit()
            return JSONResponse(status_code=400, content={"error": parsed.error_code, "detail": parsed.error})

        audit.record.method = parsed.method
        decision = policy.check(parsed.method, held)  # type: ignore[arg-type]
        audit.record.required_scopes = sorted(decision.required)
        if not decision.allowed:
            audit.record.decision = "denied"
            audit.record.error_code = "insufficient_scope"
            audit.record.reason = decision.reason
            audit.emit()
            return _forbidden(decision.reason, sorted(decision.required))

        # 3. Reverse-proxy. Strip every inbound identity-bearing header before
        #    injecting verified identity, so a client can't spoof it.
        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP
            and k.lower() != "authorization"
            and k.lower() != "x-request-id"
            and k.lower() not in _SPOOFABLE_IDENTITY_HEADERS
        }
        fwd_headers["X-Request-Id"] = audit.record.request_id
        if verified is not None:
            fwd_headers["X-Forwarded-Sub"] = verified.subject
            fwd_headers["X-Forwarded-Scopes"] = " ".join(sorted(verified.scopes))

        try:
            upstream_cm = client.stream(
                "POST",
                str(settings.upstream_url),
                content=raw,
                headers=fwd_headers,
            )
            upstream = await upstream_cm.__aenter__()
        except httpx.RequestError as exc:
            audit.record.decision = "error"
            audit.record.error_code = "bad_gateway"
            audit.record.reason = exc.__class__.__name__
            audit.emit()
            return JSONResponse(status_code=502, content={"error": "bad_gateway", "detail": f"upstream unreachable: {exc.__class__.__name__}"})

        # Response-size cap, clean path: if the upstream declares a Content-Length
        # larger than the cap, reject with 413 before any body is streamed. The
        # response has not started, so a proper status is still possible.
        cap = settings.max_response_bytes
        if cap > 0:
            declared = upstream.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > cap:
                await upstream_cm.__aexit__(None, None, None)
                audit.record.decision = "rejected"
                audit.record.error_code = "response_too_large"
                audit.emit()
                return JSONResponse(
                    status_code=413,
                    content={"error": "response_too_large", "detail": "upstream response exceeds limit"},
                )

        audit.record.decision = "allowed"
        audit.record.upstream_status = upstream.status_code
        audit.emit()

        resp_headers = {
            k: v for k, v in upstream.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }

        async def body_iter():
            # Stream upstream chunks straight through. Enforce the cap as we go:
            # once the running total exceeds it we stop yielding and let the
            # context manager close, which terminates the connection. The status
            # and headers are already sent at this point, so truncation is the
            # only enforcement available mid-stream.
            sent = 0
            try:
                async for chunk in upstream.aiter_raw():
                    if cap > 0:
                        sent += len(chunk)
                        if sent > cap:
                            # Stop; the partial body the client already has is
                            # terminated by closing the upstream stream below.
                            break
                    yield chunk
            finally:
                await upstream_cm.__aexit__(None, None, None)

        return StreamingResponse(
            body_iter(),
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=upstream.headers.get("content-type"),
        )

    return app


def _parse_jsonrpc(raw: bytes) -> JsonRpcParse:
    """Strictly parse a single JSON-RPC request and resolve its method.

    Fails closed. Returns an error (which the caller turns into a 400) for:
      - malformed / non-JSON bodies
      - JSON-RPC batches (arrays): per-item authz is not implemented, so we
        refuse rather than forward a request whose methods we haven't checked
      - JSON that isn't an object
      - objects missing a string ``method``

    Only a well-formed single request with a string method returns a method
    for the scope policy to evaluate.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return JsonRpcParse(error="request body is not valid JSON", error_code="invalid_json")

    if isinstance(data, list):
        return JsonRpcParse(
            error="JSON-RPC batch requests are not supported; send one request per call",
            error_code="batch_not_supported",
        )
    if not isinstance(data, dict):
        return JsonRpcParse(error="JSON-RPC request must be an object", error_code="invalid_jsonrpc")

    method = data.get("method")
    if not isinstance(method, str) or not method:
        return JsonRpcParse(error="JSON-RPC request missing a string 'method'", error_code="invalid_jsonrpc")

    return JsonRpcParse(method=method)
