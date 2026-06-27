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
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .config import Settings
from .policy import ScopePolicy
from .verifier import JwksVerifier, TokenError, VerifiedToken

# JSON-RPC / HTTP constants
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return ""
    return header[7:].strip()


def _resource_metadata_url(settings: Settings) -> str:
    return f"http://{settings.host}:{settings.port}/.well-known/oauth-protected-resource"


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


def create_app(
    settings: Settings,
    verifier: JwksVerifier | None,
    policy: ScopePolicy,
) -> FastAPI:
    app = FastAPI(title="MCP Auth Gateway", version="0.1.0")
    client = httpx.AsyncClient(timeout=settings.upstream_timeout)

    @app.on_event("shutdown")
    async def _close() -> None:
        await client.aclose()

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
        raw = await request.body()

        # 1. Authenticate.
        verified: VerifiedToken | None = None
        if settings.require_auth:
            if verifier is None:
                return JSONResponse(
                    status_code=500,
                    content={"error": "server_misconfigured", "detail": "auth required but no verifier"},
                )
            token = _bearer_token(request)
            if not token:
                return _unauthorized(settings, "missing bearer token")
            try:
                verified = verifier.verify(token)
            except TokenError as exc:
                return _unauthorized(settings, str(exc))

        # 2. Parse the JSON-RPC method and enforce scope.
        held = verified.scopes if verified else frozenset()
        method = _extract_method(raw)
        if method is not None:
            decision = policy.check(method, held)
            if not decision.allowed:
                return _forbidden(decision.reason, sorted(decision.required))

        # 3. Reverse-proxy to upstream, forwarding safe headers and identity.
        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
        }
        if verified is not None:
            # Pass verified identity to upstream out-of-band. Upstream should
            # trust these only because it sits behind this gateway.
            fwd_headers["X-Forwarded-Sub"] = verified.subject
            fwd_headers["X-Forwarded-Scopes"] = " ".join(sorted(verified.scopes))

        try:
            upstream = await client.post(
                str(settings.upstream_url),
                content=raw,
                headers=fwd_headers,
            )
        except httpx.RequestError as exc:
            return JSONResponse(
                status_code=502,
                content={"error": "bad_gateway", "detail": f"upstream unreachable: {exc.__class__.__name__}"},
            )

        resp_headers = {
            k: v for k, v in upstream.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=upstream.headers.get("content-type"),
        )

    return app


def _extract_method(raw: bytes) -> str | None:
    """Pull the JSON-RPC ``method`` out of a request body. Returns None if the
    body isn't a single JSON-RPC object we can read a method from (e.g. a
    batch or non-JSON), in which case scope enforcement is skipped and the
    request is still authenticated. Batches are conservatively not method-scoped
    here; enforce per-method batching upstream or reject batches if needed."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        m = data.get("method")
        return m if isinstance(m, str) else None
    return None
