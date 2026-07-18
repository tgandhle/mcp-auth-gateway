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
from .tool_policy import ToolPolicy
from .verifier import JwksVerifier, TokenError, VerifiedToken

# JSON-RPC / HTTP constants
# Maximum length of a protocol identifier (method name, tool name). These are
# short strings by design; a longer value is malformed and, if echoed into logs
# or error bodies unbounded, is a cheap amplification vector. 256 is generous
# for any real MCP method or tool name.
_MAX_IDENTIFIER_LEN = 256
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
    # For a tools/call request, the tool named in params.name. None otherwise.
    # A tools/call whose name is missing or not a string is a parse error (the
    # request cannot be resolved to a tool), surfaced via ``error`` below.
    tool_name: str | None = None
    # Canonical re-serialization of the validated request object. The gateway
    # forwards THIS to the upstream, not the original bytes, so the upstream
    # parses exactly what the gateway authorized. Prevents a duplicate-key
    # parser differential (the gateway authorizing one value while a first-wins
    # upstream executes another). None when parsing failed.
    canonical_body: bytes | None = None
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


def _forbidden_tool(tool: str, detail: str) -> JSONResponse:
    # Distinct from insufficient_scope: the token's scopes were sufficient to
    # reach tools/call, but this specific tool is not permitted by policy.
    return JSONResponse(
        status_code=403,
        content={"error": "tool_not_allowed", "detail": detail, "tool": tool},
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
    tool_policy: ToolPolicy | None = None,
) -> FastAPI:
    # tool_policy is opt-in. When None, tool-call authorization is not applied
    # and tools/call is governed by scope alone (backward-compatible). When
    # provided, the allow-list is enforced with deny-by-default after the scope
    # check passes.
    client = httpx.AsyncClient(timeout=_build_timeout(settings))

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            await client.aclose()

    app = FastAPI(title="MCP Auth Gateway", version="0.2.0", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/oauth-protected-resource")
    async def protected_resource_metadata() -> dict[str, Any]:
        # RFC 9728: "resource" MUST be the protected resource's identifier as an
        # absolute URI (its canonical location), not an opaque audience string.
        # A conforming client validates that this matches the resource it called
        # and discards the metadata otherwise, so returning the audience token
        # here would make the document unusable. We return the gateway's own
        # base URL, which is the resource clients actually reach.
        return {
            "resource": _base_url(settings),
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
        audit.record.tool_name = parsed.tool_name
        decision = policy.check(parsed.method, held)  # type: ignore[arg-type]
        audit.record.required_scopes = sorted(decision.required)
        if not decision.allowed:
            audit.record.decision = "denied"
            audit.record.error_code = "insufficient_scope"
            audit.record.reason = decision.reason
            audit.emit()
            return _forbidden(decision.reason, sorted(decision.required))

        # 2b. Tool-call authorization (opt-in). Only applies to tools/call and
        #     only when a tool policy is configured. Runs after the scope check
        #     so a token must first be entitled to call tools/call at all; this
        #     narrows *which* tool. Fails closed on both axes:
        #       - a tools/call with no resolvable string params.name is a
        #         malformed request the policy can't evaluate -> 400
        #       - a well-named tool not on the allow-list -> 403
        #     Neither is ever forwarded. When no tool policy is set this whole
        #     block is skipped and tools/call behaves as it did before.
        if tool_policy is not None and parsed.method == "tools/call":
            if parsed.tool_name is None:
                audit.record.decision = "rejected"
                audit.record.error_code = "invalid_tool_call"
                audit.record.reason = "tools/call request missing a string 'params.name'"
                audit.emit()
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_tool_call",
                        "detail": "tools/call request missing a string 'params.name'",
                    },
                )
            tdecision = tool_policy.check(parsed.tool_name)
            if not tdecision.allowed:
                audit.record.decision = "denied"
                audit.record.error_code = "tool_not_allowed"
                audit.record.reason = tdecision.reason
                audit.emit()
                return _forbidden_tool(parsed.tool_name, tdecision.reason)

        # 3. Reverse-proxy. Strip a known set of inbound identity-bearing
        #    headers (see _SPOOFABLE_IDENTITY_HEADERS) before injecting verified
        #    identity, so a client can't spoof those specific conventions. This
        #    is a denylist and therefore not exhaustive: an upstream that trusts
        #    a header not in that set (e.g. Remote-User, X-Auth-Request-User,
        #    a vendor OIDC header) would still receive it. Configure the upstream
        #    to trust only the gateway-generated X-Forwarded-* identity headers;
        #    an outbound allowlist is a tracked hardening item.
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

        # Forward the canonical re-serialization, not the original bytes, so the
        # upstream parses exactly the object the gateway authorized. Falls back
        # to raw only defensively; canonical_body is always set on a successful
        # parse by the time we reach here.
        forward_body = parsed.canonical_body if parsed.canonical_body is not None else raw
        try:
            upstream_cm = client.stream(
                "POST",
                str(settings.upstream_url),
                content=forward_body,
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
            # only enforcement available mid-stream. We emit a second audit event
            # on exit so a truncated response is distinguishable in a SIEM from a
            # clean one (the initial "allowed" event cannot convey this).
            sent = 0
            # Default to an interrupted outcome; only a natural end of the
            # upstream iterator flips this to "completed". This way any exit via
            # exception or client cancellation is never mislabeled as clean.
            result = "client_disconnected"
            try:
                async for chunk in upstream.aiter_raw():
                    if cap > 0:
                        sent += len(chunk)
                        if sent > cap:
                            result = "truncated_response_too_large"
                            break
                    yield chunk
                else:
                    # The async-for completed without break: the upstream body
                    # ended naturally. Only here is the response truly complete.
                    result = "completed"
            except GeneratorExit:
                # The client went away mid-stream. Record it as a disconnect,
                # not a completion, then re-raise so the framework can finish
                # tearing down the response.
                result = "client_disconnected"
                raise
            except (httpx.HTTPError, httpx.StreamError) as exc:
                # Reading from the upstream failed partway. This is neither a
                # clean completion nor a policy truncation.
                result = "upstream_read_error"
                audit.record.reason = f"upstream stream error: {type(exc).__name__}"
            finally:
                await upstream_cm.__aexit__(None, None, None)
                audit.emit_stream_event(result=result, bytes_streamed=sent)

        return StreamingResponse(
            body_iter(),
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=upstream.headers.get("content-type"),
        )

    return app


class _DuplicateKey(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"duplicate JSON object member: {key!r}")


class _NonFiniteConstant(ValueError):
    def __init__(self, value: str) -> None:
        self.value = value
        super().__init__(f"non-standard JSON constant: {value}")


def _reject_nonfinite(value: str) -> None:
    """parse_constant hook: refuse NaN / Infinity / -Infinity.

    Python's json.loads accepts these by default and json.dumps re-emits them,
    but they are not RFC 8259 JSON. Letting them through would put non-standard
    tokens in the canonical body, reintroducing a (mild) parser-family
    divergence the canonicalization exists to eliminate: a lax upstream parses
    them, a strict one rejects the whole request. Fail closed at the gateway
    instead, matching the duplicate-key posture.
    """
    raise _NonFiniteConstant(value)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """object_pairs_hook that rejects any object with a duplicate member name,
    recursively (it runs for every nested object). Python's default json.loads
    silently keeps the last value for a duplicate key; an upstream parser using
    first-wins semantics would keep a different one, letting an attacker have
    the gateway authorize one method/tool while the upstream executes another.
    Refusing duplicates removes the ambiguity at the source."""
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey(key)
        seen.add(key)
    return dict(pairs)


def _parse_jsonrpc(raw: bytes) -> JsonRpcParse:
    """Strictly parse a single JSON-RPC request and resolve its method.

    Fails closed. Returns an error (which the caller turns into a 400) for:
      - malformed / non-JSON bodies
      - objects containing duplicate member names (parser-differential guard)
      - NaN / Infinity constants (not RFC 8259; parser-differential guard)
      - JSON-RPC batches (arrays): per-item authz is not implemented, so we
        refuse rather than forward a request whose methods we haven't checked
      - JSON that isn't an object
      - objects missing a string ``method``

    On success it also produces ``canonical_body``: a re-serialization of the
    validated object that the caller forwards upstream instead of the original
    bytes, so the upstream parses exactly what the gateway authorized.
    """
    try:
        data = json.loads(
            raw,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except _DuplicateKey as exc:
        return JsonRpcParse(
            error=f"request contains a duplicate JSON object member: {exc.key!r}",
            error_code="duplicate_json_key",
        )
    except _NonFiniteConstant as exc:
        return JsonRpcParse(
            error=f"request contains a non-standard JSON constant: {exc.value}",
            error_code="nonstandard_json_constant",
        )
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

    # Bound identifier length. A method (or tool name) is a short protocol
    # identifier; anything long is malformed and, unbounded, would land in audit
    # logs and error responses verbatim. Reject early rather than echo it.
    if len(method) > _MAX_IDENTIFIER_LEN:
        return JsonRpcParse(
            error=f"'method' exceeds maximum length of {_MAX_IDENTIFIER_LEN}",
            error_code="identifier_too_long",
        )
    # Canonical serialization of the validated object. Forwarding this (not the
    # original bytes) is what closes the parser differential: the upstream can
    # no longer see bytes that parse differently from what we authorized.
    canonical = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    # For tools/call, extract the tool name from params.name when present. We do
    # NOT reject a missing/non-string name here: that check belongs to the
    # tool-authorization layer, which is opt-in. When no tool policy is
    # configured the gateway must treat tools/call exactly as before (name not
    # required), preserving backward compatibility. Whether a missing name is a
    # 400 is decided later, only when a tool policy is active.
    if method == "tools/call":
        params = data.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        # Bound tool-name length for the same reason as method above.
        if isinstance(name, str) and len(name) > _MAX_IDENTIFIER_LEN:
            return JsonRpcParse(
                error=f"tool name exceeds maximum length of {_MAX_IDENTIFIER_LEN}",
                error_code="identifier_too_long",
            )
        tool = name if isinstance(name, str) and name else None
        return JsonRpcParse(method=method, tool_name=tool, canonical_body=canonical)

    return JsonRpcParse(method=method, canonical_body=canonical)
