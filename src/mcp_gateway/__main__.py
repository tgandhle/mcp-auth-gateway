"""Entrypoint: ``mcp-gateway`` / ``python -m mcp_gateway``."""

from __future__ import annotations

import sys

import uvicorn
from fastapi import FastAPI

from .app import create_app
from .config import ConfigError, Settings, load_settings
from .policy import ScopePolicy
from .tool_policy import ToolPolicy
from .verifier import JwksVerifier


def build() -> tuple[FastAPI, Settings]:
    settings = load_settings()

    policy = (
        ScopePolicy.from_file(settings.scope_policy_file)
        if settings.scope_policy_file
        else ScopePolicy.builtin()
    )

    # Tool-call authorization is opt-in: build a policy only when a file is
    # configured. When None, create_app leaves tools/call to scope alone.
    tool_policy = (
        ToolPolicy.from_file(settings.tool_policy_file)
        if settings.tool_policy_file
        else None
    )

    verifier = None
    if settings.require_auth:
        # load_settings has already validated that jwks_url is present when auth
        # is enabled, so this is guaranteed non-None here.
        verifier = JwksVerifier(
            jwks_url=str(settings.jwks_url),
            issuer=settings.issuer,
            audience=settings.audience,
            allowed_algorithms=settings.allowed_algorithms,
            leeway_seconds=settings.leeway_seconds,
            cache_ttl=settings.jwks_cache_ttl,
            min_refresh_interval=settings.jwks_min_refresh_interval,
        )

    app = create_app(settings, verifier, policy, tool_policy)
    return app, settings


def main() -> None:
    try:
        app, settings = build()
    except ConfigError as exc:
        # Configuration problems are operator errors, not bugs: print the list
        # cleanly and exit non-zero rather than dumping a traceback.
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
