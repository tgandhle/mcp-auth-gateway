"""Entrypoint: ``mcp-gateway`` / ``python -m mcp_gateway``."""

from __future__ import annotations

import sys

import uvicorn

from .app import create_app
from .config import load_settings
from .policy import ScopePolicy
from .verifier import JwksVerifier


def build() -> tuple[object, object]:
    settings = load_settings()

    policy = (
        ScopePolicy.from_file(settings.scope_policy_file)
        if settings.scope_policy_file
        else ScopePolicy.builtin()
    )

    verifier = None
    if settings.require_auth:
        jwks_url = str(settings.jwks_url) if settings.jwks_url else None
        if not jwks_url:
            print(
                "error: GATEWAY_JWKS_URL is required when auth is enabled "
                "(or set GATEWAY_REQUIRE_AUTH=false for local dev).",
                file=sys.stderr,
            )
            raise SystemExit(2)
        verifier = JwksVerifier(
            jwks_url=jwks_url,
            issuer=settings.issuer,
            audience=settings.audience,
            allowed_algorithms=settings.allowed_algorithms,
            leeway_seconds=settings.leeway_seconds,
            cache_ttl=settings.jwks_cache_ttl,
        )

    app = create_app(settings, verifier, policy)
    return app, settings


def main() -> None:
    app, settings = build()
    uvicorn.run(app, host=settings.host, port=settings.port)  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
