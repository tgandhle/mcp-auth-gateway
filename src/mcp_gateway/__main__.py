"""Entrypoint: ``mcp-gateway`` / ``python -m mcp_gateway``."""

from __future__ import annotations

import logging
import sys

import uvicorn
from fastapi import FastAPI

from .app import create_app
from .audit import AUDIT_LOGGER
from .config import ConfigError, Settings, load_settings
from .policy import ScopePolicy
from .tool_policy import ToolPolicy
from .verifier import JwksVerifier


def configure_audit_logging() -> None:
    """Ensure audit events actually reach output when run via the entrypoint.

    The ``mcp_gateway.audit`` logger emits one JSON line per decision, but
    uvicorn's default log config never touches it: with no handler attached,
    INFO events (every allowed decision and every stream-completion event) were
    silently dropped, and only WARNING+ leaked to stderr via Python's
    last-resort handler. That contradicted the audit module's contract that
    every decision is emitted. Verified empirically: a fully successful
    end-to-end session produced zero visible audit lines.

    Idempotent, and deferential to operators: an existing handler or an
    explicitly set level is left alone, so embedders who configure logging
    themselves (including DEBUG for scope values) are unaffected. Lines are
    emitted bare (message only) on stdout; they are already JSON.
    """
    logger = logging.getLogger(AUDIT_LOGGER)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    if logger.level == logging.NOTSET:
        logger.setLevel(logging.INFO)
    # The line is emitted here; propagating to the root logger risks a
    # duplicate emit (or a lastResort duplicate for WARNING+).
    logger.propagate = False


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
    configure_audit_logging()
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
