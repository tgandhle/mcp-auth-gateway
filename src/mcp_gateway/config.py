"""Gateway configuration.

All settings are read from environment variables (prefix ``GATEWAY_``) or an
optional ``.env`` file. Nothing security-sensitive is hardcoded.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Inbound bind ---
    host: str = "127.0.0.1"
    port: int = 8080

    # --- Backend MCP server we proxy to ---
    # e.g. http://127.0.0.1:9000/mcp
    upstream_url: HttpUrl

    # --- Token verification (the authorization server that issues tokens) ---
    # Issuer claim we require (iss). Must match exactly.
    issuer: str
    # Audience claim we require (aud). Usually this gateway's own resource id.
    audience: str
    # JWKS endpoint of the authorization server. Required when auth is enabled.
    jwks_url: Optional[HttpUrl] = None
    # Allowed signing algorithms. RS256/ES256 only by default; never "none".
    allowed_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])

    # Clock skew tolerance for exp/nbf/iat, in seconds.
    leeway_seconds: int = 30

    # JWKS cache TTL in seconds.
    jwks_cache_ttl: int = 300

    # --- Scope policy ---
    # Path to a JSON file mapping MCP method -> required scope(s).
    # If unset, a built-in default policy is used.
    scope_policy_file: Optional[str] = None

    # Require auth on the proxied MCP endpoint. Disable only for local dev.
    require_auth: bool = True

    # Outbound request timeout to upstream, seconds.
    upstream_timeout: float = 30.0


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
