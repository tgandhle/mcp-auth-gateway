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

    # Outbound request timeout to upstream, seconds (overall default).
    upstream_timeout: float = 30.0
    # Fine-grained timeouts; fall back to upstream_timeout when unset.
    connect_timeout: Optional[float] = None
    read_timeout: Optional[float] = None
    write_timeout: Optional[float] = None
    pool_timeout: Optional[float] = None

    # Reject request bodies larger than this many bytes (DoS guard). 0 = no limit.
    max_request_bytes: int = 5 * 1024 * 1024

    # Public base URL the gateway is reached at (e.g. https://mcp.example.com),
    # used to build the RFC 9728 metadata and WWW-Authenticate URLs correctly
    # when running behind TLS / a load balancer. Falls back to host:port.
    public_base_url: Optional[str] = None


def load_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
