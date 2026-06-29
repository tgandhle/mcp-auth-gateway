"""Gateway configuration.

All settings are read from environment variables (prefix ``GATEWAY_``) or an
optional ``.env`` file. Nothing security-sensitive is hardcoded.
"""

from __future__ import annotations

import os

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(ValueError):
    """Raised when settings are syntactically valid (they parsed) but
    semantically unsafe or unusable to run with. Carries every problem found,
    not just the first, so an operator can fix them in one pass."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        joined = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"invalid gateway configuration:\n{joined}")


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
    jwks_url: HttpUrl | None = None
    # Allowed signing algorithms. RS256/ES256 only by default; never "none".
    allowed_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])

    # Clock skew tolerance for exp/nbf/iat, in seconds.
    leeway_seconds: int = 30

    # JWKS cache TTL in seconds.
    jwks_cache_ttl: int = 300

    # --- Scope policy ---
    # Path to a JSON file mapping MCP method -> required scope(s).
    # If unset, a built-in default policy is used.
    scope_policy_file: str | None = None

    # Require auth on the proxied MCP endpoint. Disable only for local dev.
    require_auth: bool = True

    # Outbound request timeout to upstream, seconds (overall default).
    upstream_timeout: float = 30.0
    # Fine-grained timeouts; fall back to upstream_timeout when unset.
    connect_timeout: float | None = None
    read_timeout: float | None = None
    write_timeout: float | None = None
    pool_timeout: float | None = None

    # Reject request bodies larger than this many bytes (DoS guard). 0 = no limit.
    max_request_bytes: int = 5 * 1024 * 1024

    # Public base URL the gateway is reached at (e.g. https://mcp.example.com),
    # used to build the RFC 9728 metadata and WWW-Authenticate URLs correctly
    # when running behind TLS / a load balancer. Falls back to host:port.
    public_base_url: str | None = None

    def validate_runtime(self) -> None:
        """Fail fast on configurations that parse but are unsafe or unusable.

        Collects all problems and raises a single ConfigError listing them, so
        the operator fixes everything in one pass rather than one error at a
        time. Called at startup before any verifier or policy is built.
        """
        problems: list[str] = []

        # Identity claims must be present and non-blank. Pydantic guarantees the
        # type but not that the string is meaningful; an empty issuer/audience
        # would make every token verification fail in a confusing way.
        if not self.issuer.strip():
            problems.append("GATEWAY_ISSUER must not be empty")
        if not self.audience.strip():
            problems.append("GATEWAY_AUDIENCE must not be empty")

        # Algorithms: mirror the verifier's rule (asymmetric only, non-empty) so
        # the operator gets a clean config error instead of a constructor
        # traceback at build time.
        if not self.allowed_algorithms:
            problems.append("GATEWAY_ALLOWED_ALGORITHMS must list at least one algorithm")
        else:
            bad = [a for a in self.allowed_algorithms if not a.startswith(("RS", "ES", "PS"))]
            if bad:
                problems.append(
                    f"GATEWAY_ALLOWED_ALGORITHMS may only contain asymmetric algorithms "
                    f"(RS*/ES*/PS*); rejected: {bad}"
                )

        # When auth is enabled, a JWKS endpoint is mandatory; without it the
        # gateway cannot verify anything.
        if self.require_auth and self.jwks_url is None:
            problems.append(
                "GATEWAY_JWKS_URL is required when auth is enabled "
                "(or set GATEWAY_REQUIRE_AUTH=false for local dev)"
            )

        # A scope policy file, if named, must exist and be readable now rather
        # than failing on first request.
        if self.scope_policy_file and not os.path.isfile(self.scope_policy_file):
            problems.append(
                f"GATEWAY_SCOPE_POLICY_FILE points to a missing file: {self.scope_policy_file}"
            )

        # Numeric sanity. These parse as ints/floats but are nonsensical at or
        # below certain bounds.
        if not (0 < self.port < 65536):
            problems.append(f"GATEWAY_PORT must be between 1 and 65535, got {self.port}")
        if self.leeway_seconds < 0:
            problems.append(f"GATEWAY_LEEWAY_SECONDS must be >= 0, got {self.leeway_seconds}")
        if self.jwks_cache_ttl < 0:
            problems.append(f"GATEWAY_JWKS_CACHE_TTL must be >= 0, got {self.jwks_cache_ttl}")
        if self.max_request_bytes < 0:
            problems.append(
                f"GATEWAY_MAX_REQUEST_BYTES must be >= 0 (0 disables the limit), "
                f"got {self.max_request_bytes}"
            )
        if self.upstream_timeout <= 0:
            problems.append(
                f"GATEWAY_UPSTREAM_TIMEOUT must be > 0, got {self.upstream_timeout}"
            )
        for name, value in (
            ("GATEWAY_CONNECT_TIMEOUT", self.connect_timeout),
            ("GATEWAY_READ_TIMEOUT", self.read_timeout),
            ("GATEWAY_WRITE_TIMEOUT", self.write_timeout),
            ("GATEWAY_POOL_TIMEOUT", self.pool_timeout),
        ):
            if value is not None and value <= 0:
                problems.append(f"{name} must be > 0 when set, got {value}")

        # public_base_url, when set, must carry a scheme or the metadata and
        # WWW-Authenticate URLs built from it will be malformed.
        if self.public_base_url and not self.public_base_url.startswith(("http://", "https://")):
            problems.append(
                "GATEWAY_PUBLIC_BASE_URL must start with http:// or https:// when set, "
                f"got {self.public_base_url!r}"
            )

        if problems:
            raise ConfigError(problems)


def load_settings() -> Settings:
    settings = Settings()  # type: ignore[call-arg]
    settings.validate_runtime()
    return settings
