"""Startup configuration validation tests.

These exercise Settings.validate_runtime directly: a valid config passes, and
each semantically-unsafe config raises ConfigError listing the specific
problem(s). Construction goes through kwargs (not env) so each case is isolated.
"""

from __future__ import annotations

import pytest

from mcp_gateway.config import ConfigError, Settings


def _valid(**overrides) -> Settings:
    base = {
        "upstream_url": "http://upstream.test/mcp",
        "issuer": "https://issuer.test/",
        "audience": "mcp-gateway",
        "jwks_url": "https://issuer.test/jwks.json",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_valid_config_passes():
    _valid().validate_runtime()  # should not raise


def test_auth_on_without_jwks_url_fails():
    s = _valid(jwks_url=None)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_JWKS_URL" in p for p in ei.value.problems)


def test_auth_off_without_jwks_url_passes():
    # With auth disabled, no JWKS is needed.
    _valid(jwks_url=None, require_auth=False).validate_runtime()


def test_empty_issuer_fails():
    s = _valid(issuer="   ")
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_ISSUER" in p for p in ei.value.problems)


def test_empty_audience_fails():
    s = _valid(audience="")
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_AUDIENCE" in p for p in ei.value.problems)


def test_symmetric_algorithm_rejected():
    s = _valid(allowed_algorithms=["RS256", "HS256"])
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("asymmetric" in p for p in ei.value.problems)


def test_none_algorithm_rejected():
    s = _valid(allowed_algorithms=["none"])
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("asymmetric" in p for p in ei.value.problems)


def test_empty_algorithm_list_rejected():
    s = _valid(allowed_algorithms=[])
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("at least one algorithm" in p for p in ei.value.problems)


def test_missing_scope_policy_file_fails():
    s = _valid(scope_policy_file="/no/such/policy.json")
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_SCOPE_POLICY_FILE" in p for p in ei.value.problems)


def test_existing_scope_policy_file_passes(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text('{"rules": {}, "default": [], "deny_by_default": true}')
    _valid(scope_policy_file=str(f)).validate_runtime()


@pytest.mark.parametrize("port", [0, 70000, -1])
def test_bad_port_fails(port):
    s = _valid(port=port)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_PORT" in p for p in ei.value.problems)


def test_negative_leeway_fails():
    s = _valid(leeway_seconds=-5)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_LEEWAY_SECONDS" in p for p in ei.value.problems)


def test_zero_upstream_timeout_fails():
    s = _valid(upstream_timeout=0)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_UPSTREAM_TIMEOUT" in p for p in ei.value.problems)


def test_negative_fine_grained_timeout_fails():
    s = _valid(connect_timeout=-1.0)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_CONNECT_TIMEOUT" in p for p in ei.value.problems)


def test_public_base_url_without_scheme_fails():
    s = _valid(public_base_url="mcp.example.com")
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_PUBLIC_BASE_URL" in p for p in ei.value.problems)


def test_public_base_url_with_scheme_passes():
    _valid(public_base_url="https://mcp.example.com").validate_runtime()


def test_multiple_problems_all_reported():
    # All problems should be collected, not just the first.
    s = _valid(issuer="", audience="", port=0, allowed_algorithms=["none"])
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    problems = ei.value.problems
    assert len(problems) >= 4
    assert any("ISSUER" in p for p in problems)
    assert any("AUDIENCE" in p for p in problems)
    assert any("PORT" in p for p in problems)
    assert any("asymmetric" in p for p in problems)


def test_max_request_bytes_zero_allowed():
    # 0 explicitly means "no limit" and must be accepted.
    _valid(max_request_bytes=0).validate_runtime()


def test_negative_max_request_bytes_fails():
    s = _valid(max_request_bytes=-1)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_MAX_REQUEST_BYTES" in p for p in ei.value.problems)


def test_negative_jwks_min_refresh_interval_fails():
    s = _valid(jwks_min_refresh_interval=-1.0)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_JWKS_MIN_REFRESH_INTERVAL" in p for p in ei.value.problems)


def test_zero_jwks_min_refresh_interval_passes():
    # Zero is allowed: it means "always allow a forced refresh on kid miss".
    _valid(jwks_min_refresh_interval=0.0).validate_runtime()


def test_max_response_bytes_zero_allowed():
    _valid(max_response_bytes=0).validate_runtime()


def test_negative_max_response_bytes_fails():
    s = _valid(max_response_bytes=-1)
    with pytest.raises(ConfigError) as ei:
        s.validate_runtime()
    assert any("GATEWAY_MAX_RESPONSE_BYTES" in p for p in ei.value.problems)
