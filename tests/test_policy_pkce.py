"""Scope policy and PKCE tests."""

from __future__ import annotations

import base64
import hashlib

from mcp_gateway.policy import ScopePolicy
from mcp_gateway.pkce import generate_pkce, build_authorization_url


def test_read_method_requires_read_scope():
    p = ScopePolicy.builtin()
    assert p.check("tools/list", ["mcp:read"]).allowed
    assert not p.check("tools/list", []).allowed


def test_invoke_method_requires_invoke_scope():
    p = ScopePolicy.builtin()
    assert p.check("tools/call", ["mcp:invoke"]).allowed
    d = p.check("tools/call", ["mcp:read"])
    assert not d.allowed
    assert "mcp:invoke" in d.required


def test_handshake_needs_no_scope():
    p = ScopePolicy.builtin()
    assert p.check("initialize", []).allowed
    assert p.check("ping", []).allowed


def test_unknown_method_denied_by_default():
    p = ScopePolicy.builtin()
    d = p.check("admin/shutdown", ["mcp:read", "mcp:invoke"])
    assert not d.allowed
    assert "deny-by-default" in d.reason


def test_prefix_rule_overridable_by_exact():
    p = ScopePolicy(
        rules={
            "tools/": frozenset({"mcp:read"}),
            "tools/call": frozenset({"mcp:invoke"}),
        }
    )
    # prefix covers an unlisted tools/* method
    assert p.check("tools/describe", ["mcp:read"]).allowed
    # exact rule overrides prefix for tools/call
    assert not p.check("tools/call", ["mcp:read"]).allowed
    assert p.check("tools/call", ["mcp:invoke"]).allowed


def test_pkce_challenge_matches_verifier():
    pair = generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(pair.verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert pair.challenge == expected
    assert pair.method == "S256"
    assert 43 <= len(pair.verifier) <= 128


def test_pkce_pairs_are_unique():
    a = generate_pkce()
    b = generate_pkce()
    assert a.verifier != b.verifier


def test_authorization_url_contains_challenge():
    pair = generate_pkce()
    url, state = build_authorization_url(
        "https://issuer.test/authorize",
        client_id="cid",
        redirect_uri="https://app/callback",
        scopes=["mcp:read", "mcp:invoke"],
        pkce=pair,
    )
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert f"state={state}" in url
