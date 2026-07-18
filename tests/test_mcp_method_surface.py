"""The scope policies must cover the full client-to-server MCP surface.

A spec-compliant MCP client sends ``notifications/initialized`` immediately
after the initialize response. An earlier builtin policy had no rule for it, so
deny-by-default returned 403 and killed every session right after the
handshake; verified end to end with the official MCP SDK on both sides of the
gateway (client failed at the first post-handshake call, and adding a
``notifications/`` rule restored the full flow). This walk pins the builtin
policy, and the shipped example policy file, to the spec's client-to-server
methods so the gap cannot reopen.

The method list is the client-to-server surface of the MCP specification:
requests a client may send to a server, plus the client-to-server
notifications. Server-to-client traffic (sampling, elicitation, roots
requests, server notifications) never arrives at the gateway's inbound
endpoint and is deliberately absent.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_gateway.policy import ScopePolicy

FULL = frozenset({"mcp:read", "mcp:invoke"})

# method -> scopes that must be sufficient to call it.
CLIENT_TO_SERVER: dict[str, frozenset[str]] = {
    # Lifecycle: valid token required (enforced by the auth layer), no scope.
    "initialize": frozenset(),
    "ping": frozenset(),
    "notifications/initialized": frozenset(),
    "notifications/cancelled": frozenset(),
    "notifications/progress": frozenset(),
    "notifications/roots/list_changed": frozenset(),
    # Read surface.
    "tools/list": frozenset({"mcp:read"}),
    "resources/list": frozenset({"mcp:read"}),
    "resources/templates/list": frozenset({"mcp:read"}),
    "resources/read": frozenset({"mcp:read"}),
    "resources/subscribe": frozenset({"mcp:read"}),
    "resources/unsubscribe": frozenset({"mcp:read"}),
    "prompts/list": frozenset({"mcp:read"}),
    "prompts/get": frozenset({"mcp:read"}),
    # Invoke surface.
    "tools/call": frozenset({"mcp:invoke"}),
    "completion/complete": frozenset({"mcp:invoke"}),
    "logging/setLevel": frozenset({"mcp:invoke"}),
}


def test_builtin_policy_allows_every_spec_method_with_full_scopes():
    policy = ScopePolicy.builtin()
    denied = [m for m in CLIENT_TO_SERVER if not policy.check(m, FULL).allowed]
    assert denied == [], f"builtin policy denies spec methods: {denied}"


def test_builtin_policy_requires_exactly_the_expected_scopes():
    policy = ScopePolicy.builtin()
    for method, sufficient in CLIENT_TO_SERVER.items():
        decision = policy.check(method, sufficient)
        assert decision.allowed, f"{method} denied with {sorted(sufficient)}: {decision.reason}"


def test_builtin_policy_lifecycle_needs_no_scope_but_reads_and_invokes_do():
    policy = ScopePolicy.builtin()
    for method, sufficient in CLIENT_TO_SERVER.items():
        decision = policy.check(method, frozenset())
        if sufficient:
            assert not decision.allowed, f"{method} must require a scope"
        else:
            assert decision.allowed, f"lifecycle method {method} must be scope-free"


def test_builtin_policy_still_denies_unknown_methods():
    policy = ScopePolicy.builtin()
    for method in ("admin/shutdown", "made-up/method", "tools_call", "notificationsX"):
        assert not policy.check(method, FULL).allowed


def test_example_policy_file_allows_every_spec_method():
    example = Path(__file__).resolve().parents[1] / "examples" / "scope-policy.json"
    policy = ScopePolicy.from_file(str(example))
    denied = [m for m in CLIENT_TO_SERVER if not policy.check(m, FULL).allowed]
    assert denied == [], f"examples/scope-policy.json denies spec methods: {denied}"
    # And it keeps the deny-by-default posture.
    data = json.loads(example.read_text(encoding="utf-8"))
    assert data.get("deny_by_default") is True
