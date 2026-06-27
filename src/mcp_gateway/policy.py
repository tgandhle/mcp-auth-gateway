"""Per-method scope policy for MCP JSON-RPC calls.

The MCP wire protocol is JSON-RPC 2.0. Each request carries a ``method`` such
as ``tools/call``, ``tools/list``, ``resources/read``. This module decides
which OAuth scope(s) a caller must hold to invoke a given method.

Policy resolution is longest-prefix: a rule for ``tools/`` covers every
``tools/*`` method, but a more specific ``tools/call`` rule overrides it. This
lets you say "listing tools needs mcp:read, calling them needs mcp:invoke"
without enumerating every method.

A method with no matching rule is denied by default when a default scope is
set, or allowed only if the policy explicitly opts into open-by-default. We
ship deny-by-default.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    required: frozenset[str]
    reason: str


@dataclass
class ScopePolicy:
    # Exact or prefix rule (key ending in "/" is a prefix) -> required scopes.
    # All listed scopes are required (AND). Use multiple to require a set.
    rules: dict[str, frozenset[str]] = field(default_factory=dict)
    # If no rule matches, require these. Empty frozenset + deny_by_default=True
    # means an unmatched method is denied outright.
    default: frozenset[str] = field(default_factory=frozenset)
    deny_by_default: bool = True

    @staticmethod
    def builtin() -> "ScopePolicy":
        """A sane default policy. Read methods need mcp:read, anything that
        executes or mutates needs mcp:invoke."""
        return ScopePolicy(
            rules={
                "initialize": frozenset(),          # handshake, no scope
                "ping": frozenset(),
                "tools/list": frozenset({"mcp:read"}),
                "tools/call": frozenset({"mcp:invoke"}),
                "resources/list": frozenset({"mcp:read"}),
                "resources/read": frozenset({"mcp:read"}),
                "resources/subscribe": frozenset({"mcp:read"}),
                "prompts/list": frozenset({"mcp:read"}),
                "prompts/get": frozenset({"mcp:read"}),
                "completion/complete": frozenset({"mcp:invoke"}),
            },
            default=frozenset(),
            deny_by_default=True,
        )

    @classmethod
    def from_file(cls, path: str) -> "ScopePolicy":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        rules = {k: frozenset(v) for k, v in data.get("rules", {}).items()}
        default = frozenset(data.get("default", []))
        deny = bool(data.get("deny_by_default", True))
        return cls(rules=rules, default=default, deny_by_default=deny)

    def _match(self, method: str) -> Optional[frozenset[str]]:
        # Exact match wins.
        if method in self.rules:
            return self.rules[method]
        # Longest prefix among rules that end in "/".
        best: Optional[str] = None
        for key in self.rules:
            if key.endswith("/") and method.startswith(key):
                if best is None or len(key) > len(best):
                    best = key
        if best is not None:
            return self.rules[best]
        return None

    def check(self, method: str, held_scopes: Iterable[str]) -> ScopeDecision:
        held = frozenset(held_scopes)
        required = self._match(method)

        if required is None:
            if self.deny_by_default and not self.default:
                return ScopeDecision(False, frozenset(), f"no policy for method '{method}' (deny-by-default)")
            required = self.default

        missing = required - held
        if missing:
            return ScopeDecision(False, required, f"missing scope(s): {sorted(missing)}")
        return ScopeDecision(True, required, "ok")
