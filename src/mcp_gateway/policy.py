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
        if not isinstance(data, dict):
            raise ValueError("scope policy file must be a JSON object")

        raw_rules = data.get("rules", {})
        if not isinstance(raw_rules, dict):
            raise ValueError("'rules' must be an object mapping method -> [scopes]")
        rules: dict[str, frozenset[str]] = {}
        for method, scopes in raw_rules.items():
            # A bare string here is the classic bug: "mcp:invoke" would become a
            # set of characters. Require an explicit list of strings.
            if isinstance(scopes, str) or not isinstance(scopes, list):
                raise ValueError(
                    f"rule '{method}' must map to a list of scope strings, got {type(scopes).__name__}"
                )
            if not all(isinstance(s, str) for s in scopes):
                raise ValueError(f"rule '{method}' contains a non-string scope")
            rules[method] = frozenset(scopes)

        raw_default = data.get("default", [])
        if isinstance(raw_default, str) or not isinstance(raw_default, list):
            raise ValueError("'default' must be a list of scope strings")
        if not all(isinstance(s, str) for s in raw_default):
            raise ValueError("'default' contains a non-string scope")
        default = frozenset(raw_default)

        raw_deny = data.get("deny_by_default", True)
        if not isinstance(raw_deny, bool):
            raise ValueError("'deny_by_default' must be a JSON boolean (true/false)")

        return cls(rules=rules, default=default, deny_by_default=raw_deny)

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
