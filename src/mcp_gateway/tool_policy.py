"""Per-tool authorization policy for MCP ``tools/call`` invocations.

Scope policy (``policy.py``) answers "may this token call the ``tools/call``
method at all?". This module answers the next question: "may it call *this
specific tool*?". The two are different axes and are checked in sequence at the
proxy; both fail closed.

The model is allow-list only: a tool is permitted only if its name appears in
the allow-set. Everything else is denied. There is deliberately no deny-list.
An allow-list makes the deny-by-default property total and trivial to verify by
reading the policy: enumerate the tools an agent may invoke, and everything not
enumerated is refused. This matches the posture you want for autonomous agents,
where the safe default is to permit only known-good actions.

The tool name for a ``tools/call`` request is carried in ``params.name`` per the
MCP wire protocol. A request whose tool name is missing or not a string cannot
be resolved to a tool and is a malformed request, not an authorization failure;
the caller distinguishes those two cases (400 vs 403) at the proxy.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    tool: str
    reason: str


@dataclass
class ToolPolicy:
    # The set of tool names permitted to be invoked via ``tools/call``. A tool
    # not in this set is denied. Matching is exact and case-sensitive: tool
    # names are identifiers, not free text, so "read_file" and "Read_File" are
    # different tools and a near-match must not slip through.
    allowed_tools: frozenset[str] = field(default_factory=frozenset)

    @staticmethod
    def builtin() -> ToolPolicy:
        """A conservative default: an empty allow-set, i.e. deny every tool.

        This is the safe default. A gateway that enables tool authorization
        without configuring an allow-list should refuse every tool call rather
        than fall open. Operators name the tools they trust explicitly.
        """
        return ToolPolicy(allowed_tools=frozenset())

    @classmethod
    def from_file(cls, path: str) -> ToolPolicy:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("tool policy file must be a JSON object")

        raw = data.get("allowed_tools", [])
        # A bare string here is the classic bug: "read_file" would become a set
        # of characters. Require an explicit list of strings.
        if isinstance(raw, str) or not isinstance(raw, list):
            raise ValueError(
                f"'allowed_tools' must be a list of tool-name strings, got {type(raw).__name__}"
            )
        if not all(isinstance(t, str) and t for t in raw):
            raise ValueError("'allowed_tools' must contain only non-empty strings")

        return cls(allowed_tools=frozenset(raw))

    def check(self, tool: str) -> ToolDecision:
        """Authorize a single tool by exact name.

        The caller is responsible for having already resolved a valid string
        tool name from the request; passing an empty string here is treated as
        an unauthorized (not malformed) call and denied, so this method never
        fails open even if misused.
        """
        if tool and tool in self.allowed_tools:
            return ToolDecision(True, tool, "ok")
        return ToolDecision(
            False, tool, f"tool '{tool}' is not in the allow-list (deny-by-default)"
        )

    def check_many(self, tools: Iterable[str]) -> bool:
        """Convenience: True only if every named tool is allowed. Unused by the
        proxy today (batches are refused before authorization) but kept so a
        future per-item batch check has a single obvious entry point."""
        return all(self.check(t).allowed for t in tools)