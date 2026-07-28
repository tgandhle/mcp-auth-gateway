"""Per-tool authorization policy for MCP ``tools/call`` invocations.

Scope policy (``policy.py``) answers "may this token call the ``tools/call``
method at all?". This module answers the next question: "may *this caller* call
*this specific tool*?". The two are different axes and are checked in sequence
at the proxy; both fail closed.

The model is allow-list only: a tool is permitted only if its name appears in
the set the caller is entitled to. Everything else is denied. There is
deliberately no deny-list. An allow-list makes the deny-by-default property
total and trivial to verify by reading the policy: enumerate the tools an agent
may invoke, and everything not enumerated is refused. This matches the posture
you want for autonomous agents, where the safe default is to permit only
known-good actions.

Two forms of policy are supported, and they compose:

*Unconditional* ``allowed_tools`` applies to every caller that got past the
scope check. This is the original single-list form and still behaves exactly as
it did.

*Claim-bound* ``rules`` bind a set of tools to a set of claim values, normally
group membership. A caller's permitted set is the unconditional list unioned
with the ``allowed_tools`` of every rule whose ``any_of`` values intersect the
caller's claim. No matching rule means an empty additional set, so the
deny-by-default property is unchanged: authorization is additive from an empty
base and there is no construction that widens it implicitly.

The claim inspected is configurable (``claim``, default ``groups``) because
issuers disagree: ``groups`` and ``memberOf`` are both common, and a policy
written against the wrong name would deny every request with no obvious cause.
Naming it explicitly, and auditing an absent claim as its own reason, turns
that silent outage into a diagnosable one.

Claim values are read strictly. A string claim is one value; it is *not* split
on whitespace, because a group named ``Domain Admins`` must never be read as
the two values ``Domain`` and ``Admins``. A list claim must contain only
non-empty strings. Anything else (a number, a nested object, a mixed list) is
treated as unusable rather than coerced, and the request is denied. Guessing at
the meaning of a malformed entitlement claim is how authorization bypasses are
built.

The tool name for a ``tools/call`` request is carried in ``params.name`` per the
MCP wire protocol. A request whose tool name is missing or not a string cannot
be resolved to a tool and is a malformed request, not an authorization failure;
the caller distinguishes those two cases (400 vs 403) at the proxy.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

# Recognised keys. Anything else in the file is an error rather than an ignored
# extra: a typo like "rulez" or "allowed_tool" would otherwise parse cleanly and
# silently produce a policy that denies everything, discovered in production.
_POLICY_KEYS = frozenset({"allowed_tools", "claim", "rules"})
_RULE_KEYS = frozenset({"name", "any_of", "allowed_tools"})

# Sentinel names for the audit trail. Bracketed so they cannot collide with a
# rule an operator actually named.
_UNCONDITIONAL = "[unconditional]"


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    tool: str
    reason: str
    # Which rule authorized this call, for the audit line. ``[unconditional]``
    # when the tool came from the top-level allow-list, a rule name when a
    # claim-bound rule matched, None on a denial.
    matched_rule: str | None = None


@dataclass(frozen=True)
class ToolRule:
    """Grant a set of tools to callers holding any of a set of claim values."""

    name: str
    any_of: frozenset[str]
    allowed_tools: frozenset[str]


def _claim_values(claims: Mapping[str, Any] | None, name: str) -> tuple[frozenset[str], str | None]:
    """Read one claim as a set of string values.

    Returns ``(values, problem)`` where problem is None on success, ``"absent"``
    when the claim is not present at all, and ``"unusable"`` when it is present
    but not a string or list of non-empty strings. The two problems are kept
    apart because they mean different things operationally: absent is usually a
    misconfigured claim name at the issuer, unusable is a malformed token.
    """
    if not claims or name not in claims:
        return frozenset(), "absent"
    raw = claims[name]
    if isinstance(raw, str):
        # One value, never split on whitespace. See module docstring.
        return (frozenset({raw}), None) if raw else (frozenset(), "unusable")
    if isinstance(raw, list) and all(isinstance(v, str) and v for v in raw):
        return frozenset(raw), None
    return frozenset(), "unusable"


@dataclass
class ToolPolicy:
    # Tools permitted to every caller that passed the scope check. Matching is
    # exact and case-sensitive: tool names are identifiers, not free text, so
    # "read_file" and "Read_File" are different tools and a near-match must not
    # slip through.
    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    # The claim consulted by ``rules``. Ignored when there are no rules.
    claim: str = "groups"
    rules: tuple[ToolRule, ...] = ()

    @property
    def claim_bound(self) -> bool:
        """True when this policy consults token claims. Lets the proxy log a
        useful reason when claims were required but none were available."""
        return bool(self.rules)

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

        unknown = sorted(set(data) - _POLICY_KEYS)
        if unknown:
            raise ValueError(
                f"unknown key(s) in tool policy file: {', '.join(unknown)}; "
                f"expected only {', '.join(sorted(_POLICY_KEYS))}"
            )

        allowed = _string_list(data.get("allowed_tools", []), "'allowed_tools'")

        claim = data.get("claim", "groups")
        if not isinstance(claim, str) or not claim:
            raise ValueError("'claim' must be a non-empty string naming a token claim")

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError(f"'rules' must be a list of rule objects, got {type(raw_rules).__name__}")

        rules: list[ToolRule] = []
        for i, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise ValueError(f"rule at index {i} must be a JSON object")
            unknown = sorted(set(raw) - _RULE_KEYS)
            if unknown:
                raise ValueError(
                    f"unknown key(s) in rule at index {i}: {', '.join(unknown)}; "
                    f"expected only {', '.join(sorted(_RULE_KEYS))}"
                )
            name = raw.get("name", f"rules[{i}]")
            if not isinstance(name, str) or not name:
                raise ValueError(f"rule at index {i}: 'name' must be a non-empty string")
            any_of = _string_list(raw.get("any_of"), f"rule '{name}': 'any_of'")
            if not any_of:
                # A rule matching nothing grants nothing; it is always a mistake
                # and it is better to say so at boot than to leave an operator
                # wondering why a group has no access.
                raise ValueError(f"rule '{name}': 'any_of' must list at least one claim value")
            tools = _string_list(raw.get("allowed_tools"), f"rule '{name}': 'allowed_tools'")
            rules.append(ToolRule(name=name, any_of=any_of, allowed_tools=tools))

        return cls(allowed_tools=allowed, claim=claim, rules=tuple(rules))

    def check(self, tool: str, claims: Mapping[str, Any] | None = None) -> ToolDecision:
        """Authorize a single tool by exact name for a caller's claims.

        The caller is responsible for having already resolved a valid string
        tool name from the request; passing an empty string here is treated as
        an unauthorized (not malformed) call and denied, so this method never
        fails open even if misused.

        ``claims`` is optional so the unconditional-only policy keeps its old
        one-argument call shape. When a policy has rules and no claims are
        supplied, no rule can match and the call is denied.
        """
        if not tool:
            return ToolDecision(False, tool, "empty tool name is never authorized (deny-by-default)")

        if tool in self.allowed_tools:
            return ToolDecision(True, tool, "ok", matched_rule=_UNCONDITIONAL)

        if not self.rules:
            return ToolDecision(
                False, tool, f"tool '{tool}' is not in the allow-list (deny-by-default)"
            )

        values, problem = _claim_values(claims, self.claim)
        if problem == "absent":
            return ToolDecision(
                False,
                tool,
                f"claim '{self.claim}' is absent from the token, so no rule can match "
                f"(deny-by-default)",
            )
        if problem == "unusable":
            return ToolDecision(
                False,
                tool,
                f"claim '{self.claim}' is not a string or list of strings; refusing to "
                f"coerce it (deny-by-default)",
            )

        matched_any = False
        for rule in self.rules:
            if not values & rule.any_of:
                continue
            matched_any = True
            if tool in rule.allowed_tools:
                return ToolDecision(True, tool, "ok", matched_rule=rule.name)

        if not matched_any:
            return ToolDecision(
                False,
                tool,
                f"no rule matches the token's '{self.claim}' values (deny-by-default)",
            )
        return ToolDecision(
            False,
            tool,
            f"tool '{tool}' is not permitted for the token's '{self.claim}' values "
            f"(deny-by-default)",
        )

    def check_many(self, tools: Iterable[str], claims: Mapping[str, Any] | None = None) -> bool:
        """Convenience: True only if every named tool is allowed. Unused by the
        proxy today (batches are refused before authorization) but kept so a
        future per-item batch check has a single obvious entry point."""
        return all(self.check(t, claims).allowed for t in tools)


def _string_list(raw: Any, label: str) -> frozenset[str]:
    """Validate a list-of-non-empty-strings field and return it as a set.

    A bare string is the classic bug: "read_file" would become a set of
    characters. Require an explicit list of strings.
    """
    if raw is None:
        raise ValueError(f"{label} is required and must be a list of strings")
    if isinstance(raw, str) or not isinstance(raw, list):
        raise ValueError(f"{label} must be a list of tool-name strings, got {type(raw).__name__}")
    if not all(isinstance(t, str) and t for t in raw):
        raise ValueError(f"{label} must contain only non-empty strings")
    return frozenset(raw)
