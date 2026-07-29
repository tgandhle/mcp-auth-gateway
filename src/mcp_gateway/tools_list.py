"""Pure filtering for JSON ``tools/list`` responses."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .tool_policy import ToolPolicy

MAX_TOOL_NAME_LEN = 256
FILTER_FAILED = "tools_list_filter_failed"
UPSTREAM_ERROR = "tools_list_upstream_error"


@dataclass(frozen=True)
class FilterOutcome:
    """A rewritten body or a fail-closed error, never both."""

    body: bytes | None
    error_code: str | None = None
    tools_returned: int = 0
    tools_filtered: int = 0

    @property
    def ok(self) -> bool:
        return self.error_code is None


def _failed() -> FilterOutcome:
    return FilterOutcome(body=None, error_code=FILTER_FAILED)


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def filter_tools_list(
    raw: bytes,
    policy: ToolPolicy,
    claims: Mapping[str, Any] | None,
) -> FilterOutcome:
    """Filter one decoded JSON tools/list page with the tools/call policy.

    Pages are independent: ``nextCursor`` and unrelated envelope/result fields
    are preserved. Any structure that cannot be evaluated fails closed.
    """
    try:
        doc = json.loads(raw, parse_constant=_reject_nonfinite)
    except (ValueError, UnicodeDecodeError):
        return _failed()

    if not isinstance(doc, dict) or doc.get("jsonrpc") != "2.0":
        return _failed()
    if "error" in doc:
        # error.data is unconstrained and may contain the same entitlement
        # detail this feature withholds. Refuse it distinctly so operators can
        # distinguish an upstream JSON-RPC error from malformed filter input.
        return FilterOutcome(body=None, error_code=UPSTREAM_ERROR)
    result = doc.get("result")
    if not isinstance(result, dict):
        return _failed()
    tools = result.get("tools")
    if not isinstance(tools, list):
        return _failed()

    kept: list[dict[str, Any]] = []
    for entry in tools:
        if not isinstance(entry, dict):
            return _failed()
        name = entry.get("name")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > MAX_TOOL_NAME_LEN
        ):
            return _failed()
        if policy.check(name, claims).allowed:
            kept.append(entry)

    result["tools"] = kept
    try:
        body = json.dumps(
            doc,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return _failed()
    return FilterOutcome(
        body=body,
        tools_returned=len(kept),
        tools_filtered=len(tools) - len(kept),
    )
