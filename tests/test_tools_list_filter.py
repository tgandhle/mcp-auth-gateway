"""Unit tests for pure tools/list response filtering."""

from __future__ import annotations

import json

import pytest

from mcp_gateway.tool_policy import ToolPolicy, ToolRule
from mcp_gateway.tools_list import (
    FILTER_FAILED,
    MAX_TOOL_NAME_LEN,
    UPSTREAM_ERROR,
    filter_tools_list,
)

CLAIMS = {"groups": ["readers"]}


def _policy() -> ToolPolicy:
    return ToolPolicy(
        allowed_tools=frozenset({"list_directory"}),
        claim="groups",
        rules=(
            ToolRule(
                "readers",
                frozenset({"readers"}),
                frozenset({"read_file"}),
            ),
        ),
    )


def _tool(name: str) -> dict:
    return {"name": name, "description": name}


def _body(tools, **extra) -> bytes:
    result = {"tools": tools, **extra}
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": result}
    ).encode()


def _names(body: bytes) -> list[str]:
    return [
        item["name"]
        for item in json.loads(body)["result"]["tools"]
    ]


def test_keeps_exactly_tools_allowed_by_call_policy():
    policy = _policy()
    advertised = [
        _tool("read_file"),
        _tool("write_file"),
        _tool("list_directory"),
    ]
    outcome = filter_tools_list(_body(advertised), policy, CLAIMS)
    assert outcome.ok and outcome.body is not None
    assert _names(outcome.body) == ["read_file", "list_directory"]
    assert outcome.tools_returned == 2
    assert outcome.tools_filtered == 1
    returned = set(_names(outcome.body))
    removed = {tool["name"] for tool in advertised} - returned
    assert all(policy.check(name, CLAIMS).allowed for name in returned)
    assert all(not policy.check(name, CLAIMS).allowed for name in removed)


def test_empty_filtered_page_preserves_cursor():
    outcome = filter_tools_list(
        _body([_tool("write_file")], nextCursor="page-2"),
        _policy(),
        CLAIMS,
    )
    assert outcome.body is not None
    result = json.loads(outcome.body)["result"]
    assert result["tools"] == []
    assert result["nextCursor"] == "page-2"


def test_claims_change_visible_tools():
    policy = _policy()
    raw = _body([_tool("read_file"), _tool("list_directory")])
    reader = filter_tools_list(raw, policy, CLAIMS)
    other = filter_tools_list(raw, policy, {"groups": ["other"]})
    assert reader.body is not None and other.body is not None
    assert _names(reader.body) == ["read_file", "list_directory"]
    assert _names(other.body) == ["list_directory"]


def test_entry_and_unrelated_envelope_fields_are_preserved():
    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "abc",
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "read",
                        "inputSchema": {"type": "object"},
                    }
                ],
                "_meta": {"x": 1},
            },
        }
    ).encode()
    outcome = filter_tools_list(raw, _policy(), CLAIMS)
    assert outcome.body is not None
    doc = json.loads(outcome.body)
    assert doc["id"] == "abc"
    assert doc["result"]["_meta"] == {"x": 1}
    assert doc["result"]["tools"][0]["inputSchema"] == {"type": "object"}


def test_flat_and_empty_policies_filter_as_expected():
    raw = _body([_tool("read_file"), _tool("write_file")])
    flat = filter_tools_list(
        raw,
        ToolPolicy(allowed_tools=frozenset({"read_file"})),
        None,
    )
    empty = filter_tools_list(raw, ToolPolicy.builtin(), CLAIMS)
    assert flat.body is not None and _names(flat.body) == ["read_file"]
    assert empty.body is not None and _names(empty.body) == []


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not-json",
        b"\xff",
        b"[]",
        b'"scalar"',
        b'{"jsonrpc":"2.0","id":1}',
        b'{"jsonrpc":"1.0","id":1,"result":{"tools":[]}}',
        b'{"jsonrpc":"2.0","id":1,"result":{"tools":[],"x":NaN}}',
    ],
)
def test_unfilterable_envelope_fails_closed(raw):
    outcome = filter_tools_list(raw, _policy(), CLAIMS)
    assert outcome.error_code == FILTER_FAILED
    assert outcome.body is None


def test_http_200_jsonrpc_error_is_refused_distinctly():
    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32603,
                "data": {"tools": ["write_file"]},
            },
        }
    ).encode()
    outcome = filter_tools_list(raw, _policy(), CLAIMS)
    assert outcome.error_code == UPSTREAM_ERROR
    assert outcome.body is None


@pytest.mark.parametrize("result", [None, [], "tools", 7, True])
def test_non_object_result_fails_closed(result):
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": result}
    ).encode()
    assert filter_tools_list(raw, _policy(), CLAIMS).error_code == FILTER_FAILED


@pytest.mark.parametrize("tools", [None, {}, "read_file", 7, True])
def test_non_list_tools_fails_closed(tools):
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}
    ).encode()
    assert filter_tools_list(raw, _policy(), CLAIMS).error_code == FILTER_FAILED


@pytest.mark.parametrize(
    "entry",
    [
        None,
        "read_file",
        [],
        {},
        {"name": ""},
        {"name": 1},
        {"name": None},
        {"name": "a" * (MAX_TOOL_NAME_LEN + 1)},
    ],
)
def test_unevaluable_entry_fails_whole_response(entry):
    outcome = filter_tools_list(
        _body([_tool("read_file"), entry]),
        _policy(),
        CLAIMS,
    )
    assert outcome.error_code == FILTER_FAILED
    assert outcome.body is None


def test_name_at_bound_is_evaluated():
    name = "a" * MAX_TOOL_NAME_LEN
    outcome = filter_tools_list(
        _body([_tool(name)]),
        ToolPolicy(allowed_tools=frozenset({name})),
        None,
    )
    assert outcome.body is not None
    assert _names(outcome.body) == [name]


def test_duplicate_tools_members_cannot_survive_reserialization():
    raw = (
        b'{"jsonrpc":"2.0","id":1,"result":{"tools":[],'
        b'"tools":[{"name":"read_file"}]}}'
    )
    outcome = filter_tools_list(raw, _policy(), CLAIMS)
    assert outcome.body is not None
    assert outcome.body.count(b'"tools"') == 1
    assert _names(outcome.body) == ["read_file"]
