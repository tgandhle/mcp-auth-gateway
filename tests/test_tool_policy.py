"""Tool-authorization policy tests."""

from __future__ import annotations

import json

import pytest

from mcp_gateway.tool_policy import ToolPolicy


def test_allowed_tool_passes():
    p = ToolPolicy(allowed_tools=frozenset({"read_file", "list_dir"}))
    d = p.check("read_file")
    assert d.allowed
    assert d.tool == "read_file"


def test_tool_not_in_allowlist_denied():
    p = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    d = p.check("delete_file")
    assert not d.allowed
    assert "deny-by-default" in d.reason


def test_builtin_denies_everything():
    p = ToolPolicy.builtin()
    assert not p.check("read_file").allowed
    assert not p.check("anything").allowed


def test_empty_tool_name_denied_not_allowed():
    p = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    assert not p.check("").allowed


def test_matching_is_case_sensitive():
    p = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    assert p.check("read_file").allowed
    assert not p.check("Read_File").allowed
    assert not p.check("READ_FILE").allowed


def test_whitespace_variant_denied():
    p = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    assert not p.check(" read_file").allowed
    assert not p.check("read_file ").allowed


def test_from_file_roundtrip(tmp_path):
    f = tmp_path / "tool-policy.json"
    f.write_text(json.dumps({"allowed_tools": ["read_file", "list_dir"]}))
    p = ToolPolicy.from_file(str(f))
    assert p.check("read_file").allowed
    assert p.check("list_dir").allowed
    assert not p.check("delete_file").allowed


def test_from_file_rejects_bare_string(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"allowed_tools": "read_file"}))
    with pytest.raises(ValueError, match="list of tool-name strings"):
        ToolPolicy.from_file(str(f))


def test_from_file_rejects_non_string_entries(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"allowed_tools": ["read_file", 123]}))
    with pytest.raises(ValueError, match="non-empty strings"):
        ToolPolicy.from_file(str(f))


def test_from_file_rejects_empty_string_entries(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"allowed_tools": ["read_file", ""]}))
    with pytest.raises(ValueError, match="non-empty strings"):
        ToolPolicy.from_file(str(f))


def test_from_file_rejects_non_object(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps(["read_file"]))
    with pytest.raises(ValueError, match="must be a JSON object"):
        ToolPolicy.from_file(str(f))


def test_missing_allowed_tools_key_denies_all(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text(json.dumps({}))
    p = ToolPolicy.from_file(str(f))
    assert not p.check("read_file").allowed