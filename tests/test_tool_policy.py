"""Tool-authorization policy tests."""

from __future__ import annotations

import json

import pytest

from mcp_gateway.tool_policy import ToolPolicy, ToolRule

# --------------------------------------------------------------------------
# Unconditional allow-list (original behavior, unchanged)
# --------------------------------------------------------------------------


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


def test_unconditional_allow_records_sentinel_rule():
    p = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    assert p.check("read_file").matched_rule == "[unconditional]"


def test_denial_records_no_rule():
    p = ToolPolicy(allowed_tools=frozenset({"read_file"}))
    assert p.check("delete_file").matched_rule is None


# --------------------------------------------------------------------------
# Claim-bound rules
# --------------------------------------------------------------------------


def _rules_policy() -> ToolPolicy:
    return ToolPolicy(
        allowed_tools=frozenset({"list_directory"}),
        claim="groups",
        rules=(
            ToolRule("readers", frozenset({"mcp-readers"}), frozenset({"read_file"})),
            ToolRule("operators", frozenset({"mcp-operators"}), frozenset({"write_file"})),
        ),
    )


def test_rule_grants_tool_to_matching_group():
    d = _rules_policy().check("read_file", {"groups": ["mcp-readers"]})
    assert d.allowed
    assert d.matched_rule == "readers"


def test_rule_does_not_grant_other_groups_tools():
    d = _rules_policy().check("write_file", {"groups": ["mcp-readers"]})
    assert not d.allowed
    assert "not permitted for the token's 'groups' values" in d.reason


def test_permitted_sets_union_across_matching_rules():
    claims = {"groups": ["mcp-readers", "mcp-operators"]}
    p = _rules_policy()
    assert p.check("read_file", claims).allowed
    assert p.check("write_file", claims).allowed


def test_unconditional_list_applies_regardless_of_claims():
    p = _rules_policy()
    assert p.check("list_directory", {"groups": ["nobody-in-particular"]}).allowed
    assert p.check("list_directory", {}).allowed


def test_unknown_group_matches_no_rule():
    d = _rules_policy().check("read_file", {"groups": ["some-other-team"]})
    assert not d.allowed
    assert "no rule matches" in d.reason


def test_absent_claim_denies_with_its_own_reason():
    d = _rules_policy().check("read_file", {"sub": "user-1"})
    assert not d.allowed
    assert "absent" in d.reason
    assert "groups" in d.reason


def test_no_claims_supplied_denies_when_rules_present():
    # A wiring bug that forgets to pass claims must fail closed, not open.
    d = _rules_policy().check("read_file")
    assert not d.allowed


def test_claim_name_is_configurable():
    p = ToolPolicy(
        claim="memberOf",
        rules=(ToolRule("r", frozenset({"grp"}), frozenset({"read_file"})),),
    )
    assert p.check("read_file", {"memberOf": ["grp"]}).allowed
    # Same values under the wrong claim name must not authorize.
    assert not p.check("read_file", {"groups": ["grp"]}).allowed


def test_string_claim_is_one_value_not_whitespace_split():
    p = ToolPolicy(
        rules=(ToolRule("r", frozenset({"Domain Admins"}), frozenset({"read_file"})),),
    )
    assert p.check("read_file", {"groups": "Domain Admins"}).allowed
    # The two halves must not become independently matchable values.
    p2 = ToolPolicy(rules=(ToolRule("r", frozenset({"Domain"}), frozenset({"read_file"})),))
    assert not p2.check("read_file", {"groups": "Domain Admins"}).allowed


def test_claim_matching_is_case_sensitive():
    p = _rules_policy()
    assert not p.check("read_file", {"groups": ["MCP-Readers"]}).allowed


@pytest.mark.parametrize(
    "value",
    [
        123,
        True,
        {"nested": "object"},
        ["ok", 7],
        ["ok", None],
        ["ok", ["nested"]],
        "",
        [""],
    ],
)
def test_unusable_claim_shapes_are_denied_not_coerced(value):
    d = _rules_policy().check("read_file", {"groups": value})
    assert not d.allowed


def test_unusable_claim_reason_names_the_claim():
    d = _rules_policy().check("read_file", {"groups": 123})
    assert "not a string or list of strings" in d.reason
    assert "groups" in d.reason


def test_empty_list_claim_matches_no_rule():
    d = _rules_policy().check("read_file", {"groups": []})
    assert not d.allowed
    assert "no rule matches" in d.reason


def test_check_many_requires_every_tool():
    claims = {"groups": ["mcp-readers"]}
    p = _rules_policy()
    assert p.check_many(["read_file", "list_directory"], claims)
    assert not p.check_many(["read_file", "write_file"], claims)


# --------------------------------------------------------------------------
# Claim-bound file parsing
# --------------------------------------------------------------------------


def _write(tmp_path, obj) -> str:
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(obj))
    return str(f)


def test_from_file_parses_rules(tmp_path):
    p = ToolPolicy.from_file(
        _write(
            tmp_path,
            {
                "claim": "groups",
                "allowed_tools": ["list_directory"],
                "rules": [
                    {"name": "readers", "any_of": ["mcp-readers"], "allowed_tools": ["read_file"]}
                ],
            },
        )
    )
    assert p.claim == "groups"
    assert p.claim_bound
    assert p.check("read_file", {"groups": ["mcp-readers"]}).matched_rule == "readers"
    assert p.check("list_directory", {}).allowed


def test_rule_name_defaults_to_index(tmp_path):
    p = ToolPolicy.from_file(
        _write(tmp_path, {"rules": [{"any_of": ["g"], "allowed_tools": ["read_file"]}]})
    )
    assert p.check("read_file", {"groups": ["g"]}).matched_rule == "rules[0]"


def test_flat_policy_is_not_claim_bound(tmp_path):
    p = ToolPolicy.from_file(_write(tmp_path, {"allowed_tools": ["read_file"]}))
    assert not p.claim_bound


def test_unknown_top_level_key_rejected(tmp_path):
    # A typo must fail at load, not silently deny everything at 3am.
    path = _write(tmp_path, {"allowed_tools": [], "rulez": []})
    with pytest.raises(ValueError, match="unknown key"):
        ToolPolicy.from_file(path)


def test_unknown_rule_key_rejected(tmp_path):
    path = _write(tmp_path, {"rules": [{"any_of": ["g"], "allowed_tools": [], "deny": ["x"]}]})
    with pytest.raises(ValueError, match="unknown key"):
        ToolPolicy.from_file(path)


def test_empty_claim_name_rejected(tmp_path):
    path = _write(tmp_path, {"claim": "", "allowed_tools": []})
    with pytest.raises(ValueError, match="non-empty string"):
        ToolPolicy.from_file(path)


def test_rules_must_be_a_list(tmp_path):
    path = _write(tmp_path, {"rules": {"any_of": ["g"]}})
    with pytest.raises(ValueError, match="list of rule objects"):
        ToolPolicy.from_file(path)


def test_rule_must_be_an_object(tmp_path):
    path = _write(tmp_path, {"rules": ["mcp-readers"]})
    with pytest.raises(ValueError, match="must be a JSON object"):
        ToolPolicy.from_file(path)


def test_rule_any_of_required_and_non_empty(tmp_path):
    path = _write(tmp_path, {"rules": [{"any_of": [], "allowed_tools": ["read_file"]}]})
    with pytest.raises(ValueError, match="at least one claim value"):
        ToolPolicy.from_file(path)


def test_rule_missing_allowed_tools_rejected(tmp_path):
    path = _write(tmp_path, {"rules": [{"any_of": ["g"]}]})
    with pytest.raises(ValueError, match="required"):
        ToolPolicy.from_file(path)


def test_rule_any_of_bare_string_rejected(tmp_path):
    path = _write(tmp_path, {"rules": [{"any_of": "g", "allowed_tools": []}]})
    with pytest.raises(ValueError, match="must be a list"):
        ToolPolicy.from_file(path)
