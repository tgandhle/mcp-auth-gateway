"""Property-based fuzzing of the JSON-RPC parser.

``_parse_jsonrpc`` is the security boundary: anything it returns with a non-None
``method`` and a None ``error`` will be scope-checked and may be forwarded
upstream. The invariant we fuzz for is strict and one-directional:

  A parse result may resolve to a forwardable method ONLY for a JSON object
  that carries a non-empty string ``method``. Everything else -- non-JSON,
  arrays (batches), non-object JSON, objects with a missing/empty/non-string
  method -- MUST come back as an error and MUST NOT yield a method.

If the fuzzer can produce any input that violates that, it is a fail-open: a
request the gateway would forward without having authorized a known method.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_gateway.app import _parse_jsonrpc

# ---- Invariant helpers -----------------------------------------------------

def _is_forwardable(parsed) -> bool:
    """A result the gateway would carry forward to scope-check + proxy."""
    return parsed.error is None and isinstance(parsed.method, str) and parsed.method != ""


def _assert_fail_closed(parsed) -> None:
    """If not forwardable, it must be an explicit error with no method."""
    if not _is_forwardable(parsed):
        assert parsed.error is not None, "non-forwardable result must carry an error"
        assert parsed.method is None, "non-forwardable result must not expose a method"


# ---- Strategies ------------------------------------------------------------

# Arbitrary bytes: most will be non-JSON. Exercises the json.loads guard.
_raw_bytes = st.binary(max_size=512)

# Arbitrary JSON values (objects, arrays, scalars, nested), serialized to bytes.
_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=32),
    lambda children: st.lists(children, max_size=6) | st.dictionaries(st.text(max_size=16), children, max_size=6),
    max_leaves=25,
)


def _to_body(value) -> bytes:
    return json.dumps(value).encode()


# ---- Properties ------------------------------------------------------------

@settings(max_examples=2000, suppress_health_check=[HealthCheck.too_slow])
@given(_raw_bytes)
def test_arbitrary_bytes_never_fail_open(raw: bytes):
    """No raw byte string may parse into a forwardable method unless it happens
    to be a valid JSON object with a string method -- in which case forwardable
    is correct. The invariant we assert is the fail-closed contract itself."""
    parsed = _parse_jsonrpc(raw)
    _assert_fail_closed(parsed)
    # If it IS forwardable, prove it really was a JSON object with a str method.
    if _is_forwardable(parsed):
        data = json.loads(raw)
        assert isinstance(data, dict)
        assert isinstance(data.get("method"), str) and data["method"] != ""


@settings(max_examples=2000, suppress_health_check=[HealthCheck.too_slow])
@given(_json_values)
def test_arbitrary_json_respects_contract(value):
    parsed = _parse_jsonrpc(_to_body(value))
    _assert_fail_closed(parsed)
    forwardable = _is_forwardable(parsed)
    is_valid_request = (
        isinstance(value, dict)
        and isinstance(value.get("method"), str)
        and value.get("method") != ""
    )
    # The two must agree exactly: forwardable IFF it's a well-formed single request.
    assert forwardable == is_valid_request, (
        f"contract mismatch: forwardable={forwardable} expected={is_valid_request} value={value!r}"
    )


@settings(max_examples=1000)
@given(st.lists(st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=4), max_size=6))
def test_batches_always_refused(batch):
    """Any JSON array -- a batch -- must be refused regardless of contents,
    including an empty array and arrays of otherwise-valid request objects."""
    parsed = _parse_jsonrpc(_to_body(batch))
    assert parsed.error is not None
    assert parsed.method is None
    assert parsed.error_code == "batch_not_supported"


@settings(max_examples=1000)
@given(st.text(max_size=64))
def test_method_must_be_nonempty_string(method_val):
    """An object whose 'method' is a string is forwardable IFF non-empty."""
    parsed = _parse_jsonrpc(_to_body({"jsonrpc": "2.0", "id": 1, "method": method_val}))
    if method_val == "":
        assert parsed.error is not None and parsed.method is None
    else:
        assert _is_forwardable(parsed) and parsed.method == method_val
