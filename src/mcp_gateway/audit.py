"""Structured security audit logging.

Every authorization decision the gateway makes emits one JSON line on the
``mcp_gateway.audit`` logger: who, what method, allowed or denied, why, and the
upstream outcome. This is the record you'd ship to a SIEM.

Hard rule: never log raw tokens, PKCE verifiers, or request/response bodies.
We log the subject and scope *counts* (not the scope values, to avoid leaking
entitlement detail into logs by default) plus the decision and a request id.
If you need scope values for debugging, raise the logger to DEBUG and they're
included there only.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field

AUDIT_LOGGER = "mcp_gateway.audit"
_logger = logging.getLogger(AUDIT_LOGGER)


def new_request_id() -> str:
    return uuid.uuid4().hex


@dataclass
class AuditRecord:
    """One authorization decision. Fields are filled in as the request flows
    through verify -> parse -> policy -> proxy. Emit once at the end."""

    request_id: str
    client_request_id: str | None = None
    source_ip: str | None = None
    subject: str | None = None
    issuer: str | None = None
    audience: str | None = None
    method: str | None = None
    decision: str = "pending"          # allowed | denied | rejected | error
    error_code: str | None = None
    reason: str | None = None
    required_scopes: list[str] = field(default_factory=list)
    held_scope_count: int = 0
    upstream_status: int | None = None
    latency_ms: float | None = None
    # Set on a follow-up event after the response body has finished streaming,
    # when something happened during streaming that the initial decision could
    # not capture (e.g. the response was truncated for exceeding the size cap).
    stream_result: str | None = None
    bytes_streamed: int | None = None
    _scope_values: list[str] = field(default_factory=list)  # DEBUG-only

    def to_dict(self, include_scope_values: bool = False) -> dict:
        d = {
            "request_id": self.request_id,
            "client_request_id": self.client_request_id,
            "source_ip": self.source_ip,
            "subject": self.subject,
            "issuer": self.issuer,
            "audience": self.audience,
            "method": self.method,
            "decision": self.decision,
            "error_code": self.error_code,
            "reason": self.reason,
            "required_scopes": self.required_scopes,
            "held_scope_count": self.held_scope_count,
            "upstream_status": self.upstream_status,
            "latency_ms": self.latency_ms,
            "stream_result": self.stream_result,
            "bytes_streamed": self.bytes_streamed,
        }
        if include_scope_values:
            d["held_scopes"] = self._scope_values
        return {k: v for k, v in d.items() if v is not None}


class AuditContext:
    """Times a request and emits its record exactly once on exit."""

    def __init__(self, request_id: str | None = None, source_ip: str | None = None) -> None:
        self.record = AuditRecord(request_id=request_id or new_request_id(), source_ip=source_ip)
        self._start = time.monotonic()

    def emit(self) -> None:
        self.record.latency_ms = round((time.monotonic() - self._start) * 1000, 2)
        debug_on = _logger.isEnabledFor(logging.DEBUG)
        payload = self.record.to_dict(include_scope_values=debug_on)
        line = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        # Denied/rejected/error are warnings; allowed is info.
        if self.record.decision in ("denied", "rejected", "error"):
            _logger.warning(line)
        else:
            _logger.info(line)

    def emit_stream_event(self, result: str, bytes_streamed: int) -> None:
        """Emit a second audit event after the response body has streamed.

        The initial event records the authorization decision ("allowed") at the
        moment the response starts. Once streaming is allowed, the status and
        headers are already sent, so a later problem (notably truncation for
        exceeding the response cap) cannot change that decision. This follow-up
        event records what actually happened to the body so a SIEM can tell a
        clean completion apart from a truncated one, which the first event
        cannot convey on its own.
        """
        self.record.stream_result = result
        self.record.bytes_streamed = bytes_streamed
        self.record.latency_ms = round((time.monotonic() - self._start) * 1000, 2)
        debug_on = _logger.isEnabledFor(logging.DEBUG)
        payload = self.record.to_dict(include_scope_values=debug_on)
        line = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        # A truncated stream is a warning; a clean completion is info.
        if result == "truncated_response_too_large":
            _logger.warning(line)
        else:
            _logger.info(line)
