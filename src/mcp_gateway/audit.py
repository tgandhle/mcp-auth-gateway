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
from typing import Optional

AUDIT_LOGGER = "mcp_gateway.audit"
_logger = logging.getLogger(AUDIT_LOGGER)


def new_request_id() -> str:
    return uuid.uuid4().hex


@dataclass
class AuditRecord:
    """One authorization decision. Fields are filled in as the request flows
    through verify -> parse -> policy -> proxy. Emit once at the end."""

    request_id: str
    source_ip: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    method: Optional[str] = None
    decision: str = "pending"          # allowed | denied | rejected | error
    error_code: Optional[str] = None
    reason: Optional[str] = None
    required_scopes: list[str] = field(default_factory=list)
    held_scope_count: int = 0
    upstream_status: Optional[int] = None
    latency_ms: Optional[float] = None
    _scope_values: list[str] = field(default_factory=list)  # DEBUG-only

    def to_dict(self, include_scope_values: bool = False) -> dict:
        d = {
            "request_id": self.request_id,
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
        }
        if include_scope_values:
            d["held_scopes"] = self._scope_values
        return {k: v for k, v in d.items() if v is not None}


class AuditContext:
    """Times a request and emits its record exactly once on exit."""

    def __init__(self, request_id: Optional[str] = None, source_ip: Optional[str] = None) -> None:
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
