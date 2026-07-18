"""Audit events must actually reach output when run via the entrypoint.

The ``mcp_gateway.audit`` logger emits one JSON line per decision, but a
logger with no handler drops INFO records; only WARNING+ escape via Python's
last-resort handler. As shipped before this fix, a fully successful session
produced zero visible audit lines (verified empirically end to end): every
"allowed" decision and every stream-completion event vanished, contradicting
the audit module's contract. ``configure_audit_logging`` closes that gap; these
tests pin its behavior.
"""

from __future__ import annotations

import logging

from mcp_gateway.__main__ import configure_audit_logging
from mcp_gateway.audit import AUDIT_LOGGER, AuditContext


def _reset_logger() -> tuple[list[logging.Handler], int, bool]:
    logger = logging.getLogger(AUDIT_LOGGER)
    saved = (list(logger.handlers), logger.level, logger.propagate)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True
    return saved


def _restore_logger(saved: tuple[list[logging.Handler], int, bool]) -> None:
    logger = logging.getLogger(AUDIT_LOGGER)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handlers, level, propagate = saved
    for h in handlers:
        logger.addHandler(h)
    logger.setLevel(level)
    logger.propagate = propagate


def test_allowed_decision_reaches_stdout(capsys):
    saved = _reset_logger()
    try:
        configure_audit_logging()
        ctx = AuditContext(request_id="req-1", source_ip="127.0.0.1")
        ctx.record.decision = "allowed"
        ctx.record.method = "tools/list"
        ctx.emit()
        out = capsys.readouterr().out
        assert '"decision":"allowed"' in out
        assert '"method":"tools/list"' in out
    finally:
        _restore_logger(saved)


def test_denied_decision_also_emitted_and_no_duplicates(capsys):
    saved = _reset_logger()
    try:
        configure_audit_logging()
        ctx = AuditContext(request_id="req-2")
        ctx.record.decision = "denied"
        ctx.emit()
        out = capsys.readouterr().out
        assert out.count('"request_id":"req-2"') == 1
    finally:
        _restore_logger(saved)


def test_configure_is_idempotent():
    saved = _reset_logger()
    try:
        configure_audit_logging()
        configure_audit_logging()
        logger = logging.getLogger(AUDIT_LOGGER)
        assert len(logger.handlers) == 1
        assert logger.level == logging.INFO
        assert logger.propagate is False
    finally:
        _restore_logger(saved)


def test_operator_configuration_is_respected():
    """An existing handler or explicit level must be left alone, so embedders
    (and DEBUG-for-scope-values setups) are unaffected."""
    saved = _reset_logger()
    try:
        logger = logging.getLogger(AUDIT_LOGGER)
        own = logging.NullHandler()
        logger.addHandler(own)
        logger.setLevel(logging.DEBUG)
        configure_audit_logging()
        assert logger.handlers == [own]          # no second handler added
        assert logger.level == logging.DEBUG     # explicit level untouched
    finally:
        _restore_logger(saved)
