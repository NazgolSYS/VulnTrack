from unittest.mock import MagicMock
import pytest

from app.models import AuditLog
from app.services.audit_log_service import (
    get_audit_logs,
    record_audit_event,
)


def test_record_audit_event_adds_and_flushes_audit_log():
    db = MagicMock()

    result = record_audit_event(
        db,
        user_id=7,
        action="created",
        entity_type="vulnerability",
        entity_id=42,
        details="Created a test vulnerability",
        ip_address="127.0.0.1",
    )

    db.add.assert_called_once_with(result)
    db.flush.assert_called_once_with()

    assert result.user_id == 7
    assert result.action == "created"
    assert result.entity_type == "vulnerability"
    assert result.entity_id == 42
    assert result.details == "Created a test vulnerability"
    assert result.ip_address == "127.0.0.1"


def test_record_audit_event_supports_optional_fields():
    db = MagicMock()

    result = record_audit_event(
        db,
        user_id=None,
        action="system_event",
        entity_type="scan",
    )

    assert result.user_id is None
    assert result.entity_id is None
    assert result.details is None
    assert result.ip_address is None

    db.add.assert_called_once_with(result)
    db.flush.assert_called_once_with()


def test_record_audit_event_propagates_flush_error():
    db = MagicMock()
    db.flush.side_effect = RuntimeError(
        "Database flush failed"
    )

    with pytest.raises(
        RuntimeError,
        match="Database flush failed",
    ):
        record_audit_event(
            db,
            user_id=7,
            action="created",
            entity_type="vulnerability",
            entity_id=42,
        )

    db.add.assert_called_once()
    db.flush.assert_called_once_with()
    db.commit.assert_not_called()


def test_get_audit_logs_applies_pagination():
    db = MagicMock()
    query = db.query.return_value

    query.order_by.return_value = query
    query.offset.return_value = query
    query.limit.return_value = query

    expected_logs = [MagicMock(), MagicMock()]
    query.all.return_value = expected_logs

    result = get_audit_logs(
        db,
        skip=20,
        limit=50,
    )

    db.query.assert_called_once_with(AuditLog)
    query.offset.assert_called_once_with(20)
    query.limit.assert_called_once_with(50)
    query.all.assert_called_once_with()

    assert result == expected_logs


def test_get_audit_logs_uses_default_pagination():
    db = MagicMock()
    query = db.query.return_value

    query.order_by.return_value = query
    query.offset.return_value = query
    query.limit.return_value = query

    query.all.return_value = []

    result = get_audit_logs(db)

    query.offset.assert_called_once_with(0)
    query.limit.assert_called_once_with(100)

    assert result == []

