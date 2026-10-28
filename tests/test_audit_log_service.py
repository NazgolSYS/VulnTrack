from unittest.mock import MagicMock

from app.services.audit_log_service import record_audit_event


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

