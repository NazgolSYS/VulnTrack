import pytest
from pydantic import ValidationError

from app.schemas.audit_log import AuditLogCreate


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", ""),
        ("action", "A" * 101),
        ("entity_type", ""),
        ("entity_type", "E" * 101),
        ("ip_address", "1" * 46),
    ],
)
def test_audit_log_create_rejects_invalid_field_lengths(
    field,
    value,
):
    data = {
        "action": "created",
        "entity_type": "vulnerability",
        field: value,
    }

    with pytest.raises(ValidationError):
        AuditLogCreate(**data)


def test_audit_log_create_accepts_valid_data():
    audit_log = AuditLogCreate(
        user_id=1,
        action="created",
        entity_type="vulnerability",
        entity_id=42,
        details="Created a test vulnerability.",
        ip_address="192.168.1.10",
    )

    assert audit_log.action == "created"
    assert audit_log.entity_type == "vulnerability"
    assert audit_log.ip_address == "192.168.1.10"


def test_audit_log_create_accepts_optional_fields_as_none():
    audit_log = AuditLogCreate(
        action="system_event",
        entity_type="scan",
    )

    assert audit_log.user_id is None
    assert audit_log.entity_id is None
    assert audit_log.details is None
    assert audit_log.ip_address is None

