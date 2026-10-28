from sqlalchemy.orm import Session

from app.models import AuditLog
from app.schemas.audit_log import AuditLogCreate


def create_audit_log(
    db: Session,
    audit_log_data: AuditLogCreate,
):
    audit_log = AuditLog(
        **audit_log_data.model_dump()
    )

    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return audit_log


def get_audit_logs(db: Session):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .all()
    )


def get_audit_log(
    db: Session,
    audit_log_id: int,
):
    return (
        db.query(AuditLog)
        .filter(
            AuditLog.id == audit_log_id
        )
        .first()
    )


def delete_audit_log(
    db: Session,
    audit_log: AuditLog,
):
    db.delete(audit_log)
    db.commit()


def record_audit_event(
    db: Session,
    *,
    user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None = None,
    details: str | None = None,
    ip_address: str | None = None,
):
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        ip_address=ip_address,
    )

    db.add(audit_log)
    db.flush()

    return audit_log

 