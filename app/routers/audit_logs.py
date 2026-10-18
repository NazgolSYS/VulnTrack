from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, User
from app.schemas.audit_log import (
    AuditLogCreate,
    AuditLogResponse,
)
from app.services import audit_log_service


router = APIRouter(
    prefix="/audit-logs",
    tags=["Audit Logs"],
)


def validate_user(
    db: Session,
    user_id: int | None,
):
    if user_id is None:
        return

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found.",
        )


@router.post(
    "/",
    response_model=AuditLogResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_audit_log(
    audit_log_data: AuditLogCreate,
    db: Session = Depends(get_db),
):
    validate_user(
        db,
        audit_log_data.user_id,
    )

    try:
        return audit_log_service.create_audit_log(
            db,
            audit_log_data,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Audit log could not be created because of a database conflict.",
        )


@router.get(
    "/",
    response_model=list[AuditLogResponse],
)
def get_audit_logs(
    db: Session = Depends(get_db),
):
    return audit_log_service.get_audit_logs(db)


@router.get(
    "/{audit_log_id}",
    response_model=AuditLogResponse,
)
def get_audit_log(
    audit_log_id: int,
    db: Session = Depends(get_db),
):
    audit_log = audit_log_service.get_audit_log(
        db,
        audit_log_id,
    )

    if audit_log is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found.",
        )

    return audit_log


@router.delete(
    "/{audit_log_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_audit_log(
    audit_log_id: int,
    db: Session = Depends(get_db),
):
    audit_log = audit_log_service.get_audit_log(
        db,
        audit_log_id,
    )

    if audit_log is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found.",
        )

    try:
        audit_log_service.delete_audit_log(
            db,
            audit_log,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Audit log could not be deleted because of a database conflict.",
        )
    