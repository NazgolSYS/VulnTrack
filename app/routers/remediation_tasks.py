from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RemediationTask, User, Vulnerability
from app.schemas.remediation_task import (
    RemediationTaskCreate,
    RemediationTaskResponse,
    RemediationTaskUpdate,
)
from app.services import audit_log_service, remediation_task_service
from app.core.dependencies import get_current_user, require_security_analyst

router = APIRouter(
    prefix="/remediation-tasks",
    tags=["Remediation Tasks"],
)


def validate_references(
    db: Session,
    vulnerability_id: int,
    assigned_to: int | None,
):
    vulnerability = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == vulnerability_id)
        .first()
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    if assigned_to is not None:
        user = (
            db.query(User)
            .filter(User.id == assigned_to)
            .first()
        )

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with ID {assigned_to} not found.",
            )


@router.post(
    "/",
    response_model=RemediationTaskResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_remediation_task(
    task_data: RemediationTaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    validate_references(
        db,
        task_data.vulnerability_id,
        task_data.assigned_to,
    )

    try:
        task = remediation_task_service.create_remediation_task(
            db,
            task_data,
            commit=False,
        )

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action="created",
            entity_type="remediation_task",
            entity_id=task.id,
            details=f"Created remediation task: {task.title}",
        )

        db.commit()
        db.refresh(task)

        return task

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation task could not be created because of a database conflict.",
        )

    except Exception:
        db.rollback()
        raise


@router.get(
    "/",
    response_model=list[RemediationTaskResponse],
)
def get_remediation_tasks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return remediation_task_service.get_remediation_tasks(db)


@router.get(
    "/{task_id}",
    response_model=RemediationTaskResponse,
)
def get_remediation_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    task = remediation_task_service.get_remediation_task(
        db,
        task_id,
    )

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found.",
        )

    return task


@router.put(
    "/{task_id}",
    response_model=RemediationTaskResponse,
)
def update_remediation_task(
    task_id: int,
    task_data: RemediationTaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    task = remediation_task_service.get_remediation_task(
        db,
        task_id,
    )

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found.",
        )

    update_data = task_data.model_dump(
        exclude_unset=True
    )

    vulnerability_id = update_data.get(
        "vulnerability_id",
        task.vulnerability_id,
    )

    assigned_to = update_data.get(
        "assigned_to",
        task.assigned_to,
    )

    validate_references(
        db,
        vulnerability_id,
        assigned_to,
    )

    old_status = task.status

    try:
        updated_task = remediation_task_service.update_remediation_task(
            db,
            task,
            task_data,
            commit=False,
        )

        if (
            "status" in update_data
            and old_status != updated_task.status
        ):
            action = "status_changed"
            details = (
                f"Remediation task status changed "
                f"from {old_status} to {updated_task.status}"
            )
        else:
            action = "updated"
            details = (
                f"Updated remediation task: {updated_task.title}"
            )

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action=action,
            entity_type="remediation_task",
            entity_id=updated_task.id,
            details=details,
        )

        db.commit()
        db.refresh(updated_task)

        return updated_task

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation task could not be updated because of a database conflict.",
        )

    except Exception:
        db.rollback()
        raise


@router.delete(
    "/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_remediation_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    task = remediation_task_service.get_remediation_task(
        db,
        task_id,
    )

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found.",
        )

    # Capture the task details before deleting it.
    task_title = task.title
    task_id_value = task.id

    try:
        remediation_task_service.delete_remediation_task(
            db,
            task,
            commit=False,
        )

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action="deleted",
            entity_type="remediation_task",
            entity_id=task_id_value,
            details=f"Deleted remediation task: {task_title}",
        )

        db.commit()

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation task could not be deleted because of a database conflict.",
        )

    except Exception:
        db.rollback()
        raise
