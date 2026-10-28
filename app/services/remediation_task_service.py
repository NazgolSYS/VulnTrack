from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import RemediationTask
from app.schemas.remediation_task import (
    RemediationTaskCreate,
    RemediationTaskUpdate,
)


ALLOWED_STATUS_TRANSITIONS = {
    "pending": {"in_progress"},
    "in_progress": {"pending", "completed"},
    "completed": {"in_progress"},
}


def create_remediation_task(
    db: Session,
    task_data: RemediationTaskCreate,
    commit: bool = True,
):
    task = RemediationTask(
        **task_data.model_dump()
    )

    db.add(task)

    if commit:
        db.commit()
        db.refresh(task)
    else:
        db.flush()

    return task


def get_remediation_tasks(db: Session):
    return (
        db.query(RemediationTask)
        .order_by(RemediationTask.id)
        .all()
    )


def get_remediation_task(
    db: Session,
    task_id: int,
):
    return (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .first()
    )


def update_remediation_task(
    db: Session,
    task: RemediationTask,
    task_data: RemediationTaskUpdate,
    commit: bool = True,
):
    update_data = task_data.model_dump(
        exclude_unset=True
    )

    if "status" in update_data:
        old_status = (task.status or "").strip().lower()
        new_status = update_data["status"].strip().lower()

        if not new_status:
            raise HTTPException(
                status_code=422,
                detail="The remediation task status cannot be empty.",
            )

        if new_status not in ALLOWED_STATUS_TRANSITIONS:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Invalid remediation task status. "
                    "Allowed statuses are: "
                    "pending, in_progress, completed."
                ),
            )

        if old_status == new_status:
            raise HTTPException(
                status_code=409,
                detail="The remediation task already has this status.",
            )

        allowed_next_statuses = ALLOWED_STATUS_TRANSITIONS.get(
            old_status,
            set(),
        )

        if new_status not in allowed_next_statuses:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Invalid remediation task status transition "
                    f"from '{old_status}' to '{new_status}'."
                ),
            )

        update_data["status"] = new_status

    try:
        for field, value in update_data.items():
            setattr(task, field, value)

        if commit:
            db.commit()
            db.refresh(task)
        else:
            db.flush()

        return task

    except Exception:
        db.rollback()
        raise


def delete_remediation_task(
    db: Session,
    task: RemediationTask,
    commit: bool = True,
):
    db.delete(task)

    if commit:
        db.commit()
    else:
        db.flush()
