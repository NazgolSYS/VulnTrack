from sqlalchemy.orm import Session

from app.models import RemediationTask
from app.schemas.remediation_task import (
    RemediationTaskCreate,
    RemediationTaskUpdate,
)


def create_remediation_task(
    db: Session,
    task_data: RemediationTaskCreate,
):
    task = RemediationTask(
        **task_data.model_dump()
    )

    db.add(task)
    db.commit()
    db.refresh(task)

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
):
    update_data = task_data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():
        setattr(task, field, value)

    db.commit()
    db.refresh(task)

    return task


def delete_remediation_task(
    db: Session,
    task: RemediationTask,
):
    db.delete(task)
    db.commit()
    