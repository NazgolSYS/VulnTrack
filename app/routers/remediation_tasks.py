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
from app.services import remediation_task_service


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
):
    validate_references(
        db,
        task_data.vulnerability_id,
        task_data.assigned_to,
    )

    try:
        return remediation_task_service.create_remediation_task(
            db,
            task_data,
        )
    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation task could not be created because of a database conflict.",
        )


@router.get(
    "/",
    response_model=list[RemediationTaskResponse],
)
def get_remediation_tasks(
    db: Session = Depends(get_db),
):
    return remediation_task_service.get_remediation_tasks(db)


@router.get(
    "/{task_id}",
    response_model=RemediationTaskResponse,
)
def get_remediation_task(
    task_id: int,
    db: Session = Depends(get_db),
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

    try:
        return remediation_task_service.update_remediation_task(
            db,
            task,
            task_data,
        )
    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation task could not be updated because of a database conflict.",
        )


@router.delete(
    "/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_remediation_task(
    task_id: int,
    db: Session = Depends(get_db),
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

    try:
        remediation_task_service.delete_remediation_task(
            db,
            task,
        )
    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation task could not be deleted because of a database conflict.",
        )
    