from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app import models
from app.schemas.comment import CommentCreate, CommentUpdate


def validate_comment_references(
    db: Session,
    user_id: int,
    vulnerability_id: int | None,
    remediation_task_id: int | None,
):
    if vulnerability_id is None and remediation_task_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "A comment must be associated with a vulnerability "
                "or a remediation task."
            ),
        )

    user = (
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if vulnerability_id is not None:
        vulnerability = (
            db.query(models.Vulnerability)
            .filter(models.Vulnerability.id == vulnerability_id)
            .first()
        )

        if vulnerability is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found.",
            )

    if remediation_task_id is not None:
        task = (
            db.query(models.RemediationTask)
            .filter(
                models.RemediationTask.id == remediation_task_id
            )
            .first()
        )

        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation task not found.",
            )


def create_comment(
    db: Session,
    comment_data: CommentCreate,
):
    validate_comment_references(
        db=db,
        user_id=comment_data.user_id,
        vulnerability_id=comment_data.vulnerability_id,
        remediation_task_id=comment_data.remediation_task_id,
    )

    comment = models.Comment(**comment_data.model_dump())

    try:
        db.add(comment)
        db.commit()
        db.refresh(comment)
    except Exception:
        db.rollback()
        raise

    return comment


def get_comment(db: Session, comment_id: int):
    comment = (
        db.query(models.Comment)
        .filter(models.Comment.id == comment_id)
        .first()
    )

    if comment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comment not found.",
        )

    return comment


def get_all_comments(
    db: Session,
    skip: int = 0,
    limit: int = 100,
):
    return (
        db.query(models.Comment)
        .order_by(models.Comment.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_comments_for_vulnerability(
    db: Session,
    vulnerability_id: int,
    skip: int = 0,
    limit: int = 100,
):
    vulnerability = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.id == vulnerability_id)
        .first()
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    return (
        db.query(models.Comment)
        .filter(models.Comment.vulnerability_id == vulnerability_id)
        .order_by(models.Comment.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_comments_for_remediation_task(
    db: Session,
    remediation_task_id: int,
    skip: int = 0,
    limit: int = 100,
):
    task = (
        db.query(models.RemediationTask)
        .filter(
            models.RemediationTask.id == remediation_task_id
        )
        .first()
    )

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation task not found.",
        )

    return (
        db.query(models.Comment)
        .filter(
            models.Comment.remediation_task_id == remediation_task_id
        )
        .order_by(models.Comment.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_comment(
    db: Session,
    comment_id: int,
    comment_data: CommentUpdate,
):
    comment = get_comment(db, comment_id)

    comment.content = comment_data.content

    try:
        db.commit()
        db.refresh(comment)
    except Exception:
        db.rollback()
        raise

    return comment
