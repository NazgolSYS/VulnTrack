from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.comment import (
    CommentCreate,
    CommentResponse,
    CommentUpdate,
)
from app.services import comment_service
from app.models import User
from app.core.dependencies import get_current_user, require_security_analyst


router = APIRouter(
    prefix="/comments",
    tags=["Comments"],
)


@router.post(
    "/",
    response_model=CommentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_comment(
    comment_data: CommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    return comment_service.create_comment(db, comment_data)


@router.get(
    "/",
    response_model=list[CommentResponse],
)
def read_all_comments(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return comment_service.get_all_comments(db, skip, limit)


@router.get(
    "/vulnerability/{vulnerability_id}",
    response_model=list[CommentResponse],
)
def read_comments_for_vulnerability(
    vulnerability_id: int,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return comment_service.get_comments_for_vulnerability(
        db,
        vulnerability_id,
        skip,
        limit,
    )


@router.get(
    "/remediation-task/{remediation_task_id}",
    response_model=list[CommentResponse],
)
def read_comments_for_remediation_task(
    remediation_task_id: int,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return comment_service.get_comments_for_remediation_task(
        db,
        remediation_task_id,
        skip,
        limit,
    )


@router.get(
    "/{comment_id}",
    response_model=CommentResponse,
)
def read_comment(
    comment_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return comment_service.get_comment(db, comment_id)


@router.patch(
    "/{comment_id}",
    response_model=CommentResponse,
)
def edit_comment(
    comment_id: int,
    comment_data: CommentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    return comment_service.update_comment(
        db,
        comment_id,
        comment_data,
    )
