from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan, User
from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanUpdate,
)
from app.services import scan_service
from app.core.dependencies import get_current_user, require_security_analyst


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


def validate_started_by(
    db: Session,
    started_by: int | None,
):
    if started_by is None:
        return

    user = (
        db.query(User)
        .filter(User.id == started_by)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {started_by} not found.",
        )


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    validate_started_by(
        db,
        scan_data.started_by,
    )

    try:
        return scan_service.create_scan(
            db,
            scan_data,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan could not be created because of a database conflict.",
        )


@router.get(
    "/",
    response_model=list[ScanResponse],
)
def get_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return scan_service.get_scans(db)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = scan_service.get_scan(
        db,
        scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return scan


@router.put(
    "/{scan_id}",
    response_model=ScanResponse,
)
def update_scan(
    scan_id: int,
    scan_data: ScanUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    scan = scan_service.get_scan(
        db,
        scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    update_data = scan_data.model_dump(
        exclude_unset=True
    )

    started_by = update_data.get(
        "started_by",
        scan.started_by,
    )

    validate_started_by(
        db,
        started_by,
    )

    try:
        return scan_service.update_scan(
            db,
            scan,
            scan_data,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan could not be updated because of a database conflict.",
        )


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    scan = scan_service.get_scan(
        db,
        scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    try:
        scan_service.delete_scan(
            db,
            scan,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan could not be deleted because of a database conflict.",
        )
    