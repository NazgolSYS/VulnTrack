
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, User, Vulnerability
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from app.services import vulnerability_service
from app.schemas.vulnerability_status import (
    VulnerabilityStatusChange
)

from app.schemas.vulnerability_priority import (
    PrioritizedVulnerabilityResponse,
)
from app.services import vulnerability_priority_service

router = APIRouter(
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"],
)


def validate_references(
    db: Session,
    asset_id: int,
    assigned_to: int | None,
    created_by: int | None = None,
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found.",
        )

    for user_id in (assigned_to, created_by):
        if user_id is not None:
            user = db.query(User).filter(
                User.id == user_id
            ).first()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"User with ID {user_id} not found.",
                )


@router.post(
    "/",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_vulnerability(
    vulnerability_data: VulnerabilityCreate,
    db: Session = Depends(get_db),
):
    validate_references(
        db,
        vulnerability_data.asset_id,
        vulnerability_data.assigned_to,
        vulnerability_data.created_by,
    )

    try:
        return vulnerability_service.create_vulnerability(
            db,
            vulnerability_data,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vulnerability could not be created because of a database conflict.",
        )


@router.get(
    "/",
    response_model=list[VulnerabilityResponse],
)
def get_vulnerabilities(
    db: Session = Depends(get_db),
):
    return vulnerability_service.get_vulnerabilities(db)


@router.get(
    "/prioritized",
    response_model=list[PrioritizedVulnerabilityResponse],
)
def get_prioritized_vulnerabilities(
    db: Session = Depends(get_db),
):
    return (
        vulnerability_priority_service
        .get_prioritized_vulnerabilities(db)
    )


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    vulnerability = vulnerability_service.get_vulnerability(
        db,
        vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    return vulnerability


@router.put(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def update_vulnerability(
    vulnerability_id: int,
    vulnerability_data: VulnerabilityUpdate,
    db: Session = Depends(get_db),
):
    vulnerability = vulnerability_service.get_vulnerability(
        db,
        vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    update_data = vulnerability_data.model_dump(
        exclude_unset=True
    )

    asset_id = update_data.get(
        "asset_id",
        vulnerability.asset_id,
    )

    assigned_to = update_data.get(
        "assigned_to",
        vulnerability.assigned_to,
    )

    created_by = vulnerability.created_by

    validate_references(
        db,
        asset_id,
        assigned_to,
        created_by,
    )

    try:
        return vulnerability_service.update_vulnerability(
            db,
            vulnerability,
            vulnerability_data,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vulnerability could not be updated because of a database conflict.",
        )


@router.delete(
    "/{vulnerability_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    vulnerability = vulnerability_service.get_vulnerability(
        db,
        vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    try:
        vulnerability_service.delete_vulnerability(
            db,
            vulnerability,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Vulnerability cannot be deleted because other records "
                "reference it. Remove or reassign those records first."
            ),
        )


@router.patch(
    "/{vulnerability_id}/status",
    tags=["Vulnerabilities"],
)
def change_vulnerability_status(
    vulnerability_id: int,
    change_data: VulnerabilityStatusChange,
    db: Session = Depends(get_db),
):
    return vulnerability_service.change_vulnerability_status(
        db,
        vulnerability_id,
        change_data,
    )
