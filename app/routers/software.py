from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Software, User
from app.schemas.software import (
    SoftwareCreate,
    SoftwareResponse,
    SoftwareUpdate,
)
from app.services import software_service
from app.core.dependencies import get_current_user, require_security_analyst


router = APIRouter(
    prefix="/software",
    tags=["Software"],
)


@router.post(
    "/",
    response_model=SoftwareResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_software(
    software_data: SoftwareCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    existing_software = (
        db.query(Software)
        .filter(
            Software.name == software_data.name,
            Software.version == software_data.version,
            Software.vendor == software_data.vendor,
        )
        .first()
    )

    if existing_software:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Software with the same name, version, and vendor already exists.",
        )

    try:
        return software_service.create_software(
            db,
            software_data,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Software could not be created because of a database conflict.",
        )


@router.get(
    "/",
    response_model=list[SoftwareResponse],
)
def get_software_list(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return software_service.get_software_list(db)


@router.get(
    "/{software_id}",
    response_model=SoftwareResponse,
)
def get_software(
    software_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    software = software_service.get_software(
        db,
        software_id,
    )

    if software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Software not found.",
        )

    return software


@router.put(
    "/{software_id}",
    response_model=SoftwareResponse,
)
def update_software(
    software_id: int,
    software_data: SoftwareUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    software = software_service.get_software(
        db,
        software_id,
    )

    if software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Software not found.",
        )

    update_data = software_data.model_dump(
        exclude_unset=True
    )

    name = update_data.get(
        "name",
        software.name,
    )

    version = update_data.get(
        "version",
        software.version,
    )

    vendor = update_data.get(
        "vendor",
        software.vendor,
    )

    duplicate = (
        db.query(Software)
        .filter(
            Software.name == name,
            Software.version == version,
            Software.vendor == vendor,
            Software.id != software_id,
        )
        .first()
    )

    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Software with the same name, version, and vendor already exists.",
        )

    try:
        return software_service.update_software(
            db,
            software,
            software_data,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Software could not be updated because of a database conflict.",
        )


@router.delete(
    "/{software_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_software(
    software_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    software = software_service.get_software(
        db,
        software_id,
    )

    if software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Software not found.",
        )

    try:
        software_service.delete_software(
            db,
            software,
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Software cannot be deleted because other records reference it.",
        )

    