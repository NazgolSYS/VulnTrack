from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, AssetSoftware, Software, User
from app.schemas.asset_software import (
    AssetSoftwareCreate,
    AssetSoftwareResponse,
    AssetSoftwareUpdate,
)
from app.services import asset_software_service
from app.core.dependencies import get_current_user, require_security_analyst


router = APIRouter(
    prefix="/asset-software",
    tags=["Asset Software"],
)


def validate_references(
    db: Session,
    asset_id: int,
    software_id: int,
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id)
        .first()
    )

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found.",
        )

    software = (
        db.query(Software)
        .filter(Software.id == software_id)
        .first()
    )

    if software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Software not found.",
        )


@router.post(
    "/",
    response_model=AssetSoftwareResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_asset_software(
    asset_software_data: AssetSoftwareCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    validate_references(
        db,
        asset_software_data.asset_id,
        asset_software_data.software_id,
    )

    existing_link = (
        db.query(AssetSoftware)
        .filter(
            AssetSoftware.asset_id
            == asset_software_data.asset_id,
            AssetSoftware.software_id
            == asset_software_data.software_id,
        )
        .first()
    )

    if existing_link:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This software is already linked to this asset.",
        )

    try:
        return asset_software_service.create_asset_software(
            db,
            asset_software_data,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset-software relationship could not be created because of a database conflict.",
        )


@router.get(
    "/",
    response_model=list[AssetSoftwareResponse],
)
def get_asset_software_list(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return asset_software_service.get_asset_software_list(db)


@router.get(
    "/{asset_software_id}",
    response_model=AssetSoftwareResponse,
)
def get_asset_software(
    asset_software_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    asset_software = (
        asset_software_service.get_asset_software(
            db,
            asset_software_id,
        )
    )

    if asset_software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset-software relationship not found.",
        )

    return asset_software


@router.put(
    "/{asset_software_id}",
    response_model=AssetSoftwareResponse,
)
def update_asset_software(
    asset_software_id: int,
    asset_software_data: AssetSoftwareUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    asset_software = (
        asset_software_service.get_asset_software(
            db,
            asset_software_id,
        )
    )

    if asset_software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset-software relationship not found.",
        )

    update_data = asset_software_data.model_dump(
        exclude_unset=True
    )

    asset_id = update_data.get(
        "asset_id",
        asset_software.asset_id,
    )

    software_id = update_data.get(
        "software_id",
        asset_software.software_id,
    )

    validate_references(
        db,
        asset_id,
        software_id,
    )

    duplicate = (
        db.query(AssetSoftware)
        .filter(
            AssetSoftware.asset_id == asset_id,
            AssetSoftware.software_id == software_id,
            AssetSoftware.id != asset_software_id,
        )
        .first()
    )

    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This software is already linked to this asset.",
        )

    try:
        return asset_software_service.update_asset_software(
            db,
            asset_software,
            asset_software_data,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset-software relationship could not be updated because of a database conflict.",
        )


@router.delete(
    "/{asset_software_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_asset_software(
    asset_software_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    asset_software = (
        asset_software_service.get_asset_software(
            db,
            asset_software_id,
        )
    )

    if asset_software is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset-software relationship not found.",
        )

    try:
        asset_software_service.delete_asset_software(
            db,
            asset_software,
        )

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Asset-software relationship could not be deleted because of a database conflict.",
        )
    