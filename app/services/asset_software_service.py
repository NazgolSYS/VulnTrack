from sqlalchemy.orm import Session

from app.models import AssetSoftware
from app.schemas.asset_software import (
    AssetSoftwareCreate,
    AssetSoftwareUpdate,
)


def create_asset_software(
    db: Session,
    asset_software_data: AssetSoftwareCreate,
):
    asset_software = AssetSoftware(
        **asset_software_data.model_dump()
    )

    db.add(asset_software)
    db.commit()
    db.refresh(asset_software)

    return asset_software


def get_asset_software_list(db: Session):
    return (
        db.query(AssetSoftware)
        .order_by(AssetSoftware.id)
        .all()
    )


def get_asset_software(
    db: Session,
    asset_software_id: int,
):
    return (
        db.query(AssetSoftware)
        .filter(
            AssetSoftware.id == asset_software_id
        )
        .first()
    )


def update_asset_software(
    db: Session,
    asset_software: AssetSoftware,
    asset_software_data: AssetSoftwareUpdate,
):
    update_data = asset_software_data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():
        setattr(asset_software, field, value)

    db.commit()
    db.refresh(asset_software)

    return asset_software


def delete_asset_software(
    db: Session,
    asset_software: AssetSoftware,
):
    db.delete(asset_software)
    db.commit()
    