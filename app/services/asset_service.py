
from sqlalchemy.orm import Session

from app.models import Asset
from app.schemas.asset import AssetCreate, AssetUpdate


def create_asset(db: Session, asset_data: AssetCreate):
    asset = Asset(**asset_data.model_dump())

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


def get_assets(db: Session):
    return db.query(Asset).order_by(Asset.id).all()


def get_asset(db: Session, asset_id: int):
    return db.query(Asset).filter(Asset.id == asset_id).first()


def update_asset(
    db: Session,
    asset: Asset,
    asset_data: AssetUpdate,
):
    update_data = asset_data.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)

    return asset


def delete_asset(db: Session, asset: Asset):
    db.delete(asset)
    db.commit()
