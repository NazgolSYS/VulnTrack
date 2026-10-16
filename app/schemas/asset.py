
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetBase(BaseModel):
    name: str
    asset_type: str
    hostname: str | None = None
    ip_address: str | None = None
    environment: str | None = None
    owner_id: int | None = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: str | None = None
    asset_type: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    environment: str | None = None
    owner_id: int | None = None


class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
