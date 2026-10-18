from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetSoftwareBase(BaseModel):
    asset_id: int
    software_id: int
    installed_at: datetime | None = None
    last_seen_at: datetime | None = None


class AssetSoftwareCreate(AssetSoftwareBase):
    pass


class AssetSoftwareUpdate(BaseModel):
    asset_id: int | None = None
    software_id: int | None = None
    installed_at: datetime | None = None
    last_seen_at: datetime | None = None


class AssetSoftwareResponse(AssetSoftwareBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
    