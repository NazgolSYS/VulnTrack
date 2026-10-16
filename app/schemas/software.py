from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SoftwareBase(BaseModel):
    name: str
    version: str
    vendor: str | None = None
    cpe: str | None = None


class SoftwareCreate(SoftwareBase):
    pass


class SoftwareUpdate(BaseModel):
    name: str | None = None
    version: str | None = None
    vendor: str | None = None
    cpe: str | None = None


class SoftwareResponse(SoftwareBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
    