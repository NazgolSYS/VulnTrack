from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanBase(BaseModel):
    name: str
    scan_type: str
    status: str = "pending"
    started_by: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: str | None = None


class ScanCreate(ScanBase):
    pass


class ScanUpdate(BaseModel):
    name: str | None = None
    scan_type: str | None = None
    status: str | None = None
    started_by: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: str | None = None


class ScanResponse(ScanBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
    