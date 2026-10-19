from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FindingCreate(BaseModel):
    scan_id: int = Field(gt=0)
    asset_id: int = Field(gt=0)
    vulnerability_id: int | None = Field(default=None, gt=0)

    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: str = Field(min_length=1, max_length=50)
    status: str = Field(default="open", min_length=1, max_length=50)
    evidence: str | None = None


class FindingUpdate(BaseModel):
    scan_id: int | None = Field(default=None, gt=0)
    asset_id: int | None = Field(default=None, gt=0)
    vulnerability_id: int | None = Field(default=None, gt=0)

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    severity: str | None = Field(default=None, min_length=1, max_length=50)
    status: str | None = Field(default=None, min_length=1, max_length=50)
    evidence: str | None = None


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    asset_id: int
    vulnerability_id: int | None
    title: str
    description: str | None
    severity: str
    status: str
    evidence: str | None
    first_detected_at: datetime
    last_detected_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
    