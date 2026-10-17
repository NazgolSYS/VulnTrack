from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RemediationTaskBase(BaseModel):
    vulnerability_id: int
    title: str
    description: str | None = None
    status: str = "pending"
    priority: str = "medium"
    assigned_to: int | None = None
    due_date: datetime | None = None


class RemediationTaskCreate(RemediationTaskBase):
    pass


class RemediationTaskUpdate(BaseModel):
    vulnerability_id: int | None = None
    title: str | None = None
    description: str | None = None
    status: str | None = None
    priority: str | None = None
    assigned_to: int | None = None
    due_date: datetime | None = None


class RemediationTaskResponse(RemediationTaskBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
    