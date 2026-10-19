from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CommentCreate(BaseModel):
    user_id: int = Field(gt=0)
    vulnerability_id: int | None = Field(default=None, gt=0)
    remediation_task_id: int | None = Field(default=None, gt=0)
    content: str = Field(min_length=1, max_length=5000)


class CommentUpdate(BaseModel):
    content: str = Field(min_length=1, max_length=5000)


class CommentResponse(BaseModel):
    id: int
    user_id: int
    vulnerability_id: int | None
    remediation_task_id: int | None
    content: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
