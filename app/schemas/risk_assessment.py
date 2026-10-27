
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskAssessmentCreate(BaseModel):
    vulnerability_id: int = Field(gt=0)

    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)

    justification: str | None = None
    mitigation_recommendation: str | None = None


class RiskAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    vulnerability_id: int
    assessed_by: int
    likelihood: int
    impact: int
    risk_score: float
    risk_level: str
    justification: str | None
    mitigation_recommendation: str | None
    assessed_at: datetime
    created_at: datetime
