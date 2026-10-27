
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.dependencies import (
    get_current_user,
    require_security_analyst,
)
from app.database import get_db
from app.models import User
from app.schemas.risk_assessment import (
    RiskAssessmentCreate,
    RiskAssessmentResponse,
)
from app.services import risk_assessment_service


router = APIRouter(
    prefix="/risk-assessments",
    tags=["Risk Assessments"],
)


@router.post(
    "/",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_assessment(
    assessment_data: RiskAssessmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    """Create a risk assessment for a vulnerability."""

    return risk_assessment_service.create_risk_assessment(
        db=db,
        assessment_data=assessment_data,
        assessed_by=current_user.id,
    )


@router.get(
    "/vulnerability/{vulnerability_id}/latest",
    response_model=RiskAssessmentResponse,
)
def get_latest_risk_assessment_for_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the latest assessment for a vulnerability."""

    return (
        risk_assessment_service
        .get_latest_risk_assessment_for_vulnerability(
            db,
            vulnerability_id,
        )
    )


@router.get(
    "/vulnerability/{vulnerability_id}",
    response_model=list[RiskAssessmentResponse],
)
def get_risk_assessments_for_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the assessment history for a vulnerability."""

    return (
        risk_assessment_service
        .get_risk_assessments_for_vulnerability(
            db,
            vulnerability_id,
        )
    )
