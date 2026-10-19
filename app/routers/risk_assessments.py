from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Vulnerability
from app.schemas.risk_assessment import (
    RiskAssessmentCreate,
    RiskAssessmentResponse,
)
from app.services.risk_assessment_service import (
    create_risk_assessment,
)

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
):
    # Confirm that the vulnerability exists.
    vulnerability = db.get(
        Vulnerability,
        assessment_data.vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found",
        )

    # Confirm that the assessing user exists.
    user = db.get(User, assessment_data.assessed_by)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Calculate the risk and persist the assessment.
    return create_risk_assessment(
        db=db,
        assessment_data=assessment_data,
    )


@router.get(
    "/vulnerability/{vulnerability_id}/latest",
    response_model=RiskAssessmentResponse,
)
def get_latest_risk_assessment_for_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    return risk_assessment_service.get_latest_risk_assessment_for_vulnerability(
        db,
        vulnerability_id,
    )


@router.get(
    "/vulnerability/{vulnerability_id}",
    response_model=list[RiskAssessmentResponse],
)
def get_risk_assessments_for_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    return risk_assessment_service.get_risk_assessments_for_vulnerability(
        db,
        vulnerability_id,
    )


