from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app import models
from app.models import RiskAssessment
from app.schemas.risk_assessment import RiskAssessmentCreate
from app.services.risk_service import calculate_risk


def create_risk_assessment(
    db: Session,
    assessment_data: RiskAssessmentCreate,
) -> RiskAssessment:
    # Reuse the existing risk calculation function.
    result = calculate_risk(
        assessment_data.likelihood,
        assessment_data.impact,
    )

    # Create a database record using the calculated results.
    assessment = RiskAssessment(
        vulnerability_id=assessment_data.vulnerability_id,
        assessed_by=assessment_data.assessed_by,
        likelihood=assessment_data.likelihood,
        impact=assessment_data.impact,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        justification=assessment_data.justification,
        mitigation_recommendation=(
            assessment_data.mitigation_recommendation
        ),
    )

    try:
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        return assessment

    except Exception:
        db.rollback()
        raise


from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app import models


def get_risk_assessments_for_vulnerability(
    db: Session,
    vulnerability_id: int,
):
    vulnerability = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.id == vulnerability_id)
        .first()
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    return (
        db.query(models.RiskAssessment)
        .filter(
            models.RiskAssessment.vulnerability_id
            == vulnerability_id
        )
        .order_by(
            models.RiskAssessment.assessed_at.desc()
        )
        .all()
    )


def get_latest_risk_assessment_for_vulnerability(
    db: Session,
    vulnerability_id: int,
):
    vulnerability = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.id == vulnerability_id)
        .first()
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    assessment = (
        db.query(models.RiskAssessment)
        .filter(
            models.RiskAssessment.vulnerability_id
            == vulnerability_id
        )
        .order_by(
            models.RiskAssessment.assessed_at.desc()
        )
        .first()
    )

    if assessment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No risk assessment found for this vulnerability.",
        )

    return assessment
