
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app import models
from app.models import RiskAssessment
from app.schemas.risk_assessment import RiskAssessmentCreate
from app.services.risk_service import calculate_risk


def create_risk_assessment(
    db: Session,
    assessment_data: RiskAssessmentCreate,
    assessed_by: int,
) -> RiskAssessment:
    """Calculate and save a risk assessment."""

    # Confirm that the vulnerability exists.
    vulnerability = db.get(
        models.Vulnerability,
        assessment_data.vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    # Calculate the risk using the existing calculation service.
    result = calculate_risk(
        assessment_data.likelihood,
        assessment_data.impact,
    )

    assessment = RiskAssessment(
        vulnerability_id=assessment_data.vulnerability_id,
        assessed_by=assessed_by,
        likelihood=result["likelihood"],
        impact=result["impact"],
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


def get_risk_assessments_for_vulnerability(
    db: Session,
    vulnerability_id: int,
):
    """Return all assessments for an existing vulnerability."""

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
    """Return the latest assessment for an existing vulnerability."""

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
