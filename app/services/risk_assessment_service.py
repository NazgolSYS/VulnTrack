from sqlalchemy.orm import Session

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
