
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.dependencies import get_current_user
from app.models import RiskAssessment, User, Vulnerability


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_vulnerabilities = db.query(Vulnerability).count()

    severity_counts = {
        severity: (
            db.query(Vulnerability)
            .filter(Vulnerability.severity.ilike(severity))
            .count()
        )
        for severity in ("critical", "high", "medium", "low")
    }

    status_counts = {
        status: (
            db.query(Vulnerability)
            .filter(Vulnerability.status.ilike(status))
            .count()
        )
        for status in ("open", "in_progress", "resolved")
    }

    total_assessments = db.query(RiskAssessment).count()

    risk_level_counts = {
        level: (
            db.query(RiskAssessment)
            .filter(RiskAssessment.risk_level.ilike(level))
            .count()
        )
        for level in ("critical", "high", "medium", "low")
    }

    assessed_vulnerability_ids = (
        db.query(RiskAssessment.vulnerability_id)
        .distinct()
        .subquery()
    )

    assessed_vulnerabilities = (
        db.query(Vulnerability)
        .filter(Vulnerability.id.in_(assessed_vulnerability_ids))
        .count()
    )

    return {
        "total_vulnerabilities": total_vulnerabilities,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "total_risk_assessments": total_assessments,
        "risk_level_counts": risk_level_counts,
        "assessed_vulnerabilities": assessed_vulnerabilities,
        "unassessed_vulnerabilities": (
            total_vulnerabilities - assessed_vulnerabilities
        ),
    }
