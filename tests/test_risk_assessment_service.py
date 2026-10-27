
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.schemas.risk_assessment import RiskAssessmentCreate
from app.services.risk_assessment_service import (
    create_risk_assessment,
    get_latest_risk_assessment_for_vulnerability,
    get_risk_assessments_for_vulnerability,
)


def test_create_risk_assessment_persists_calculated_result():
    db = MagicMock()
    vulnerability = MagicMock()
    db.get.return_value = vulnerability

    assessment_data = RiskAssessmentCreate(
        vulnerability_id=10,
        likelihood=4,
        impact=3,
        justification="Test justification",
        mitigation_recommendation="Apply security patches",
    )

    result = create_risk_assessment(
        db,
        assessment_data,
        assessed_by=1,
    )

    db.add.assert_called_once()
    db.commit.assert_called_once()

    saved_assessment = db.add.call_args.args[0]

    db.refresh.assert_called_once_with(saved_assessment)

    assert result is saved_assessment
    assert saved_assessment.vulnerability_id == 10
    assert saved_assessment.assessed_by == 1
    assert saved_assessment.likelihood == 4
    assert saved_assessment.impact == 3
    assert saved_assessment.risk_score == 12
    assert saved_assessment.risk_level == "high"
    assert saved_assessment.justification == "Test justification"
    assert (
        saved_assessment.mitigation_recommendation
        == "Apply security patches"
    )


def test_create_risk_assessment_rolls_back_on_commit_failure():
    db = MagicMock()
    db.get.return_value = MagicMock()
    db.commit.side_effect = RuntimeError("Database commit failed")

    assessment_data = RiskAssessmentCreate(
        vulnerability_id=10,
        likelihood=2,
        impact=2,
    )

    with pytest.raises(
        RuntimeError,
        match="Database commit failed",
    ):
        create_risk_assessment(
            db,
            assessment_data,
            assessed_by=1,
        )

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.rollback.assert_called_once()
    db.refresh.assert_not_called()


def test_create_risk_assessment_rejects_missing_vulnerability():
    db = MagicMock()
    db.get.return_value = None

    assessment_data = RiskAssessmentCreate(
        vulnerability_id=999999,
        likelihood=3,
        impact=4,
    )

    with pytest.raises(HTTPException) as exc_info:
        create_risk_assessment(
            db,
            assessment_data,
            assessed_by=1,
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Vulnerability not found."
    db.add.assert_not_called()
    db.commit.assert_not_called()


@pytest.mark.parametrize(
    "service_function",
    [
        get_risk_assessments_for_vulnerability,
        get_latest_risk_assessment_for_vulnerability,
    ],
)
def test_get_assessments_raises_404_for_missing_vulnerability(
    service_function,
):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    with pytest.raises(HTTPException) as exc_info:
        service_function(db, vulnerability_id=999999)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Vulnerability not found."


def test_get_latest_assessment_raises_404_when_none_exists():
    db = MagicMock()

    vulnerability = MagicMock()
    vulnerability_query = MagicMock()
    vulnerability_query.filter.return_value.first.return_value = (
        vulnerability
    )

    assessment_query = MagicMock()
    (
        assessment_query
        .filter.return_value
        .order_by.return_value
        .first.return_value
    ) = None

    db.query.side_effect = [
        vulnerability_query,
        assessment_query,
    ]

    with pytest.raises(HTTPException) as exc_info:
        get_latest_risk_assessment_for_vulnerability(
            db,
            vulnerability_id=10,
        )

    assert exc_info.value.status_code == 404
    assert (
        exc_info.value.detail
        == "No risk assessment found for this vulnerability."
    )
