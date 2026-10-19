
import pytest

from app.services.risk_service import calculate_risk


def test_calculate_low_risk():
    result = calculate_risk(likelihood=2, impact=2)

    assert result == {
        "likelihood": 2,
        "impact": 2,
        "risk_score": 4,
        "risk_level": "low",
    }


def test_calculate_medium_risk():
    result = calculate_risk(likelihood=3, impact=3)

    assert result["risk_score"] == 9
    assert result["risk_level"] == "medium"


def test_calculate_high_risk():
    result = calculate_risk(likelihood=3, impact=5)

    assert result["risk_score"] == 15
    assert result["risk_level"] == "high"


def test_calculate_critical_risk():
    result = calculate_risk(likelihood=5, impact=5)

    assert result["risk_score"] == 25
    assert result["risk_level"] == "critical"


@pytest.mark.parametrize(
    "likelihood, impact",
    [
        (0, 3),
        (6, 3),
        (-1, 2),
    ],
)
def test_invalid_likelihood_raises_error(likelihood, impact):
    with pytest.raises(
        ValueError,
        match="Likelihood must be between 1 and 5.",
    ):
        calculate_risk(likelihood, impact)


@pytest.mark.parametrize(
    "likelihood, impact",
    [
        (3, 0),
        (3, 6),
        (2, -1),
    ],
)
def test_invalid_impact_raises_error(likelihood, impact):
    with pytest.raises(
        ValueError,
        match="Impact must be between 1 and 5.",
    ):
        calculate_risk(likelihood, impact)
