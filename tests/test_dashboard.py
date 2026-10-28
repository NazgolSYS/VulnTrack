
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.dependencies import get_current_user


def test_dashboard_summary_route_is_registered():
    """The dashboard summary GET endpoint is registered."""

    response = app.openapi()

    assert "/dashboard/summary" in response["paths"]
    assert "get" in response["paths"]["/dashboard/summary"]
    

def test_dashboard_summary_returns_expected_counts():
    """The dashboard returns the expected vulnerability and risk counts."""

    mock_db = MagicMock()

    test_user = SimpleNamespace(
        id=1,
        username="dashboard_test_user",
        is_active=True,
        role=SimpleNamespace(name="Security Analyst"),
    )

    # Expected results in the order the dashboard endpoint queries them:
    # Total vulnerabilities.
    # Severity counts: critical, high, medium, low.
    # Status counts: open, in_progress, resolved.
    # Total risk assessments.
    # Risk-level counts: critical, high, medium, low.
    # Number of assessed vulnerabilities.
    count_results = iter([
        10,
        1, 3, 4, 2,
        5, 3, 2,
        7,
        1, 2, 3, 1,
        6,
    ])

    def make_count_query():
        """Create a mock query supporting filter() and count()."""

        query = MagicMock()
        query.filter.return_value = query
        query.count.side_effect = lambda: next(count_results)
        return query

    # The endpoint makes 13 count queries before the distinct-ID
    # subquery, followed by one count query for assessed vulnerabilities.
    mock_db.query.side_effect = (
        [make_count_query() for _ in range(13)]
        + [
            MagicMock(),  # Distinct assessed vulnerability IDs subquery.
            make_count_query(),  # Count assessed vulnerabilities.
        ]
    )

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: test_user

    try:
        with TestClient(app) as client:
            response = client.get("/dashboard/summary")

        assert response.status_code == 200, response.text

        data = response.json()

        assert data["total_vulnerabilities"] == 10

        assert data["severity_counts"] == {
            "critical": 1,
            "high": 3,
            "medium": 4,
            "low": 2,
        }

        assert data["status_counts"] == {
            "open": 5,
            "in_progress": 3,
            "resolved": 2,
        }

        assert data["total_risk_assessments"] == 7

        assert data["risk_level_counts"] == {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 1,
        }

        assert data["assessed_vulnerabilities"] == 6
        assert data["unassessed_vulnerabilities"] == 4

    finally:
        app.dependency_overrides.clear()


def test_dashboard_summary_requires_authentication():
    """Unauthenticated requests to the dashboard return 401."""

    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db

    try:
        with TestClient(app) as client:
            response = client.get("/dashboard/summary")

        assert response.status_code == 401
        assert response.headers.get("www-authenticate") == "Bearer"

        # Authentication should reject the request before querying data.
        mock_db.query.assert_not_called()

    finally:
        app.dependency_overrides.clear()
