
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.roles import ADMINISTRATOR, SECURITY_ANALYST, VIEWER
from app.core.dependencies import get_current_user
from app.services import (
    asset_service, 
    user_service,
    vulnerability_service,
    finding_service,
    remediation_task_service,
    risk_assessment_service,
)


@pytest.fixture
def client(monkeypatch):
    """Create a test client without accessing the real database."""

    mock_db = MagicMock()

    app.dependency_overrides[get_db] = lambda: mock_db

    # Keep the application dependencies isolated between tests.
    yield TestClient(app)

    app.dependency_overrides.clear()


# Add user and assets RBAC tests
def set_test_user(role_name):
    """Override authentication with a user having the requested role."""

    test_user = SimpleNamespace(
        id=1,
        username="rbac_test_user",
        is_active=True,
        role=SimpleNamespace(name=role_name),
    )

    app.dependency_overrides[get_current_user] = lambda: test_user


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_assets(client, monkeypatch, role_name):
    """All three roles can access the asset listing."""

    set_test_user(role_name)
    monkeypatch.setattr(asset_service, "get_assets", lambda db: [])

    response = client.get("/assets/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_administrator_and_analyst_can_access_users(
    client, monkeypatch, role_name
):
    """Only Administrators can access the users listing."""

    set_test_user(role_name)
    monkeypatch.setattr(user_service, "get_users", lambda db: [])

    response = client.get("/users/")

    if role_name == ADMINISTRATOR:
        assert response.status_code == 200
        assert response.json() == []
    else:
        assert response.status_code == 403


def test_viewer_cannot_access_users(client, monkeypatch):
    """A Viewer must be denied access to the users listing."""

    set_test_user(VIEWER)
    monkeypatch.setattr(user_service, "get_users", lambda db: [])

    response = client.get("/users/")

    assert response.status_code == 403


def test_unauthenticated_user_cannot_read_assets(client):
    """Requests without a bearer token must be rejected."""

    response = client.get("/assets/")

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_viewer_cannot_delete_assets(client):
    """A Viewer cannot perform an asset-management operation."""

    set_test_user(VIEWER)

    response = client.delete("/assets/999999")

    assert response.status_code == 403


# Add vulnerability RBAC tests
@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_vulnerabilities(
    client,
    monkeypatch,
    role_name,
):
    """All three roles can read vulnerabilities."""

    set_test_user(role_name)

    monkeypatch.setattr(
        vulnerability_service,
        "get_vulnerabilities",
        lambda db: [],
    )

    response = client.get("/vulnerabilities/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_create_vulnerability(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can create vulnerabilities."""

    set_test_user(role_name)

    created_vulnerability = SimpleNamespace(
        id=1,
        asset_id=1,
        title="RBAC Test Vulnerability",
        description="RBAC automated test.",
        cve_id="CVE-2026-0001",
        severity="High",
        status="open",
        cvss_score=8.5,
        assigned_to=None,
        created_by=1,
        discovered_at=None,
        due_date=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        vulnerability_service,
        "create_vulnerability",
        lambda db, vulnerability_data: created_vulnerability,
    )

    monkeypatch.setattr(
        # validate_references is inside the router, so it is easier
        # to bypass its database lookup for this authorization test.
        "app.routers.vulnerabilities.validate_references",
        lambda db, asset_id, assigned_to, created_by=None: None,
    )

    response = client.post(
        "/vulnerabilities/",
        json={
            "asset_id": 1,
            "cve_id": "CVE-2026-0001",
            "title": "RBAC Test Vulnerability",
            "description": "RBAC automated test.",
            "severity": "High",
            "cvss_score": 8.5,
            "status": "open",
            "assigned_to": None,
            "created_by": 1,
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] == 1


def test_viewer_cannot_create_vulnerability(client):
    """A Viewer cannot create vulnerabilities."""

    set_test_user(VIEWER)

    response = client.post(
        "/vulnerabilities/",
        json={
            "asset_id": 1,
            "cve_id": "CVE-2026-0001",
            "title": "RBAC Test Vulnerability",
            "description": "RBAC automated test.",
            "severity": "High",
            "cvss_score": 8.5,
            "status": "Open",
            "assigned_to": None,
            "created_by": 1,
        },
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_update_vulnerability(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can update vulnerabilities."""

    set_test_user(role_name)

    existing_vulnerability = SimpleNamespace(
        id=1,
        asset_id=1,
        title="Original Vulnerability",
        description="Original description.",
        cve_id="CVE-2026-0001",
        severity="High",
        status="open",
        cvss_score=8.5,
        assigned_to=None,
        created_by=1,
        discovered_at=None,
        due_date=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    updated_vulnerability = SimpleNamespace(
        id=1,
        asset_id=1,
        title="Updated RBAC Test Vulnerability",
        description="Updated description.",
        cve_id="CVE-2026-0001",
        severity="High",
        status="open",
        cvss_score=8.5,
        assigned_to=None,
        created_by=1,
        discovered_at=None,
        due_date=None,
        created_at=existing_vulnerability.created_at,
        updated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        vulnerability_service,
        "get_vulnerability",
        lambda db, vulnerability_id: existing_vulnerability,
    )

    monkeypatch.setattr(
        vulnerability_service,
        "update_vulnerability",
        lambda db, vulnerability, vulnerability_data: updated_vulnerability,
    )

    monkeypatch.setattr(
        "app.routers.vulnerabilities.validate_references",
        lambda db, asset_id, assigned_to, created_by=None: None,
    )

    response = client.put(
        "/vulnerabilities/1",
        json={
            "title": "Updated RBAC Test Vulnerability",
        },
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["title"] == "Updated RBAC Test Vulnerability"


def test_viewer_cannot_update_vulnerability(client):
    """A Viewer cannot update vulnerabilities."""

    set_test_user(VIEWER)

    response = client.put(
        "/vulnerabilities/1",
        json={
            "title": "Unauthorized update",
        },
    )

    assert response.status_code == 403


def test_viewer_cannot_delete_vulnerability(client):
    """A Viewer cannot delete vulnerabilities."""

    set_test_user(VIEWER)

    response = client.delete("/vulnerabilities/1")

    assert response.status_code == 403


def test_viewer_cannot_change_vulnerability_status(client):
    """A Viewer cannot change vulnerability status."""

    set_test_user(VIEWER)

    response = client.patch(
        "/vulnerabilities/1/status",
        json={
            "status": "Resolved",
        },
    )

    assert response.status_code == 403


# Add findings RBAC tests
@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_findings(
    client,
    monkeypatch,
    role_name,
):
    """All three roles can read findings."""

    set_test_user(role_name)

    monkeypatch.setattr(
        finding_service,
        "get_all_findings",
        lambda db, skip, limit: [],
    )

    response = client.get("/findings/")

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_finding(client):
    """A Viewer cannot create findings."""

    set_test_user(VIEWER)

    response = client.post(
        "/findings/",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_update_finding(client):
    """A Viewer cannot update findings."""

    set_test_user(VIEWER)

    response = client.patch(
        "/findings/1",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_link_finding_to_vulnerability(client):
    """A Viewer cannot link a finding to a vulnerability."""

    set_test_user(VIEWER)

    response = client.patch(
        "/findings/1/link-vulnerability",
        json={},
    )

    assert response.status_code == 403


# Add remediation task RBAC tests
@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_remediation_tasks(
    client,
    monkeypatch,
    role_name,
):
    """All three roles can read remediation tasks."""

    set_test_user(role_name)

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_tasks",
        lambda db: [],
    )

    response = client.get("/remediation-tasks/")

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_remediation_task(client):
    """A Viewer cannot create remediation tasks."""

    set_test_user(VIEWER)

    response = client.post(
        "/remediation-tasks/",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_update_remediation_task(client):
    """A Viewer cannot update remediation tasks."""

    set_test_user(VIEWER)

    response = client.put(
        "/remediation-tasks/1",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_delete_remediation_task(client):
    """A Viewer cannot delete remediation tasks."""

    set_test_user(VIEWER)

    response = client.delete("/remediation-tasks/1")

    assert response.status_code == 403


# Add risk assessment RBAC tests
@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_risk_assessments(
    client,
    monkeypatch,
    role_name,
):
    """All three roles can read risk assessments."""

    set_test_user(role_name)

    monkeypatch.setattr(
        risk_assessment_service,
        "get_risk_assessments_for_vulnerability",
        lambda db, vulnerability_id: [],
    )

    response = client.get(
        "/risk-assessments/vulnerability/1"
    )

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_risk_assessment(client):
    """A Viewer cannot create risk assessments."""

    set_test_user(VIEWER)

    response = client.post(
        "/risk-assessments/",
        json={},
    )

    assert response.status_code == 403


# Add unauthenticated tests
@pytest.mark.parametrize(
    "endpoint",
    [
        "/vulnerabilities/",
        "/findings/",
        "/remediation-tasks/",
        "/risk-assessments/vulnerability/1",
    ],
)
def test_unauthenticated_user_cannot_access_protected_endpoints(
    client,
    endpoint,
):
    """Protected endpoints require authentication."""

    response = client.get(endpoint)

    assert response.status_code == 401









