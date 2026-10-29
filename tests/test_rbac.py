
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
    audit_log_service,
    comment_service,
    vulnerability_history_service,
    role_service,
    software_service,
    scan_service,
    asset_software_service,
    vulnerability_priority_service,
)


@pytest.fixture
def client(monkeypatch):
    """Create a test client without accessing the real database."""

    mock_db = MagicMock()
    monkeypatch.setattr(
        __import__(__name__),
        "_test_mock_db",
        mock_db,
        raising=False,
    )


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
        lambda db, vulnerability_data, commit=True: created_vulnerability,
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


def test_create_vulnerability_records_audit_event(
    client,
    monkeypatch,
):
    """Creating a vulnerability records an audit event."""

    set_test_user(SECURITY_ANALYST)

    created_vulnerability = SimpleNamespace(
        id=42,
        asset_id=1,
        title="Audit Test Vulnerability",
        description="Testing automatic audit logging.",
        cve_id="CVE-2026-0042",
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
        lambda db, vulnerability_data, commit=True: created_vulnerability,
    )

    monkeypatch.setattr(
        "app.routers.vulnerabilities.validate_references",
        lambda db, asset_id, assigned_to, created_by=None: None,
    )

    audit_mock = MagicMock()
    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        audit_mock,
    )

    response = client.post(
        "/vulnerabilities/",
        json={
            "asset_id": 1,
            "title": "Audit Test Vulnerability",
            "description": "Testing automatic audit logging.",
            "cve_id": "CVE-2026-0042",
            "severity": "High",
            "cvss_score": 8.5,
            "status": "open",
            "assigned_to": None,
            "created_by": 1,
        },
    )

    assert response.status_code == 201

    audit_call = audit_mock.call_args
    assert audit_call.args[0] is not None
    assert audit_call.kwargs["user_id"] == 1
    assert audit_call.kwargs["action"] == "created"
    assert audit_call.kwargs["entity_type"] == "vulnerability"
    assert audit_call.kwargs["entity_id"] == 42
    assert audit_call.kwargs["details"] == (
        "Created vulnerability: Audit Test Vulnerability"
    )


def test_create_vulnerability_rolls_back_when_audit_logging_fails(
    client,
    monkeypatch,
):
    """A failed audit log causes creation to fail and roll back."""

    set_test_user(SECURITY_ANALYST)

    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db

    created_vulnerability = SimpleNamespace(
        id=42,
        asset_id=1,
        title="Audit Failure Test",
        description="Testing rollback on audit failure.",
        cve_id="CVE-2026-0042",
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
        lambda db, vulnerability_data, commit=True: created_vulnerability,
    )

    monkeypatch.setattr(
        "app.routers.vulnerabilities.validate_references",
        lambda db, asset_id, assigned_to, created_by=None: None,
    )

    def fail_audit_logging(*args, **kwargs):
        raise RuntimeError("Simulated audit logging failure")

    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        fail_audit_logging,
    )

    with TestClient(app, raise_server_exceptions=False) as test_client:
        response = test_client.post(
            "/vulnerabilities/",
            json={
                "asset_id": 1,
                "title": "Audit Failure Test",
                "description": "Testing rollback on audit failure.",
                "cve_id": "CVE-2026-0042",
                "severity": "High",
                "cvss_score": 8.5,
                "status": "open",
                "assigned_to": None,
                "created_by": 1,
            },
        )

    assert response.status_code == 500
    mock_db.rollback.assert_called_once()


def test_update_vulnerability_records_audit_event(
    client,
    monkeypatch,
):
    """Updating a vulnerability records an audit event."""

    set_test_user(SECURITY_ANALYST)

    existing_vulnerability = SimpleNamespace(
        id=42,
        asset_id=1,
        title="Original Vulnerability",
        description="Original description.",
        cve_id="CVE-2026-0042",
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
        id=42,
        asset_id=1,
        title="Updated Audit Test Vulnerability",
        description="Updated description.",
        cve_id="CVE-2026-0042",
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
        lambda db, vulnerability, vulnerability_data, commit=True:
            updated_vulnerability,
    )

    monkeypatch.setattr(
        "app.routers.vulnerabilities.validate_references",
        lambda db, asset_id, assigned_to, created_by=None: None,
    )

    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        MagicMock(),
    )

    response = client.put(
        "/vulnerabilities/42",
        json={
            "title": "Updated Audit Test Vulnerability",
        },
    )

    assert response.status_code == 200

    audit_call = audit_log_service.record_audit_event.call_args
    assert audit_call.args[0] is not None
    assert audit_call.kwargs["user_id"] == 1
    assert audit_call.kwargs["action"] == "updated"
    assert audit_call.kwargs["entity_type"] == "vulnerability"
    assert audit_call.kwargs["entity_id"] == 42
    assert audit_call.kwargs["details"] == (
        "Updated vulnerability: Updated Audit Test Vulnerability"
    )


def test_delete_vulnerability_records_audit_event(
    client,
    monkeypatch,
):
    """Deleting a vulnerability records an audit event."""

    set_test_user(SECURITY_ANALYST)

    vulnerability = SimpleNamespace(
        id=42,
        asset_id=1,
        title="Audit Test Vulnerability",
        description="Testing automatic audit logging.",
        cve_id="CVE-2026-0042",
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
        "get_vulnerability",
        lambda db, vulnerability_id: vulnerability,
    )

    monkeypatch.setattr(
        vulnerability_service,
        "delete_vulnerability",
        lambda db, vulnerability, commit=True: None,
    )

    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        MagicMock(),
    )

    response = client.delete("/vulnerabilities/42")

    assert response.status_code == 204

    audit_call = audit_log_service.record_audit_event.call_args
    assert audit_call.args[0] is not None
    assert audit_call.kwargs["user_id"] == 1
    assert audit_call.kwargs["action"] == "deleted"
    assert audit_call.kwargs["entity_type"] == "vulnerability"
    assert audit_call.kwargs["entity_id"] == 42
    assert audit_call.kwargs["details"] == (
        "Deleted vulnerability: Audit Test Vulnerability"
    )


def test_change_vulnerability_status_records_audit_event(
    client,
    monkeypatch,
):
    """Changing vulnerability status records an audit event."""

    set_test_user(SECURITY_ANALYST)

    vulnerability = SimpleNamespace(
        id=42,
        title="Audit Test Vulnerability",
        status="resolved",
    )

    history = SimpleNamespace(
        old_status="open",
        new_status="resolved",
    )

    monkeypatch.setattr(
        vulnerability_service,
        "change_vulnerability_status",
        lambda db, vulnerability_id, change_data, changed_by, commit=True: {
            "vulnerability": vulnerability,
            "history": history,
        },
    )

    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        MagicMock(),
    )

    response = client.patch(
        "/vulnerabilities/42/status",
        json={"new_status": "resolved"},
    )

    assert response.status_code == 200

    audit_call = audit_log_service.record_audit_event.call_args
    assert audit_call.args[0] is not None
    assert audit_call.kwargs["user_id"] == 1
    assert audit_call.kwargs["action"] == "status_changed"
    assert audit_call.kwargs["entity_type"] == "vulnerability"
    assert audit_call.kwargs["entity_id"] == 42
    assert audit_call.kwargs["details"] == (
        "Vulnerability status changed from open to resolved"
    )


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
        lambda db, vulnerability, vulnerability_data, commit=True: updated_vulnerability,
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


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_create_finding(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can create findings."""

    set_test_user(role_name)

    now = datetime.now(timezone.utc)
    created_finding = SimpleNamespace(
        id=1,
        scan_id=1,
        asset_id=1,
        vulnerability_id=None,
        title="RBAC Test Finding",
        description="Finding created for an RBAC test.",
        severity="high",
        status="open",
        evidence=None,
        first_detected_at=now,
        last_detected_at=now,
        created_at=now,
    )

    monkeypatch.setattr(
        finding_service,
        "create_finding",
        lambda db, finding_data: created_finding,
    )

    response = client.post(
        "/findings/",
        json={
            "scan_id": 1,
            "asset_id": 1,
            "title": "RBAC Test Finding",
            "severity": "high",
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] == 1
    assert response.json()["title"] == "RBAC Test Finding"


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_update_finding(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can update findings."""

    set_test_user(role_name)

    now = datetime.now(timezone.utc)
    updated_finding = SimpleNamespace(
        id=1,
        scan_id=1,
        asset_id=1,
        vulnerability_id=None,
        title="Updated RBAC Test Finding",
        description=None,
        severity="high",
        status="open",
        evidence=None,
        first_detected_at=now,
        last_detected_at=now,
        created_at=now,
    )

    monkeypatch.setattr(
        finding_service,
        "update_finding",
        lambda db, finding_id, finding_data: updated_finding,
    )

    response = client.patch(
        "/findings/1",
        json={"title": "Updated RBAC Test Finding"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["title"] == "Updated RBAC Test Finding"


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_link_finding_to_vulnerability(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can link findings."""

    set_test_user(role_name)

    now = datetime.now(timezone.utc)
    linked_finding = SimpleNamespace(
        id=1,
        scan_id=1,
        asset_id=1,
        vulnerability_id=42,
        title="RBAC Test Finding",
        description=None,
        severity="high",
        status="open",
        evidence=None,
        first_detected_at=now,
        last_detected_at=now,
        created_at=now,
    )

    monkeypatch.setattr(
        finding_service,
        "link_finding_to_vulnerability",
        lambda db, finding_id, link_data: linked_finding,
    )

    response = client.patch(
        "/findings/1/link-vulnerability",
        json={"vulnerability_id": 42},
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["vulnerability_id"] == 42


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


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_create_remediation_task(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can create remediation tasks."""

    set_test_user(role_name)

    created_task = SimpleNamespace(
        id=1,
        vulnerability_id=1,
        title="RBAC Test Remediation",
        description=None,
        status="pending",
        priority="medium",
        assigned_to=None,
        due_date=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        "app.routers.remediation_tasks.validate_references",
        lambda db, vulnerability_id, assigned_to: None,
    )
    monkeypatch.setattr(
        remediation_task_service,
        "create_remediation_task",
        lambda db, task_data, commit=True: created_task,
    )
    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        MagicMock(),
    )

    response = client.post(
        "/remediation-tasks/",
        json={
            "vulnerability_id": 1,
            "title": "RBAC Test Remediation",
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] == 1
    assert response.json()["title"] == "RBAC Test Remediation"


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_update_remediation_task(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can update remediation tasks."""

    set_test_user(role_name)

    existing_task = SimpleNamespace(
        id=1,
        vulnerability_id=1,
        title="Original Remediation",
        description=None,
        status="pending",
        priority="medium",
        assigned_to=None,
        due_date=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    updated_task = SimpleNamespace(
        id=1,
        vulnerability_id=1,
        title="Updated Remediation",
        description=None,
        status="pending",
        priority="medium",
        assigned_to=None,
        due_date=None,
        created_at=existing_task.created_at,
        updated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: existing_task,
    )
    monkeypatch.setattr(
        "app.routers.remediation_tasks.validate_references",
        lambda db, vulnerability_id, assigned_to: None,
    )
    monkeypatch.setattr(
        remediation_task_service,
        "update_remediation_task",
        lambda db, task, task_data, commit=True: updated_task,
    )
    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        MagicMock(),
    )

    response = client.put(
        "/remediation-tasks/1",
        json={"title": "Updated Remediation"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == 1
    assert response.json()["title"] == "Updated Remediation"


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_delete_remediation_task(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can delete remediation tasks."""

    set_test_user(role_name)

    existing_task = SimpleNamespace(
        id=1,
        vulnerability_id=1,
        title="Remediation to Delete",
        description=None,
        status="pending",
        priority="medium",
        assigned_to=None,
        due_date=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: existing_task,
    )
    monkeypatch.setattr(
        remediation_task_service,
        "delete_remediation_task",
        MagicMock(),
    )
    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        MagicMock(),
    )

    response = client.delete("/remediation-tasks/1")

    assert response.status_code == 204


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
        "/scans/",
        "/assets/",
        "/audit-logs/",
        "/vulnerabilities/prioritized",
    ],
)
def test_unauthenticated_user_cannot_access_protected_endpoints(
    client,
    endpoint,
):
    """Protected endpoints require authentication."""

    response = client.get(endpoint)

    assert response.status_code == 401


# Comments RBAC tests
@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_comments(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can read comments."""

    set_test_user(role_name)

    monkeypatch.setattr(
        comment_service,
        "get_all_comments",
        lambda db, skip, limit: [],
    )

    response = client.get("/comments/")

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_comment(client):
    """A Viewer cannot create comments."""

    set_test_user(VIEWER)

    response = client.post("/comments/", json={})

    assert response.status_code == 403


def test_viewer_cannot_edit_comment(client):
    """A Viewer cannot edit comments."""

    set_test_user(VIEWER)

    response = client.patch("/comments/1", json={})

    assert response.status_code == 403


# Vulnerability History RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_vulnerability_history(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can read vulnerability history."""

    set_test_user(role_name)

    monkeypatch.setattr(
        vulnerability_history_service,
        "get_all_vulnerability_history",
        lambda db, skip, limit: [],
    )

    response = client.get("/vulnerability-history/")

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_vulnerability_history(client):
    """A Viewer cannot create vulnerability history records."""

    set_test_user(VIEWER)

    response = client.post(
        "/vulnerability-history/",
        json={},
    )

    assert response.status_code == 403


# Roles RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_roles(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can list roles."""

    set_test_user(role_name)

    monkeypatch.setattr(
        role_service,
        "get_roles",
        lambda db: [],
    )

    response = client.get("/roles/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "role_name",
    [SECURITY_ANALYST, VIEWER],
)
def test_non_admin_users_cannot_create_roles(
    client,
    monkeypatch,
    role_name,
):
    """Only Administrators can create roles."""

    set_test_user(role_name)

    response = client.post(
        "/roles/",
        json={"name": "RBAC Test Role"},
    )

    assert response.status_code == 403


def test_viewer_cannot_update_role(client):
    """A Viewer cannot update roles."""

    set_test_user(VIEWER)

    response = client.put(
        "/roles/999999",
        json={"name": "Updated Test Role"},
    )

    assert response.status_code == 403


def test_security_analyst_cannot_delete_role(client):
    """A Security Analyst cannot delete roles."""

    set_test_user(SECURITY_ANALYST)

    response = client.delete("/roles/999999")

    assert response.status_code == 403




# Software RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_software(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can list software."""

    set_test_user(role_name)

    monkeypatch.setattr(
        software_service,
        "get_software_list",
        lambda db: [],
    )

    response = client.get("/software/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_create_software(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Analysts can create software."""

    set_test_user(role_name)

    # Configure the mocked database so the duplicate check
    # finds no existing software record.
    from app.database import get_db

    mock_db = app.dependency_overrides[get_db]()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    created_software = SimpleNamespace(
        id=1,
        name="RBAC Test Software",
        version="1.0",
        vendor="Test Vendor",
        description="Software created for an RBAC test.",
        created_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        software_service,
        "create_software",
        lambda db, software_data: created_software,
    )

    response = client.post(
        "/software/",
        json={
            "name": "RBAC Test Software",
            "version": "1.0",
            "vendor": "Test Vendor",
            "description": "Software created for an RBAC test.",
        },
    )

    assert response.status_code == 201
    assert response.json()["id"] == 1


def test_viewer_cannot_create_software(client):
    """A Viewer cannot create software."""

    set_test_user(VIEWER)

    response = client.post(
        "/software/",
        json={
            "name": "Unauthorized Software",
            "version": "1.0",
            "vendor": "Test Vendor",
        },
    )

    assert response.status_code == 403


def test_viewer_cannot_update_software(client):
    """A Viewer cannot update software."""

    set_test_user(VIEWER)

    response = client.put(
        "/software/1",
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403


def test_viewer_cannot_delete_software(client):
    """A Viewer cannot delete software."""

    set_test_user(VIEWER)

    response = client.delete("/software/1")

    assert response.status_code == 403



# Scans RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_scans(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can list scans."""

    set_test_user(role_name)

    monkeypatch.setattr(
        scan_service,
        "get_scans",
        lambda db: [],
    )

    response = client.get("/scans/")

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_scan(client):
    """A Viewer cannot create scans."""

    set_test_user(VIEWER)

    response = client.post(
        "/scans/",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_update_scan(client):
    """A Viewer cannot update scans."""

    set_test_user(VIEWER)

    response = client.put(
        "/scans/1",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_delete_scan(client):
    """A Viewer cannot delete scans."""

    set_test_user(VIEWER)

    response = client.delete("/scans/1")

    assert response.status_code == 403



# Asset-Software RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_asset_software(
    client,
    monkeypatch,
    role_name,
):
    set_test_user(role_name)

    monkeypatch.setattr(
        asset_software_service,
        "get_asset_software_list",
        lambda db: [],
    )

    response = client.get("/asset-software/")

    assert response.status_code == 200
    assert response.json() == []


def test_viewer_cannot_create_asset_software(client):
    set_test_user(VIEWER)

    response = client.post(
        "/asset-software/",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_update_asset_software(client):
    set_test_user(VIEWER)

    response = client.put(
        "/asset-software/1",
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_delete_asset_software(client):
    set_test_user(VIEWER)

    response = client.delete("/asset-software/1")

    assert response.status_code == 403



# Audit Logs RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_audit_logs(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can list audit logs."""

    set_test_user(role_name)

    monkeypatch.setattr(
        audit_log_service,
        "get_audit_logs",
        lambda db: [],
    )

    response = client.get("/audit-logs/")

    assert response.status_code == 200
    assert response.json() == []



@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST],
)
def test_admin_and_analyst_can_create_audit_log(
    client,
    monkeypatch,
    role_name,
):
    """Administrators and Security Analysts can create audit logs."""

    set_test_user(role_name)

    created_audit_log = SimpleNamespace(
        id=1,
        user_id=1,
        action="RBAC test",
        entity_type="vulnerability",
        entity_id=1,
        details="Audit log created for an RBAC test.",
        ip_address=None,
        created_at=datetime.now(timezone.utc),
    )

    monkeypatch.setattr(
        audit_log_service,
        "create_audit_log",
        lambda db, audit_log_data: created_audit_log,
    )

    monkeypatch.setattr(
        "app.routers.audit_logs.validate_user",
        lambda db, user_id: None,
    )

    response = client.post(
        "/audit-logs/",
        json={
            "user_id": 1,
            "action": "RBAC test",
            "entity_type": "vulnerability",
            "entity_id": 1,
            "details": "Audit log created for an RBAC test.",
            "ip_address": None,
        },
    )

    if response.status_code != 201:
        print("Status:", response.status_code)
        print("Response:", response.json())

    assert response.status_code == 201
    assert response.json()["id"] == 1
    assert response.json()["action"] == "RBAC test"
    assert response.json()["entity_type"] == "vulnerability"


def test_viewer_cannot_create_audit_log(client):
    """Viewers cannot create audit logs."""

    set_test_user(VIEWER)

    response = client.post(
        "/audit-logs/",
        json={},
    )

    assert response.status_code == 403


def test_unauthenticated_user_cannot_read_audit_logs(client):
    """Unauthenticated users cannot read audit logs."""

    response = client.get("/audit-logs/")

    assert response.status_code == 401


def test_unauthenticated_user_cannot_create_audit_log(client):
    """Unauthenticated users cannot create audit logs."""

    response = client.post(
    "/audit-logs/",
    json={
        "user_id": 1,
        "action": "RBAC test",
        "entity_type": "vulnerability",
        "entity_id": 1,
        "details": "Audit log created for an RBAC test.",
        "ip_address": None,
        },
    )

    assert response.status_code == 401


def test_vulnerability_status_cannot_be_changed_through_put(client, monkeypatch):
    set_test_user(SECURITY_ANALYST)

    response = client.put(
        "/vulnerabilities/1",
        json={"status": "resolved"},
    )

    assert response.status_code == 422
    assert "PATCH" in response.json()["detail"]


# Vulnerability prioritization RBAC tests

@pytest.mark.parametrize(
    "role_name",
    [ADMINISTRATOR, SECURITY_ANALYST, VIEWER],
)
def test_all_roles_can_read_prioritized_vulnerabilities(
    client,
    monkeypatch,
    role_name,
):
    """All authenticated roles can read prioritized vulnerabilities."""

    set_test_user(role_name)

    prioritized_data = [
        {
            "vulnerability_id": 1,
            "title": "Prioritized test vulnerability",
            "cve_id": "CVE-2026-1234",
            "severity": "high",
            "status": "open",
            "asset_id": 1,
            "risk_score": 12,
            "risk_level": "high",
            "assessed_at": None,
        }
    ]

    monkeypatch.setattr(
        vulnerability_priority_service,
        "get_prioritized_vulnerabilities",
        lambda db, status=None, risk_level=None, severity=None: (
            prioritized_data
        ),
    )

    response = client.get("/vulnerabilities/prioritized")

    assert response.status_code == 200
    assert response.json() == prioritized_data


def test_unauthenticated_user_cannot_read_prioritized_vulnerabilities(
    client,
):
    """Prioritized vulnerabilities require authentication."""

    response = client.get("/vulnerabilities/prioritized")

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


# Vulnerability prioritization filter API tests

def test_prioritized_endpoint_passes_filters_to_service(
    client,
    monkeypatch,
):
    set_test_user(SECURITY_ANALYST)

    expected_data = [
        {
            "vulnerability_id": 1,
            "title": "Open high-risk vulnerability",
            "cve_id": "CVE-2026-1234",
            "severity": "high",
            "status": "open",
            "asset_id": 1,
            "risk_score": 12,
            "risk_level": "high",
            "assessed_at": None,
        }
    ]

    def mock_get_prioritized_vulnerabilities(
        db,
        status=None,
        risk_level=None,
        severity=None,
    ):
        assert status == "open"
        assert risk_level == "high"
        assert severity == "high"
        return expected_data

    monkeypatch.setattr(
        vulnerability_priority_service,
        "get_prioritized_vulnerabilities",
        mock_get_prioritized_vulnerabilities,
    )

    response = client.get(
        "/vulnerabilities/prioritized",
        params={
            "status": "open",
            "risk_level": "high",
            "severity": "high",
        },
    )

    assert response.status_code == 200
    assert response.json() == expected_data


def test_prioritized_endpoint_filters_are_optional(
    client,
    monkeypatch,
):
    set_test_user(SECURITY_ANALYST)

    monkeypatch.setattr(
        vulnerability_priority_service,
        "get_prioritized_vulnerabilities",
        lambda db, status=None, risk_level=None, severity=None: [],
    )

    response = client.get("/vulnerabilities/prioritized")

    assert response.status_code == 200
    assert response.json() == []


def test_prioritized_endpoint_rejects_unauthenticated_user(client):
    response = client.get(
        "/vulnerabilities/prioritized",
        params={"status": "open"},
    )

    assert response.status_code == 401


