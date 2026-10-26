
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app import models
from app.core.dependencies import get_current_user
from app.database import get_db
from app.main import app
from app.services import finding_service


def make_test_finding(finding_data):
    now = datetime.now(timezone.utc)

    return SimpleNamespace(
        id=101,
        scan_id=finding_data.scan_id,
        asset_id=finding_data.asset_id,
        vulnerability_id=None,
        title=finding_data.title,
        description=finding_data.description,
        severity=finding_data.severity,
        status=finding_data.status,
        evidence=finding_data.evidence,
        first_detected_at=now,
        last_detected_at=now,
        created_at=now,
    )


def test_create_finding_endpoint_calls_integration_service(monkeypatch):
    mock_db = MagicMock()

    test_user = SimpleNamespace(
        id=1,
        username="integration_test_user",
        is_active=True,
        role=SimpleNamespace(name="Security Analyst"),
    )

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: test_user

    now = datetime.now(timezone.utc)
    created_finding = SimpleNamespace(
        id=101,
        scan_id=1,
        asset_id=1,
        vulnerability_id=99,
        title="Apache vulnerability CVE-2021-44228",
        description="Detected during scan",
        severity="High",
        status="open",
        evidence="CVE-2021-44228 detected",
        first_detected_at=now,
        last_detected_at=now,
        created_at=now,
    )

    def fake_create_finding(db, finding_data):
        assert db is mock_db
        assert finding_data.scan_id == 1
        assert finding_data.asset_id == 1
        return created_finding

    monkeypatch.setattr(
        finding_service,
        "create_finding",
        fake_create_finding,
    )

    try:
        with TestClient(app) as client:
            response = client.post(
                "/findings/",
                json={
                    "scan_id": 1,
                    "asset_id": 1,
                    "title": "Apache vulnerability CVE-2021-44228",
                    "description": "Detected during scan",
                    "severity": "High",
                    "status": "open",
                    "evidence": "CVE-2021-44228 detected",
                },
            )

        assert response.status_code == 201
        assert response.json()["id"] == 101
        assert response.json()["vulnerability_id"] == 99

    finally:
        app.dependency_overrides.clear()



def test_create_finding_endpoint_creates_and_links_vulnerability(
    monkeypatch,
):
    mock_db = MagicMock()

    test_user = SimpleNamespace(
        id=1,
        username="integration_test_user",
        is_active=True,
        role=SimpleNamespace(name="Security Analyst"),
    )

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: test_user

    now = datetime.now(timezone.utc)
    added_objects = []

    def fake_add(obj):
        added_objects.append(obj)

        if isinstance(obj, models.Finding):
            obj.id = 101
            obj.first_detected_at = now
            obj.last_detected_at = now
            obj.created_at = now

    mock_db.add.side_effect = fake_add

    # Simulate generated database IDs during flush.
    def fake_flush():
        for obj in added_objects:
            if isinstance(obj, models.Vulnerability):
                obj.id = 201

    mock_db.flush.side_effect = fake_flush

    # Return existing scan, existing asset, then no CVE match.
    query_results = iter([
        SimpleNamespace(id=1),
        SimpleNamespace(id=1),
        None,
    ])

    def fake_query(model):
        query = MagicMock()
        query.filter.return_value.first.side_effect = (
            lambda: next(query_results)
        )
        return query

    mock_db.query.side_effect = fake_query

    try:
        with TestClient(app) as client:
            response = client.post(
                "/findings/",
                json={
                    "scan_id": 1,
                    "asset_id": 1,
                    "title": "Apache vulnerability CVE-2021-44228",
                    "description": "Detected during scan",
                    "severity": "High",
                    "status": "open",
                    "evidence": "CVE-2021-44228 detected",
                },
            )

        assert response.status_code == 201, response.text
        assert response.json()["vulnerability_id"] == 201

        created_vulnerabilities = [
            obj for obj in added_objects
            if isinstance(obj, models.Vulnerability)
        ]

        assert len(created_vulnerabilities) == 1
        assert created_vulnerabilities[0].cve_id == "CVE-2021-44228"
        assert created_vulnerabilities[0].status == "open"

        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once()

    finally:
        app.dependency_overrides.clear()



def test_create_finding_reuses_and_reopens_resolved_vulnerability(
    monkeypatch,
):
    mock_db = MagicMock()

    test_user = SimpleNamespace(
        id=1,
        username="integration_test_user",
        is_active=True,
        role=SimpleNamespace(name="Security Analyst"),
    )

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: test_user

    now = datetime.now(timezone.utc)
    original_discovery = datetime(2025, 1, 1, tzinfo=timezone.utc)

    existing_vulnerability = SimpleNamespace(
        id=201,
        asset_id=1,
        cve_id="CVE-2021-44228",
        title="Apache Log4j vulnerability",
        description="Previously detected vulnerability",
        severity="High",
        status="resolved",
        discovered_at=original_discovery,
    )

    added_objects = []

    def fake_add(obj):
        added_objects.append(obj)

        if isinstance(obj, models.Finding):
            obj.id = 102
            obj.first_detected_at = now
            obj.last_detected_at = now
            obj.created_at = now

    mock_db.add.side_effect = fake_add

    def fake_flush():
        # Simulate the database-generated finding ID.
        for obj in added_objects:
            if isinstance(obj, models.Finding):
                obj.id = 102

    mock_db.flush.side_effect = fake_flush

    # The first two queries validate the scan and asset.
    # The third finds the existing CVE on the same asset.
    query_results = iter([
        SimpleNamespace(id=1),
        SimpleNamespace(id=1),
        existing_vulnerability,
    ])

    def fake_query(model):
        query = MagicMock()
        query.filter.return_value.first.side_effect = (
            lambda: next(query_results)
        )
        return query

    mock_db.query.side_effect = fake_query

    try:
        with TestClient(app) as client:
            response = client.post(
                "/findings/",
                json={
                    "scan_id": 2,
                    "asset_id": 1,
                    "title": "Apache Log4j detected: CVE-2021-44228",
                    "description": "Detected again during a new scan",
                    "severity": "High",
                    "status": "open",
                    "evidence": "CVE-2021-44228 detected",
                },
            )

        assert response.status_code == 201, response.text
        assert response.json()["vulnerability_id"] == 201

        assert existing_vulnerability.status == "open"
        assert existing_vulnerability.discovered_at == original_discovery

        created_vulnerabilities = [
            obj for obj in added_objects
            if isinstance(obj, models.Vulnerability)
        ]

        assert created_vulnerabilities == []
        mock_db.commit.assert_called_once()

    finally:
        app.dependency_overrides.clear()
