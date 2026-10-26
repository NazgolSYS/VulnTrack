
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.roles import SECURITY_ANALYST, VIEWER
from app.services import scan_service

# Reuse the existing RBAC test fixtures and helpers.
from tests.test_rbac import client, set_test_user


@pytest.fixture
def existing_scan():
    return SimpleNamespace(
        id=1,
        name="Lifecycle API test scan",
        scan_type="vulnerability",
        status="pending",
        started_by=1,
        started_at=None,
        completed_at=None,
        summary=None,
        created_at=datetime(2026, 10, 26, tzinfo=timezone.utc),
    )


def test_analyst_can_start_scan(
    client, monkeypatch, existing_scan
):
    set_test_user(SECURITY_ANALYST)

    monkeypatch.setattr(
        scan_service,
        "get_scan",
        lambda db, scan_id: existing_scan,
    )

    def update_scan(db, scan, scan_data):
        scan.status = "running"
        scan.started_at = datetime(
            2026, 10, 26, tzinfo=timezone.utc
        )
        return scan

    monkeypatch.setattr(
        scan_service, "update_scan", update_scan
    )

    response = client.put(
        "/scans/1",
        json={"status": "running"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "running"
    assert response.json()["started_at"] is not None


def test_analyst_cannot_skip_pending_to_completed(
    client, monkeypatch, existing_scan
):
    set_test_user(SECURITY_ANALYST)

    monkeypatch.setattr(
        scan_service,
        "get_scan",
        lambda db, scan_id: existing_scan,
    )

    def reject_transition(db, scan, scan_data):
        scan_service.validate_status_transition(
            scan.status,
            scan_data.status,
        )

    monkeypatch.setattr(
        scan_service, "update_scan", reject_transition
    )

    response = client.put(
        "/scans/1",
        json={"status": "completed"},
    )

    assert response.status_code == 409
    assert "cannot transition" in response.json()["detail"].lower()


def test_viewer_cannot_update_scan_status(
    client, monkeypatch, existing_scan
):
    set_test_user(VIEWER)

    monkeypatch.setattr(
        scan_service,
        "get_scan",
        lambda db, scan_id: existing_scan,
    )

    response = client.put(
        "/scans/1",
        json={"status": "running"},
    )

    assert response.status_code == 403
