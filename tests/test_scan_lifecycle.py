
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.schemas.scan import ScanUpdate
from app.services import scan_service


def test_pending_scan_can_transition_to_running():
    scan_service.validate_status_transition("pending", "running")


def test_running_scan_can_transition_to_completed():
    scan_service.validate_status_transition("running", "completed")


def test_running_scan_can_transition_to_failed():
    scan_service.validate_status_transition("running", "failed")


@pytest.mark.parametrize(
    ("current", "new"),
    [
        ("pending", "completed"),
        ("pending", "failed"),
        ("completed", "running"),
        ("completed", "pending"),
        ("failed", "running"),
        ("failed", "completed"),
    ],
)
def test_invalid_scan_transitions_are_rejected(current, new):
    with pytest.raises(HTTPException) as exc_info:
        scan_service.validate_status_transition(current, new)

    assert exc_info.value.status_code == 409


def test_invalid_status_is_rejected():
    with pytest.raises(HTTPException) as exc_info:
        scan_service.validate_status_transition("pending", "unknown")

    assert exc_info.value.status_code == 422


def test_update_scan_sets_started_at_when_scan_starts(monkeypatch):
    db = MagicMock()
    scan = SimpleNamespace(
        id=1,
        status="pending",
        started_at=None,
        completed_at=None,
    )

    monkeypatch.setattr(
        scan_service,
        "utc_now",
        lambda: datetime(2026, 10, 26, tzinfo=timezone.utc),
    )

    result = scan_service.update_scan(
        db,
        scan,
        ScanUpdate(status="running"),
    )

    assert result.status == "running"
    assert result.started_at == datetime(2026, 10, 26, tzinfo=timezone.utc)
    assert result.completed_at is None
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(scan)


def test_update_scan_sets_completed_at_when_scan_finishes(monkeypatch):
    db = MagicMock()
    started_at = datetime(2026, 10, 25, tzinfo=timezone.utc)
    completed_at = datetime(2026, 10, 26, tzinfo=timezone.utc)

    scan = SimpleNamespace(
        id=1,
        status="running",
        started_at=started_at,
        completed_at=None,
    )

    monkeypatch.setattr(
        scan_service,
        "utc_now",
        lambda: completed_at,
    )

    result = scan_service.update_scan(
        db,
        scan,
        ScanUpdate(status="completed"),
    )

    assert result.status == "completed"
    assert result.started_at == started_at
    assert result.completed_at == completed_at
    db.commit.assert_called_once()


def test_update_scan_rejects_manual_timestamp_changes():
    db = MagicMock()
    scan = SimpleNamespace(
        id=1,
        status="pending",
        started_at=None,
        completed_at=None,
    )

    with pytest.raises(HTTPException) as exc_info:
        scan_service.update_scan(
            db,
            scan,
            ScanUpdate(started_at=datetime.now(timezone.utc)),
        )

    assert exc_info.value.status_code == 422
    db.commit.assert_not_called()
