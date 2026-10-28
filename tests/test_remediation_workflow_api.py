
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.dependencies import get_current_user
from app.core.roles import SECURITY_ANALYST
from app.services import audit_log_service, remediation_task_service
from app.database import get_db


@pytest.fixture
def client():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db

    yield TestClient(app)

    app.dependency_overrides.clear()


def make_task(status="pending"):
    return SimpleNamespace(
        id=1,
        vulnerability_id=10,
        title="Fix vulnerable software",
        description="Update the affected package",
        status=status,
        priority="medium",
        assigned_to=2,
        due_date=None,
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


@pytest.fixture
def analyst_user():
    user = SimpleNamespace(
        id=1,
        username="remediation_test_analyst",
        is_active=True,
        role=SimpleNamespace(name=SECURITY_ANALYST),
    )

    app.dependency_overrides[get_current_user] = lambda: user
    yield user
    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize(
    ("old_status", "new_status"),
    [
        ("pending", "in_progress"),
        ("in_progress", "completed"),
        ("in_progress", "pending"),
        ("completed", "in_progress"),
    ],
)
def test_api_accepts_allowed_status_transitions(
    client,
    analyst_user,
    monkeypatch,
    old_status,
    new_status,
):
    task = make_task(status=old_status)

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: task,
    )

    def validate_references(db, vulnerability_id, assigned_to):
        return None

    monkeypatch.setattr(
        "app.routers.remediation_tasks.validate_references",
        validate_references,
    )

    def update_task(
    db,
    existing_task,
    task_data,
    commit=True,
    ):
        existing_task.status = task_data.status.strip().lower()
        return existing_task

    monkeypatch.setattr(
        remediation_task_service,
        "update_remediation_task",
        update_task,
    )

    response = client.put(
        "/remediation-tasks/1",
        json={"status": new_status},
    )

    assert response.status_code == 200
    assert response.json()["status"] == new_status


@pytest.mark.parametrize(
    ("old_status", "new_status", "expected_code"),
    [
        ("pending", "completed", 409),
        ("pending", "cancelled", 422),
        ("in_progress", "cancelled", 422),
        ("completed", "pending", 409),
        ("completed", "completed", 409),
    ],
)
def test_api_rejects_invalid_status_transitions(
    client,
    analyst_user,
    monkeypatch,
    old_status,
    new_status,
    expected_code,
):
    task = make_task(status=old_status)

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: task,
    )

    monkeypatch.setattr(
        "app.routers.remediation_tasks.validate_references",
        lambda db, vulnerability_id, assigned_to: None,
    )

    def reject_update(db, existing_task, task_data):
        from fastapi import HTTPException

        return remediation_task_service.update_remediation_task(
            db,
            existing_task,
            task_data,
        )

    # Use the real service implementation for transition validation.
    monkeypatch.undo()

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: task,
    )

    monkeypatch.setattr(
        "app.routers.remediation_tasks.validate_references",
        lambda db, vulnerability_id, assigned_to: None,
    )

    response = client.put(
        "/remediation-tasks/1",
        json={"status": new_status},
    )

    assert response.status_code == expected_code


def test_delete_remediation_task_records_audit_event(
    client,
    analyst_user,
    monkeypatch,
):
    task = make_task()
    mock_db = app.dependency_overrides[get_db]()

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: task,
    )

    deleted = {}

    def delete_task(db, existing_task, commit=True):
        deleted["task"] = existing_task
        deleted["commit"] = commit

    monkeypatch.setattr(
        remediation_task_service,
        "delete_remediation_task",
        delete_task,
    )

    audit_events = []

    def record_audit_event(db, **kwargs):
        audit_events.append(kwargs)

    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        record_audit_event,
    )

    response = client.delete("/remediation-tasks/1")

    assert response.status_code == 204
    assert deleted["task"] is task
    assert deleted["commit"] is False

    assert audit_events == [
        {
            "user_id": analyst_user.id,
            "action": "deleted",
            "entity_type": "remediation_task",
            "entity_id": task.id,
            "details": f"Deleted remediation task: {task.title}",
        }
    ]

    mock_db.commit.assert_called_once()
    mock_db.rollback.assert_not_called()


def test_delete_remediation_task_rolls_back_if_audit_fails(
    client,
    analyst_user,
    monkeypatch,
):
    task = make_task()
    mock_db = app.dependency_overrides[get_db]()

    monkeypatch.setattr(
        remediation_task_service,
        "get_remediation_task",
        lambda db, task_id: task,
    )

    deleted = {}

    def delete_task(db, existing_task, commit=True):
        deleted["task"] = existing_task
        deleted["commit"] = commit

    monkeypatch.setattr(
        remediation_task_service,
        "delete_remediation_task",
        delete_task,
    )

    def fail_audit(db, **kwargs):
        raise RuntimeError("Audit logging failed")

    monkeypatch.setattr(
        audit_log_service,
        "record_audit_event",
        fail_audit,
    )

    with pytest.raises(RuntimeError, match="Audit logging failed"):
        client.delete("/remediation-tasks/1")

    assert deleted["task"] is task
    assert deleted["commit"] is False

    mock_db.commit.assert_not_called()
    mock_db.rollback.assert_called_once()
