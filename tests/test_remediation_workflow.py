from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.services.remediation_task_service import (
    create_remediation_task,
    update_remediation_task,
)


def make_task(status="pending", priority="medium"):
    return SimpleNamespace(
        id=1,
        vulnerability_id=10,
        title="Fix vulnerable software",
        description="Update the affected package",
        status=status,
        priority=priority,
        assigned_to=2,
        due_date=None,
    )


def make_update_data(**fields):
    return SimpleNamespace(
        model_dump=lambda exclude_unset=False: dict(fields)
    )


@pytest.mark.parametrize(
    ("old_status", "new_status"),
    [
        ("pending", "in_progress"),
        ("in_progress", "completed"),
        ("in_progress", "pending"),
        ("completed", "in_progress"),
    ],
)
def test_allowed_remediation_status_transitions(
    old_status,
    new_status,
):
    db = MagicMock()
    task = make_task(status=old_status)

    result = update_remediation_task(
        db,
        task,
        make_update_data(status=new_status),
    )

    assert result.status == new_status
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(task)


@pytest.mark.parametrize(
    ("old_status", "new_status"),
    [
        ("pending", "completed"),
        ("pending", "cancelled"),
        ("in_progress", "cancelled"),
        ("completed", "pending"),
        ("completed", "completed"),
    ],
)
def test_invalid_remediation_status_transitions_are_rejected(
    old_status,
    new_status,
):
    db = MagicMock()
    task = make_task(status=old_status)

    with pytest.raises(HTTPException):
        update_remediation_task(
            db,
            task,
            make_update_data(status=new_status),
        )

    db.commit.assert_not_called()


def test_status_values_are_normalized():
    db = MagicMock()
    task = make_task(status=" PENDING ")

    result = update_remediation_task(
        db,
        task,
        make_update_data(status=" IN_PROGRESS "),
    )

    assert result.status == "in_progress"
    db.commit.assert_called_once()


def test_non_status_updates_remain_supported():
    db = MagicMock()
    task = make_task()

    result = update_remediation_task(
        db,
        task,
        make_update_data(title="Apply security patch"),
    )

    assert result.title == "Apply security patch"
    assert result.status == "pending"
    db.commit.assert_called_once()


def test_database_error_rolls_back_update():
    db = MagicMock()
    task = make_task(status="pending")
    db.commit.side_effect = Exception("Database error")

    with pytest.raises(Exception, match="Database error"):
        update_remediation_task(
            db,
            task,
            make_update_data(status="in_progress"),
        )

    db.rollback.assert_called_once()


def test_update_with_commit_false_flushes_without_committing():
    db = MagicMock()
    task = make_task()

    result = update_remediation_task(
        db,
        task,
        make_update_data(title="Apply security patch"),
        commit=False,
    )

    assert result.title == "Apply security patch"
    db.flush.assert_called_once()
    db.commit.assert_not_called()
    db.refresh.assert_not_called()
    db.rollback.assert_not_called()


def test_flush_error_rolls_back_update():
    db = MagicMock()
    task = make_task()
    db.flush.side_effect = Exception("Flush failed")

    with pytest.raises(Exception, match="Flush failed"):
        update_remediation_task(
            db,
            task,
            make_update_data(title="Apply security patch"),
            commit=False,
        )

    db.flush.assert_called_once()
    db.commit.assert_not_called()
    db.rollback.assert_called_once()


def test_delete_with_commit_false_flushes_without_committing():
    from app.services.remediation_task_service import (
        delete_remediation_task,
    )

    db = MagicMock()
    task = make_task()

    delete_remediation_task(
        db,
        task,
        commit=False,
    )

    db.delete.assert_called_once_with(task)
    db.flush.assert_called_once()
    db.commit.assert_not_called()


def test_create_with_commit_false_flushes_without_committing():
    db = MagicMock()

    task_data = SimpleNamespace(
        model_dump=lambda: {
            "vulnerability_id": 10,
            "title": "Fix vulnerable software",
            "description": "Update the affected package",
            "status": "pending",
            "priority": "medium",
            "assigned_to": 2,
            "due_date": None,
        }
    )

    result = create_remediation_task(
        db,
        task_data,
        commit=False,
    )

    db.add.assert_called_once_with(result)
    db.flush.assert_called_once()
    db.commit.assert_not_called()
    db.refresh.assert_not_called()
