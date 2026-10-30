from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services import user_service
from app.services.auth_service import hash_password


def test_create_user_hashes_password(monkeypatch):
    """New user passwords are hashed before database storage."""

    mock_db = MagicMock()

    user_data = SimpleNamespace(
        username="test_user",
        email="test@example.com",
        password="plain_password",
        role_id=2,
    )

    monkeypatch.setattr(
        user_service,
        "hash_password",
        lambda password: "hashed_password",
    )

    user = user_service.create_user(mock_db, user_data)

    assert user.username == "test_user"
    assert user.email == "test@example.com"
    assert user.hashed_password == "hashed_password"
    assert user.role_id == 2

    mock_db.add.assert_called_once_with(user)
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(user)


def test_get_users():
    """Users are retrieved in ascending ID order."""

    mock_db = MagicMock()
    expected_users = [MagicMock(), MagicMock()]

    mock_db.query.return_value.order_by.return_value.all.return_value = (
        expected_users
    )

    result = user_service.get_users(mock_db)

    assert result == expected_users


def test_get_user():
    """A user is retrieved by ID."""

    mock_db = MagicMock()
    expected_user = MagicMock()

    mock_db.query.return_value.filter.return_value.first.return_value = (
        expected_user
    )

    result = user_service.get_user(mock_db, 1)

    assert result == expected_user


def test_update_user():
    """Permitted user fields are updated and committed."""

    mock_db = MagicMock()

    user = SimpleNamespace(
        username="old_username",
        email="old@example.com",
        role_id=2,
        is_active=True,
    )

    user_data = SimpleNamespace(
        model_dump=lambda exclude_unset: {
            "username": "new_username",
            "is_active": False,
        }
    )

    result = user_service.update_user(
        mock_db,
        user,
        user_data,
    )

    assert result == user
    assert user.username == "new_username"
    assert user.email == "old@example.com"
    assert user.is_active is False

    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once_with(user)


def test_delete_user():
    """A user is deleted and the transaction is committed."""

    mock_db = MagicMock()
    user = MagicMock()

    user_service.delete_user(mock_db, user)

    mock_db.delete.assert_called_once_with(user)
    mock_db.commit.assert_called_once()

