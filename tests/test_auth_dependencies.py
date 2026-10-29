
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.dependencies import get_current_user
from app.models import User


def create_credentials(token="test-token"):
    """Create mock HTTP Bearer credentials."""

    return HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=token,
    )


def create_test_user(
    user_id=1,
    username="auth_test_user",
    is_active=True,
):
    """Create a lightweight user without accessing PostgreSQL."""

    return SimpleNamespace(
        id=user_id,
        username=username,
        is_active=is_active,
    )


def create_mock_db(user=None):
    """Configure a mock database query to return the specified user."""

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = user

    return mock_db


def test_get_current_user_valid_token(monkeypatch):
    """A valid token for an active user returns that user."""

    user = create_test_user()
    mock_db = create_mock_db(user)

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        lambda token: {"sub": str(user.id)},
    )

    result = get_current_user(
        credentials=create_credentials(),
        db=mock_db,
    )

    assert result is user
    assert result.id == 1
    assert result.username == "auth_test_user"
    assert result.is_active is True


def test_get_current_user_missing_credentials():
    """Missing Bearer credentials return 401."""

    mock_db = create_mock_db()

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=None,
            db=mock_db,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == (
        "Invalid or missing authentication token."
    )
    assert exc_info.value.headers["WWW-Authenticate"] == "Bearer"

    mock_db.query.assert_not_called()


def test_get_current_user_invalid_token(monkeypatch):
    """An invalid JWT returns 401."""

    mock_db = create_mock_db()

    def raise_invalid_token(token):
        raise jwt.InvalidTokenError("Invalid token")

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        raise_invalid_token,
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=create_credentials("invalid-token"),
            db=mock_db,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == (
        "Invalid or missing authentication token."
    )

    mock_db.query.assert_not_called()


def test_get_current_user_missing_subject(monkeypatch):
    """A JWT without a subject claim returns 401."""

    mock_db = create_mock_db()

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        lambda token: {},
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=create_credentials(),
            db=mock_db,
        )

    assert exc_info.value.status_code == 401
    mock_db.query.assert_not_called()


@pytest.mark.parametrize(
    "subject",
    ["not-an-integer", "", None],
)
def test_get_current_user_invalid_subject(monkeypatch, subject):
    """A missing or non-integer user ID returns 401."""

    mock_db = create_mock_db()

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        lambda token: {"sub": subject},
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=create_credentials(),
            db=mock_db,
        )

    assert exc_info.value.status_code == 401
    mock_db.query.assert_not_called()


def test_get_current_user_nonexistent_user(monkeypatch):
    """A valid token referencing a nonexistent user returns 401."""

    mock_db = create_mock_db(user=None)

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        lambda token: {"sub": "999999"},
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=create_credentials(),
            db=mock_db,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == (
        "Invalid or missing authentication token."
    )


def test_get_current_user_inactive_user(monkeypatch):
    """An inactive account is rejected with 403."""

    user = create_test_user(is_active=False)
    mock_db = create_mock_db(user)

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        lambda token: {"sub": str(user.id)},
    )

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=create_credentials(),
            db=mock_db,
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "User account is inactive."


def test_get_current_user_queries_user_by_id(monkeypatch):
    """The database lookup uses the ID from the JWT subject."""

    user = create_test_user(user_id=42)
    mock_db = create_mock_db(user)

    monkeypatch.setattr(
        "app.core.dependencies.decode_access_token",
        lambda token: {"sub": "42"},
    )

    result = get_current_user(
        credentials=create_credentials(),
        db=mock_db,
    )

    assert result.id == 42
    mock_db.query.assert_called_once_with(User)
    mock_db.query.return_value.filter.assert_called_once()
    mock_db.query.return_value.filter.return_value.first.assert_called_once()


def test_get_current_user_malformed_token():
    """A malformed JWT returns 401 without querying the database."""

    mock_db = create_mock_db()

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(
            credentials=create_credentials("not.a.valid.jwt"),
            db=mock_db,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == (
        "Invalid or missing authentication token."
    )
    assert exc_info.value.headers["WWW-Authenticate"] == "Bearer"

    mock_db.query.assert_not_called()

