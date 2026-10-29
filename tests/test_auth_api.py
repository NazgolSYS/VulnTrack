
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import app
from app.routers import auth as auth_router


@pytest.fixture
def client(monkeypatch):
    """Create a test client with a mocked database."""

    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db

    yield TestClient(app)

    app.dependency_overrides.clear()


def configure_mock_user(mock_db, user):
    """Configure the mocked database to return a specific user."""

    mock_db.query.return_value.filter.return_value.first.return_value = user


def make_test_user(
    username="test_user",
    password_hash="test_password_hash",
    is_active=True,
):
    """Create a mock user for login tests."""

    return SimpleNamespace(
        id=1,
        username=username,
        hashed_password=password_hash,
        is_active=is_active,
        role_id=2,
    )


def test_login_success(client, monkeypatch):
    """Valid credentials return a bearer access token."""

    mock_user = make_test_user()
    configure_mock_user(
        client.app.dependency_overrides[get_db](),
        mock_user,
    )

    monkeypatch.setattr(
        auth_router,
        "verify_password",
        lambda password, hashed_password: True,
    )
    monkeypatch.setattr(
        auth_router,
        "create_access_token",
        lambda user_id, username, role_id: "test-access-token",
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "test_user",
            "password": "correct-password",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "test-access-token",
        "token_type": "bearer",
    }


def test_login_unknown_username(client):
    """Unknown usernames receive a generic authentication error."""

    mock_db = client.app.dependency_overrides[get_db]()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    response = client.post(
        "/auth/login",
        json={
            "username": "unknown_user",
            "password": "any-password",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid username or password."
    )


def test_login_incorrect_password(client, monkeypatch):
    """Incorrect passwords receive a generic authentication error."""

    mock_db = client.app.dependency_overrides[get_db]()
    configure_mock_user(mock_db, make_test_user())

    monkeypatch.setattr(
        auth_router,
        "verify_password",
        lambda password, hashed_password: False,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "test_user",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid username or password."
    )


def test_login_inactive_user(client, monkeypatch):
    """Inactive accounts are rejected before password verification."""

    mock_db = client.app.dependency_overrides[get_db]()
    configure_mock_user(
        mock_db,
        make_test_user(is_active=False),
    )

    verify_password_mock = MagicMock(return_value=True)
    monkeypatch.setattr(
        auth_router,
        "verify_password",
        verify_password_mock,
    )

    response = client.post(
        "/auth/login",
        json={
            "username": "test_user",
            "password": "correct-password",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "User account is inactive."
    )
    verify_password_mock.assert_not_called()

