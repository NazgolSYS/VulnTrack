from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.database import get_db
from app.main import app


@pytest.fixture
def client():
    mock_db = MagicMock()

    mock_user = SimpleNamespace(
        id=1,
        username="jwt_test_user",
        email="jwt_test_user@example.com",
        is_active=True,
        role_id=2,
        created_at=datetime.now(timezone.utc),
        role=SimpleNamespace(name="Administrator"),
    )

    mock_db.query.return_value.filter.return_value.first.return_value = (
        mock_user
    )
    mock_db.query.return_value.order_by.return_value.all.return_value = [
        mock_user
    ]

    app.dependency_overrides[get_db] = lambda: mock_db

    test_client = TestClient(app)
    test_client.mock_user = mock_user

    yield test_client

    app.dependency_overrides.clear()


def create_token(
    user_id="1",
    expires_delta=timedelta(minutes=5),
    secret_key=None,
):
    expire = datetime.now(timezone.utc) + expires_delta

    payload = {
        "sub": str(user_id),
        "username": "jwt_test_user",
        "role_id": 2,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        secret_key or settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


# ============================================================
# JWT Authentication Integration Tests
# ============================================================

def test_users_endpoint_accepts_valid_jwt(client):
    token = create_token()

    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_users_endpoint_rejects_missing_jwt(client):
    response = client.get("/users/")

    assert response.status_code == 401


def test_users_endpoint_rejects_invalid_jwt(client):
    response = client.get(
        "/users/",
        headers={"Authorization": "Bearer invalid.token.value"},
    )

    assert response.status_code == 401


def test_users_endpoint_rejects_expired_jwt(client):
    token = create_token(
        expires_delta=timedelta(seconds=-1),
    )

    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_users_endpoint_rejects_jwt_signed_with_wrong_secret(client):
    token = create_token(
        secret_key="definitely-not-the-configured-secret",
    )

    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


# ============================================================
# Role-Based Access Control (RBAC) Integration Tests
# ============================================================

def test_administrator_can_access_users_endpoint(client):
    token = create_token()

    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_security_analyst_cannot_access_users_endpoint(client):
    client.mock_user.role.name = "Security Analyst"

    token = create_token()

    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator role required."


def test_viewer_cannot_access_users_endpoint(client):
    client.mock_user.role.name = "Viewer"

    token = create_token()

    response = client.get(
        "/users/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator role required."
