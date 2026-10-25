
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.core.roles import ADMINISTRATOR, SECURITY_ANALYST, VIEWER
from app.core.dependencies import get_current_user
from app.services import asset_service, user_service


@pytest.fixture
def client(monkeypatch):
    """Create a test client without accessing the real database."""

    mock_db = MagicMock()

    app.dependency_overrides[get_db] = lambda: mock_db

    # Keep the application dependencies isolated between tests.
    yield TestClient(app)

    app.dependency_overrides.clear()


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
