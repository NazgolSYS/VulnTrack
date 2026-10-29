
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.services.auth_service import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_hash_password():
    password = "AdminDemo123!"

    hashed_password = hash_password(password)

    assert hashed_password != password
    assert hashed_password.startswith("$argon2id$")


def test_verify_correct_password():
    password = "AdminDemo123!"

    hashed_password = hash_password(password)

    assert verify_password(
        password,
        hashed_password,
    )


def test_verify_incorrect_password():
    password = "AdminDemo123!"
    wrong_password = "WrongPassword123!"

    hashed_password = hash_password(password)

    assert not verify_password(
        wrong_password,
        hashed_password,
    )


def test_decode_valid_access_token():
    token = create_access_token(
        user_id=1,
        username="auth_test_user",
        role_id=2,
    )

    payload = decode_access_token(token)

    assert payload["sub"] == "1"
    assert payload["username"] == "auth_test_user"
    assert payload["role_id"] == 2
    assert "exp" in payload


def test_decode_expired_token():
    expired_payload = {
        "sub": "1",
        "username": "auth_test_user",
        "role_id": 2,
        "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
    }

    token = jwt.encode(
        expired_payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_decode_token_with_invalid_signature():
    token = jwt.encode(
        {
            "sub": "1",
            "username": "auth_test_user",
            "role_id": 2,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        "a-different-test-secret-key-long-enough",
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token)


def test_decode_token_without_expiration():
    token = jwt.encode(
        {
            "sub": "1",
            "username": "auth_test_user",
            "role_id": 2,
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)


def test_decode_token_without_subject():
    token = jwt.encode(
        {
            "username": "auth_test_user",
            "role_id": 2,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)


def test_decode_token_with_unexpected_algorithm():
    """A token signed with an unconfigured algorithm is rejected."""

    token = jwt.encode(
        {
            "sub": "1",
            "username": "auth_test_user",
            "role_id": 2,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        "a-different-test-secret-key-long-enough-for-sha384",
        algorithm="HS384",
    )

    with pytest.raises(jwt.InvalidAlgorithmError):
        decode_access_token(token)


def test_decode_token_with_invalid_expiration():
    """A token with an invalid expiration claim is rejected."""

    token = jwt.encode(
        {
            "sub": "1",
            "username": "auth_test_user",
            "role_id": 2,
            "exp": "not-a-valid-timestamp",
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token)


def test_decode_token_with_non_string_subject():
    """A JWT with a non-string subject is rejected."""

    token = jwt.encode(
        {
            "sub": 1,
            "username": "auth_test_user",
            "role_id": 2,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token)


def test_settings_reject_missing_jwt_secret(monkeypatch):
    """JWT secret configuration is required when no secret is provided."""

    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    "expiration_minutes",
    [0, -1],
)
def test_settings_reject_nonpositive_token_expiration(
    expiration_minutes,
):
    """Token expiration must be a positive number of minutes."""

    with pytest.raises(ValidationError):
        Settings(
            jwt_secret_key="test-secret-key",
            access_token_expire_minutes=expiration_minutes,
            _env_file=None,
        )

