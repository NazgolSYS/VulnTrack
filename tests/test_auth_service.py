from app.services.auth_service import (
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
    