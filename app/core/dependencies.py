
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.services.auth_service import decode_access_token

from app.core.roles import ADMINISTRATOR, SECURITY_ANALYST, VIEWER

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate a JWT bearer token and return the authenticated user."""

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized

    try:
        payload = decode_access_token(credentials.credentials)
        subject = payload.get("sub")

        if not subject:
            raise unauthorized

        user_id = int(subject)

    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise unauthorized

    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise unauthorized

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
        )

    return user



def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Allow access only to Administrators."""

    if current_user.role.name != ADMINISTRATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required.",
        )

    return current_user


def require_security_analyst(
    current_user: User = Depends(get_current_user),
) -> User:
    """Allow Administrators and Security Analysts."""

    if current_user.role.name not in (
        ADMINISTRATOR,
        SECURITY_ANALYST,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator or Security Analyst role required.",
        )

    return current_user


def require_viewer(
    current_user: User = Depends(get_current_user),
) -> User:
    """Allow all three defined roles to read permitted resources."""

    if current_user.role.name not in (
        ADMINISTRATOR,
        SECURITY_ANALYST,
        VIEWER,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Valid user role required.",
        )

    return current_user
