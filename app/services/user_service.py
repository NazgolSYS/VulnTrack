
from sqlalchemy.orm import Session
from pwdlib import PasswordHash

from app.models import User
from app.schemas.user import UserCreate, UserUpdate
from app.services.auth_service import hash_password


password_hash = PasswordHash.recommended()


def create_user(db: Session, user_data: UserCreate):
    user = User(
        username=user_data.username,
        email=str(user_data.email),
        hashed_password=hash_password(user_data.password),
        role_id=user_data.role_id,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def get_users(db: Session):
    return db.query(User).order_by(User.id).all()


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def update_user(
    db: Session,
    user: User,
    user_data: UserUpdate,
):
    update_data = user_data.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        if field == "email" and value is not None:
            value = str(value)

        setattr(user, field, value)

    db.commit()
    db.refresh(user)

    return user


def delete_user(db: Session, user: User):
    db.delete(user)
    db.commit()
