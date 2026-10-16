from sqlalchemy.orm import Session

from app.models import Role
from app.schemas.role import RoleCreate, RoleUpdate


def create_role(db: Session, role_data: RoleCreate):
    role = Role(
        name=role_data.name,
        description=role_data.description,
    )

    db.add(role)
    db.commit()
    db.refresh(role)

    return role


def get_roles(db: Session):
    return db.query(Role).order_by(Role.id).all()


def get_role(db: Session, role_id: int):
    return db.query(Role).filter(Role.id == role_id).first()


def update_role(
    db: Session,
    role: Role,
    role_data: RoleUpdate,
):
    if role_data.name is not None:
        role.name = role_data.name

    if role_data.description is not None:
        role.description = role_data.description

    db.commit()
    db.refresh(role)

    return role


def delete_role(db: Session, role: Role):
    db.delete(role)
    db.commit()