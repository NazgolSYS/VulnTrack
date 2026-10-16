from sqlalchemy.orm import Session

from app.models import Software
from app.schemas.software import SoftwareCreate, SoftwareUpdate


def create_software(db: Session, software_data: SoftwareCreate):
    software = Software(**software_data.model_dump())

    db.add(software)
    db.commit()
    db.refresh(software)

    return software


def get_software_list(db: Session):
    return db.query(Software).order_by(Software.id).all()


def get_software(db: Session, software_id: int):
    return (
        db.query(Software)
        .filter(Software.id == software_id)
        .first()
    )


def update_software(
    db: Session,
    software: Software,
    software_data: SoftwareUpdate,
):
    update_data = software_data.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(software, field, value)

    db.commit()
    db.refresh(software)

    return software


def delete_software(db: Session, software: Software):
    db.delete(software)
    db.commit()
    