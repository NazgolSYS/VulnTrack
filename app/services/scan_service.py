from sqlalchemy.orm import Session

from app.models import Scan
from app.schemas.scan import ScanCreate, ScanUpdate


def create_scan(
    db: Session,
    scan_data: ScanCreate,
):
    scan = Scan(
        **scan_data.model_dump()
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def get_scans(db: Session):
    return (
        db.query(Scan)
        .order_by(Scan.id)
        .all()
    )


def get_scan(
    db: Session,
    scan_id: int,
):
    return (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )


def update_scan(
    db: Session,
    scan: Scan,
    scan_data: ScanUpdate,
):
    update_data = scan_data.model_dump(
        exclude_unset=True
    )

    for field, value in update_data.items():
        setattr(scan, field, value)

    db.commit()
    db.refresh(scan)

    return scan


def delete_scan(
    db: Session,
    scan: Scan,
):
    db.delete(scan)
    db.commit()
    