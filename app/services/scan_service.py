
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import Scan
from app.schemas.scan import ScanCreate, ScanUpdate


ALLOWED_TRANSITIONS = {
    "pending": {"running"},
    "running": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
}

VALID_STATUSES = set(ALLOWED_TRANSITIONS)


def utc_now():
    return datetime.now(timezone.utc)


def normalize_status(value: str) -> str:
    return value.strip().lower()


def validate_status_transition(
    current_status: str,
    new_status: str,
):
    current = normalize_status(current_status)
    new = normalize_status(new_status)

    if current not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Current scan status '{current_status}' is invalid.",
        )

    if new not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Invalid scan status '{new_status}'. "
                f"Allowed statuses: {', '.join(sorted(VALID_STATUSES))}."
            ),
        )

    if current == new:
        return

    if new not in ALLOWED_TRANSITIONS[current]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Scan cannot transition from '{current}' to '{new}'."
            ),
        )


def create_scan(
    db: Session,
    scan_data: ScanCreate,
):
    data = scan_data.model_dump()

    requested_status = normalize_status(data.get("status") or "pending")

    if requested_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A new scan must start with pending status.",
        )

    data["status"] = "pending"
    data["started_at"] = None
    data["completed_at"] = None

    scan = Scan(**data)

    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except Exception:
        db.rollback()
        raise

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
    update_data = scan_data.model_dump(exclude_unset=True)

    current_status = normalize_status(scan.status)
    new_status = current_status

    if "status" in update_data:
        if update_data["status"] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Scan status cannot be null.",
            )

        new_status = normalize_status(update_data["status"])
        validate_status_transition(current_status, new_status)

    # Lifecycle timestamps are managed by the service.
    # Clients cannot directly set or clear them.
    if "started_at" in update_data or "completed_at" in update_data:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "started_at and completed_at are managed "
                "automatically by scan status transitions."
            ),
        )

    update_data.pop("started_at", None)
    update_data.pop("completed_at", None)

    now = utc_now()

    if current_status == "pending" and new_status == "running":
        scan.started_at = now
        scan.completed_at = None

    elif current_status == "running" and new_status in {"completed", "failed"}:
        if scan.started_at is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A running scan must have a started_at timestamp.",
            )

        scan.completed_at = now

    if "status" in update_data:
        update_data["status"] = new_status

    for field, value in update_data.items():
        setattr(scan, field, value)

    try:
        db.commit()
        db.refresh(scan)
    except Exception:
        db.rollback()
        raise

    return scan


def delete_scan(
    db: Session,
    scan: Scan,
):
    try:
        db.delete(scan)
        db.commit()
    except Exception:
        db.rollback()
        raise
