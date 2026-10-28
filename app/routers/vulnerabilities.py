
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, User, Vulnerability
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from app.services import (
    vulnerability_service, 
    vulnerability_priority_service,
    audit_log_service,
)    
from app.schemas.vulnerability_status import (
    VulnerabilityStatusChange
)

from app.schemas.vulnerability_priority import (
    PrioritizedVulnerabilityResponse,
)
from app.core.dependencies import get_current_user, require_security_analyst


router = APIRouter(
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"],
)


def validate_references(
    db: Session,
    asset_id: int,
    assigned_to: int | None,
    created_by: int | None = None,
):
    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found.",
        )

    for user_id in (assigned_to, created_by):
        if user_id is not None:
            user = db.query(User).filter(
                User.id == user_id
            ).first()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"User with ID {user_id} not found.",
                )


@router.post(
    "/",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_vulnerability(
    vulnerability_data: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    validate_references(
        db,
        vulnerability_data.asset_id,
        vulnerability_data.assigned_to,
        vulnerability_data.created_by,
    )

    try:
        vulnerability = vulnerability_service.create_vulnerability(
        db,
        vulnerability_data,
        commit=False,
        )

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action="created",
            entity_type="vulnerability",
            entity_id=vulnerability.id,
            details=f"Created vulnerability: {vulnerability.title}",
        )

        db.commit()

        return vulnerability

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vulnerability or audit log could not be created because of a database conflict.",
        )
    except Exception:
        db.rollback()
        raise


@router.get(
    "/",
    response_model=list[VulnerabilityResponse],
)
def get_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return vulnerability_service.get_vulnerabilities(db)


@router.get(
    "/prioritized",
    response_model=list[PrioritizedVulnerabilityResponse],
)
def get_prioritized_vulnerabilities(
    status_filter: str | None = Query(
        default=None,
        alias="status",
    ),
    risk_level: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        vulnerability_priority_service
        .get_prioritized_vulnerabilities(
            db,
            status=status_filter,
            risk_level=risk_level,
            severity=severity,
        )
    )


@router.get(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vulnerability = vulnerability_service.get_vulnerability(
        db,
        vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    return vulnerability


@router.put(
    "/{vulnerability_id}",
    response_model=VulnerabilityResponse,
)
def update_vulnerability(
    vulnerability_id: int,
    vulnerability_data: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    vulnerability = vulnerability_service.get_vulnerability(
        db,
        vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    update_data = vulnerability_data.model_dump(
        exclude_unset=True
    )

    if "status" in update_data:
        raise HTTPException(
            status_code=422,
            detail=(
                "Vulnerability status must be changed through "
                "PATCH /vulnerabilities/{vulnerability_id}/status."
            ),
        )

    asset_id = update_data.get(
        "asset_id",
        vulnerability.asset_id,
    )

    assigned_to = update_data.get(
        "assigned_to",
        vulnerability.assigned_to,
    )

    created_by = vulnerability.created_by

    validate_references(
        db,
        asset_id,
        assigned_to,
        created_by,
    )
    
    try:
        updated_vulnerability = vulnerability_service.update_vulnerability(
            db,
            vulnerability,
            vulnerability_data,
            commit=False,
        )

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action="updated",
            entity_type="vulnerability",
            entity_id=updated_vulnerability.id,
            details=f"Updated vulnerability: {updated_vulnerability.title}",
        )

        db.commit()

        return updated_vulnerability

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vulnerability or audit log could not be updated because of a database conflict.",
        )
    except Exception:
        db.rollback()
        raise


@router.delete(
    "/{vulnerability_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    vulnerability = vulnerability_service.get_vulnerability(
        db,
        vulnerability_id,
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )
    
    try:
        audit_details = f"Deleted vulnerability: {vulnerability.title}"
        vulnerability_id = vulnerability.id

        vulnerability_service.delete_vulnerability(
            db,
            vulnerability,
            commit=False,
        )

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action="deleted",
            entity_type="vulnerability",
            entity_id=vulnerability_id,
            details=audit_details,
        )

        db.commit()

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Vulnerability cannot be deleted because other records "
                "reference it, or an audit log could not be created."
            ),
        )
    except Exception:
        db.rollback()
        raise


@router.patch("/{vulnerability_id}/status", tags=["Vulnerabilities"])
def change_vulnerability_status(
    vulnerability_id: int,
    change_data: VulnerabilityStatusChange,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
):
    
    try:
        result = vulnerability_service.change_vulnerability_status(
            db=db,
            vulnerability_id=vulnerability_id,
            change_data=change_data,
            changed_by=current_user.id,
            commit=False,
        )

        vulnerability = result["vulnerability"]
        history = result["history"]

        audit_log_service.record_audit_event(
            db,
            user_id=current_user.id,
            action="status_changed",
            entity_type="vulnerability",
            entity_id=vulnerability.id,
            details=(
                f"Vulnerability status changed from "
                f"{history.old_status} to {history.new_status}"
            ),
        )

        db.commit()
        return result

    except Exception:
        db.rollback()
        raise



