from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.finding import (
    FindingCreate,
    FindingResponse,
    FindingUpdate,
)
from app.services import finding_service
from app.schemas.finding_vulnerability import FindingVulnerabilityLink


router = APIRouter(
    prefix="/findings",
    tags=["Findings"],
)


@router.post(
    "/",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    finding_data: FindingCreate,
    db: Session = Depends(get_db),
):
    return finding_service.create_finding(db, finding_data)


@router.get(
    "/",
    response_model=list[FindingResponse],
)
def read_all_findings(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return finding_service.get_all_findings(db, skip, limit)


@router.get(
    "/scan/{scan_id}",
    response_model=list[FindingResponse],
)
def read_findings_for_scan(
    scan_id: int,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return finding_service.get_findings_for_scan(
        db,
        scan_id,
        skip,
        limit,
    )


@router.get(
    "/asset/{asset_id}",
    response_model=list[FindingResponse],
)
def read_findings_for_asset(
    asset_id: int,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return finding_service.get_findings_for_asset(
        db,
        asset_id,
        skip,
        limit,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def read_finding(
    finding_id: int,
    db: Session = Depends(get_db),
):
    return finding_service.get_finding(db, finding_id)


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
)
def edit_finding(
    finding_id: int,
    finding_data: FindingUpdate,
    db: Session = Depends(get_db),
):
    return finding_service.update_finding(
        db,
        finding_id,
        finding_data,
    )


@router.patch(
    "/{finding_id}/link-vulnerability",
    response_model=FindingResponse,
)
def link_finding_to_vulnerability(
    finding_id: int,
    link_data: FindingVulnerabilityLink,
    db: Session = Depends(get_db),
):
    return finding_service.link_finding_to_vulnerability(
        db,
        finding_id,
        link_data,
    )
