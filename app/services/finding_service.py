from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app import models
from app.schemas.finding import FindingCreate, FindingUpdate
from app.schemas.finding_vulnerability import FindingVulnerabilityLink


def validate_finding_references(
    db: Session,
    scan_id: int,
    asset_id: int,
    vulnerability_id: int | None,
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id)
        .first()
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    asset = (
        db.query(models.Asset)
        .filter(models.Asset.id == asset_id)
        .first()
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found.",
        )

    if vulnerability_id is not None:
        vulnerability = (
            db.query(models.Vulnerability)
            .filter(
                models.Vulnerability.id == vulnerability_id
            )
            .first()
        )
        if vulnerability is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vulnerability not found.",
            )


def create_finding(
    db: Session,
    finding_data: FindingCreate,
):
    validate_finding_references(
        db=db,
        scan_id=finding_data.scan_id,
        asset_id=finding_data.asset_id,
        vulnerability_id=finding_data.vulnerability_id,
    )

    finding = models.Finding(**finding_data.model_dump())

    try:
        db.add(finding)
        db.commit()
        db.refresh(finding)
    except Exception:
        db.rollback()
        raise

    return finding


def get_finding(db: Session, finding_id: int):
    finding = (
        db.query(models.Finding)
        .filter(models.Finding.id == finding_id)
        .first()
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    return finding


def get_all_findings(
    db: Session,
    skip: int = 0,
    limit: int = 100,
):
    return (
        db.query(models.Finding)
        .order_by(models.Finding.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_findings_for_scan(
    db: Session,
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id)
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return (
        db.query(models.Finding)
        .filter(models.Finding.scan_id == scan_id)
        .order_by(models.Finding.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_findings_for_asset(
    db: Session,
    asset_id: int,
    skip: int = 0,
    limit: int = 100,
):
    asset = (
        db.query(models.Asset)
        .filter(models.Asset.id == asset_id)
        .first()
    )

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found.",
        )

    return (
        db.query(models.Finding)
        .filter(models.Finding.asset_id == asset_id)
        .order_by(models.Finding.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_finding(
    db: Session,
    finding_id: int,
    finding_data: FindingUpdate,
):
    finding = get_finding(db, finding_id)
    changes = finding_data.model_dump(exclude_unset=True)

    # A supplied null value is allowed only for the optional vulnerability link.
    if "scan_id" in changes and changes["scan_id"] is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="scan_id cannot be null.",
        )

    if "asset_id" in changes and changes["asset_id"] is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="asset_id cannot be null.",
        )

    if "vulnerability_id" in changes:
        vulnerability_id = changes["vulnerability_id"]
    else:
        vulnerability_id = finding.vulnerability_id

    scan_id = changes.get("scan_id", finding.scan_id)
    asset_id = changes.get("asset_id", finding.asset_id)

    validate_finding_references(
        db=db,
        scan_id=scan_id,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
    )

    for field, value in changes.items():
        setattr(finding, field, value)

    try:
        db.commit()
        db.refresh(finding)
    except Exception:
        db.rollback()
        raise

    return finding


def link_finding_to_vulnerability(
    db: Session,
    finding_id: int,
    link_data: FindingVulnerabilityLink,
):
    # Find the finding
    finding = (
        db.query(models.Finding)
        .filter(models.Finding.id == finding_id)
        .first()
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    # Find the vulnerability
    vulnerability = (
        db.query(models.Vulnerability)
        .filter(
            models.Vulnerability.id
            == link_data.vulnerability_id
        )
        .first()
    )

    if vulnerability is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found.",
        )

    # Make sure the finding and vulnerability
    # belong to the same asset.
    if vulnerability.asset_id != finding.asset_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "The vulnerability does not belong to "
                "the same asset as the finding."
            ),
        )

    # Check whether it is already linked.
    if finding.vulnerability_id == vulnerability.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Finding is already linked to this vulnerability.",
        )

    try:
        finding.vulnerability_id = vulnerability.id

        db.commit()
        db.refresh(finding)

    except Exception:
        db.rollback()
        raise

    return finding
