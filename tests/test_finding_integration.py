import pytest

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from app import models
from app.schemas.finding import FindingCreate
from app.services import finding_service
from app.services.finding_service import (
    extract_cve_id,
    integrate_finding_with_vulnerability,
)


def test_extract_cve_id_from_title():
    finding = FindingCreate(
        scan_id=1,
        asset_id=1,
        title="CVE-2021-44228: Log4Shell vulnerability",
        severity="critical",
    )

    assert extract_cve_id(finding) == "CVE-2021-44228"


def test_extract_cve_id_from_description():
    finding = FindingCreate(
        scan_id=1,
        asset_id=1,
        title="Remote code execution vulnerability",
        description="Affected software contains cve-2023-12345.",
        severity="high",
    )

    assert extract_cve_id(finding) == "CVE-2023-12345"


def test_extract_cve_id_from_evidence():
    finding = FindingCreate(
        scan_id=1,
        asset_id=1,
        title="Outdated software detected",
        evidence="Scanner reference: CVE-2022-123456",
        severity="medium",
    )

    assert extract_cve_id(finding) == "CVE-2022-123456"


def test_extract_cve_id_returns_none_when_missing():
    finding = FindingCreate(
        scan_id=1,
        asset_id=1,
        title="Unidentified software vulnerability",
        description="The software may have an insecure configuration.",
        severity="medium",
    )

    assert extract_cve_id(finding) is None


def test_existing_resolved_vulnerability_is_reused_and_reopened():
    db = MagicMock()

    detected_at = datetime(2026, 10, 26, tzinfo=timezone.utc)

    existing_vulnerability = SimpleNamespace(
        id=10,
        asset_id=1,
        cve_id="CVE-2021-44228",
        status="resolved",
        discovered_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    db.query.return_value.filter.return_value.first.return_value = (
        existing_vulnerability
    )

    finding = SimpleNamespace(
        scan_id=5,
        asset_id=1,
        vulnerability_id=None,
        title="CVE-2021-44228: Log4Shell vulnerability",
        description="A known vulnerability was detected.",
        severity="critical",
        status="open",
        evidence=None,
        first_detected_at=detected_at,
    )

    result = integrate_finding_with_vulnerability(db, finding)

    assert result is existing_vulnerability
    assert finding.vulnerability_id == 10
    assert existing_vulnerability.status == "open"
    assert existing_vulnerability.discovered_at == datetime(
        2025, 1, 1, tzinfo=timezone.utc
    )

    db.add.assert_called_once()

    history = db.add.call_args.args[0]

    assert isinstance(history, models.VulnerabilityHistory)
    assert history.vulnerability_id == 10
    assert history.changed_by is None
    assert history.old_status == "resolved"
    assert history.new_status == "open"
    assert (
        history.comment
        == "Automatically reopened because a new scan detected this vulnerability."
    )

    db.flush.assert_not_called()



def test_new_vulnerability_is_created_when_no_match_exists(monkeypatch):
    db = MagicMock()

    detected_at = datetime(2026, 10, 26, tzinfo=timezone.utc)

    new_vulnerability = SimpleNamespace(
        id=None,
        asset_id=1,
        title="CVE-2024-12345: Example vulnerability",
        description="A newly detected vulnerability.",
        cve_id="CVE-2024-12345",
        severity="high",
        status="open",
        discovered_at=detected_at,
    )

    db.query.return_value.filter.return_value.first.return_value = None

    def create_vulnerability(**kwargs):
        return SimpleNamespace(id=None, **kwargs)

    monkeypatch.setattr(
        models,
        "Vulnerability",
        type(
            "MockVulnerability",
            (),
            {
                "asset_id": MagicMock(),
                "cve_id": MagicMock(),
                "__new__": lambda cls, **kwargs: create_vulnerability(**kwargs),
            },
        ),
    )

    def assign_id_on_flush():
        # The mock database assigns an ID when the new object is flushed.
        added_object = db.add.call_args.args[0]
        added_object.id = 20

    db.flush.side_effect = assign_id_on_flush

    finding = SimpleNamespace(
        scan_id=6,
        asset_id=1,
        vulnerability_id=None,
        title="CVE-2024-12345: Example vulnerability",
        description="A newly detected vulnerability.",
        severity="high",
        status="open",
        evidence=None,
        first_detected_at=detected_at,
    )

    result = integrate_finding_with_vulnerability(db, finding)

    assert result.id == 20
    assert finding.vulnerability_id == 20
    assert result.cve_id == "CVE-2024-12345"
    assert result.status == "open"
    db.add.assert_called_once()
    db.flush.assert_called_once()


def test_create_finding_integrates_and_commits(monkeypatch):
    db = MagicMock()

    monkeypatch.setattr(
        finding_service,
        "validate_finding_references",
        lambda **kwargs: None,
    )

    def fake_integrate(db, finding):
        finding.vulnerability_id = 99
        return SimpleNamespace(id=99, asset_id=finding.asset_id)

    monkeypatch.setattr(
        finding_service,
        "integrate_finding_with_vulnerability",
        fake_integrate,
    )

    finding_data = FindingCreate(
        scan_id=5,
        asset_id=1,
        title="CVE-2024-12345: Example vulnerability",
        description="Detected during a security scan.",
        severity="high",
        evidence="CVE-2024-12345",
    )

    result = finding_service.create_finding(db, finding_data)

    assert result.scan_id == 5
    assert result.asset_id == 1
    assert result.vulnerability_id == 99

    db.add.assert_called_once_with(result)
    db.flush.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(result)
    db.rollback.assert_not_called()


def test_create_finding_rolls_back_when_integration_fails(
    monkeypatch,
):
    db = MagicMock()

    monkeypatch.setattr(
        finding_service,
        "validate_finding_references",
        lambda **kwargs: None,
    )

    def failing_integration(db, finding):
        raise RuntimeError(
            "Vulnerability integration failed."
        )

    monkeypatch.setattr(
        finding_service,
        "integrate_finding_with_vulnerability",
        failing_integration,
    )

    finding_data = FindingCreate(
        scan_id=5,
        asset_id=1,
        title="CVE-2024-12345: Example vulnerability",
        description="Detected during a security scan.",
        severity="high",
        evidence="CVE-2024-12345",
    )

    with pytest.raises(
        RuntimeError,
        match="Vulnerability integration failed.",
    ):
        finding_service.create_finding(
            db,
            finding_data,
        )

    db.add.assert_called_once()
    db.flush.assert_called_once()
    db.rollback.assert_called_once()
    db.commit.assert_not_called()
    db.refresh.assert_not_called()


def test_create_finding_reopens_explicitly_linked_resolved_vulnerability(
    monkeypatch,
):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from app.schemas.finding import FindingCreate
    from app.services import finding_service

    mock_db = MagicMock()
    original_discovery = datetime(2025, 1, 1, tzinfo=timezone.utc)
    new_detection = datetime(2026, 1, 1, tzinfo=timezone.utc)

    existing_vulnerability = SimpleNamespace(
        id=10,
        asset_id=1,
        status="resolved",
        discovered_at=original_discovery,
    )

    # validate_finding_references performs its own checks.
    # Isolate this test to focus on the explicit-link behavior.
    monkeypatch.setattr(
        finding_service,
        "validate_finding_references",
        lambda **kwargs: None,
    )

    # The first query below finds the explicitly linked vulnerability.
    mock_db.query.return_value.filter.return_value.first.return_value = (
        existing_vulnerability
    )

    finding_data = FindingCreate(
        scan_id=1,
        asset_id=1,
        vulnerability_id=10,
        title="Previously resolved vulnerability",
        description="Detected again",
        severity="High",
        status="open",
    )

    def fake_add(finding):
        finding.id = 20
        finding.first_detected_at = new_detection
        finding.last_detected_at = new_detection
        finding.created_at = new_detection

    mock_db.add.side_effect = fake_add

    result = finding_service.create_finding(mock_db, finding_data)

    assert result.vulnerability_id == 10
    assert existing_vulnerability.status == "open"
    assert existing_vulnerability.discovered_at == original_discovery
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()
    mock_db.rollback.assert_not_called()
