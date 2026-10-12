
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    CheckConstraint,
)

from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role_id = Column(
        Integer,
        ForeignKey("roles.id"),
        nullable=False,
    )
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    name = Column(String(150), nullable=False)
    asset_type = Column(String(50), nullable=False)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    environment = Column(String(50), nullable=True)
    owner_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class Software(Base):
    __tablename__ = "software"

    __table_args__ = (
        UniqueConstraint(
            "name",
            "version",
            "vendor",
            name="uq_software_name_version_vendor",
        ),
    )

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    version = Column(String(100), nullable=False)
    vendor = Column(String(150), nullable=True)
    cpe = Column(String(255), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False,
    )
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    cve_id = Column(String(30), nullable=True, index=True)
    severity = Column(String(20), nullable=False)
    status = Column(
        String(30),
        default="open",
        nullable=False,
    )
    cvss_score = Column(Float, nullable=True)
    assigned_to = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    created_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    discovered_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    due_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id"),
        nullable=False,
    )
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(
        String(30),
        default="pending",
        nullable=False,
    )
    priority = Column(
        String(20),
        default="medium",
        nullable=False,
    )
    assigned_to = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    due_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    name = Column(String(150), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(
        String(30),
        default="pending",
        nullable=False,
    )
    started_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class AssetSoftware(Base):
    __tablename__ = "asset_software"

    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "software_id",
            name="uq_asset_software",
        ),
    )

    id = Column(Integer, primary_key=True)
    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False,
    )
    software_id = Column(
        Integer,
        ForeignKey("software.id"),
        nullable=False,
    )
    installed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_seen_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    action = Column(String(100), nullable=False)
    entity_type = Column(String(100), nullable=False)
    entity_id = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )


class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id"),
        nullable=False,
    )
    changed_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )
    old_status = Column(String(30), nullable=True)
    new_status = Column(String(30), nullable=False)
    comment = Column(Text, nullable=True)
    changed_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id"),
        nullable=True,
    )

    remediation_task_id = Column(
        Integer,
        ForeignKey("remediation_tasks.id"),
        nullable=True,
    )

    content = Column(Text, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False,
    )

    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False,
    )

    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id"),
        nullable=True,
    )

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    status = Column(
        String(30),
        default="open",
        nullable=False,
    )

    evidence = Column(Text, nullable=True)

    first_detected_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    last_detected_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    __table_args__ = (
        CheckConstraint(
            "likelihood BETWEEN 1 AND 5",
            name="ck_risk_likelihood_range",
        ),
        CheckConstraint(
            "impact BETWEEN 1 AND 5",
            name="ck_risk_impact_range",
        ),
        CheckConstraint(
            "risk_score = likelihood * impact",
            name="ck_risk_score_calculation",
        ),
        CheckConstraint(
            """
            (risk_score <= 4 AND risk_level = 'low')
            OR (risk_score > 4 AND risk_score <= 9
                AND risk_level = 'medium')
            OR (risk_score > 9 AND risk_score <= 15
                AND risk_level = 'high')
            OR (risk_score > 15 AND risk_score <= 25
                AND risk_level = 'critical')
            """,
            name="ck_risk_level_matches_score",
        ),
    )

    id = Column(Integer, primary_key=True)

    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id"),
        nullable=False,
    )

    assessed_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )

    likelihood = Column(Integer, nullable=False)
    impact = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=False)

    risk_level = Column(
        String(20),
        nullable=False,
    )

    justification = Column(Text, nullable=True)
    mitigation_recommendation = Column(Text, nullable=True)

    assessed_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

