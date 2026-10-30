from datetime import UTC, datetime

from sqlalchemy import JSON, Column, Text
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite does not store tzinfo)."""
    return datetime.now(UTC).replace(tzinfo=None)


class TargetStatus:
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


class VulnStatus:
    OPEN = "OPEN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    RESOLVED = "RESOLVED"


class RunStatus:
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RunScope:
    ALL = "ALL"
    TARGET = "TARGET"
    TARGETS = "TARGETS"  # an explicit list of targets, stored in ScanRun.target_ids


class WorkerStatus:
    IDLE = "IDLE"
    SCANNING = "SCANNING"
    UPDATING_TEMPLATES = "UPDATING_TEMPLATES"


class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: int | None = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True, max_length=512)
    host: str = Field(index=True, max_length=255)
    domain_root: str = Field(index=True, max_length=255)
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    status: str = Field(default=TargetStatus.ACTIVE, index=True, max_length=16)
    notes: str | None = Field(default=None, max_length=1000)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_scanned_at: datetime | None = None
    last_scan_status: str | None = Field(default=None, max_length=16)
    # Pre-scan reachability probe. UNREACHABLE targets are skipped by the scan and never auto-resolved.
    reachability: str = Field(default="UNKNOWN", max_length=16)
    consecutive_probe_failures: int = 0
    last_probed_at: datetime | None = None
    last_probe_error: str | None = Field(default=None, max_length=255)


class Vulnerability(SQLModel, table=True):
    __tablename__ = "vulnerabilities"

    id: int | None = Field(default=None, primary_key=True)
    # sha256(target_url | template_id | matcher_name): one row per finding per target.
    fingerprint: str = Field(unique=True, index=True, max_length=64)
    target_id: int = Field(index=True)
    target_url: str = Field(index=True, max_length=512)
    domain_root: str = Field(index=True, max_length=255)

    template_id: str = Field(index=True, max_length=255)
    cve_id: str | None = Field(default=None, index=True, max_length=32)
    name: str = Field(default="", max_length=512)
    severity: str = Field(index=True, max_length=16)
    cvss_score: float | None = None
    matched_at: str = Field(default="", max_length=1024)
    matcher_name: str | None = Field(default=None, max_length=255)
    curl_command: str | None = Field(default=None, sa_column=Column(Text))
    description: str | None = Field(default=None, sa_column=Column(Text))
    remediation: str | None = Field(default=None, sa_column=Column(Text))
    request: str | None = Field(default=None, sa_column=Column(Text))
    response: str | None = Field(default=None, sa_column=Column(Text))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))

    status: str = Field(default=VulnStatus.OPEN, index=True, max_length=20)
    first_seen_at: datetime = Field(default_factory=utcnow, index=True)
    last_seen_at: datetime = Field(default_factory=utcnow, index=True)
    resolved_at: datetime | None = None
    missed_scans: int = 0
    last_run_id: int | None = None


class ScanRun(SQLModel, table=True):
    __tablename__ = "scan_runs"

    id: int | None = Field(default=None, primary_key=True)
    scope: str = Field(default=RunScope.ALL, max_length=16)
    # Plain integer, not a FK, so historical runs survive a hard target delete.
    target_id: int | None = Field(default=None, index=True)
    severities: str = Field(default="critical,high,medium", max_length=128)
    status: str = Field(default=RunStatus.QUEUED, index=True, max_length=16)
    requested_by: str = Field(default="api", max_length=64)
    # Times this run has been started. Interrupted runs are re-queued until MAX_RUN_ATTEMPTS.
    attempts: int = 0
    # Explicit target selection for scope=TARGETS (e.g. a random sample).
    target_ids: list[int] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    # Set by the API on a RUNNING run; the worker stops Nuclei within one heartbeat slice.
    cancel_requested: bool = False
    targets_count: int = 0
    unreachable_count: int = 0
    findings_count: int = 0
    new_findings: int = 0
    resolved_findings: int = 0
    error: str | None = Field(default=None, sa_column=Column(Text))
    output_path: str | None = Field(default=None, max_length=1024)
    created_at: datetime = Field(default_factory=utcnow, index=True)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ScanLog(SQLModel, table=True):
    __tablename__ = "scan_logs"

    id: int | None = Field(default=None, primary_key=True)
    run_id: int | None = Field(default=None, index=True)
    ts: datetime = Field(default_factory=utcnow, index=True)
    level: str = Field(default="INFO", max_length=8)
    message: str = Field(sa_column=Column(Text))


class WorkerState(SQLModel, table=True):
    """Singleton row (id=1) written by the worker and read by the API."""

    __tablename__ = "worker_state"

    id: int = Field(default=1, primary_key=True)
    status: str = Field(default=WorkerStatus.IDLE, max_length=32)
    current_run_id: int | None = None
    heartbeat_at: datetime | None = None
    template_updated_at: datetime | None = None  # last *successful* update
    template_attempted_at: datetime | None = None  # last attempt, success or not (drives retry cadence)
    template_status: str = Field(default="never", max_length=16)
    template_error: str | None = Field(default=None, sa_column=Column(Text))
    template_update_requested: bool = False


class WebhookConfig(SQLModel, table=True):
    __tablename__ = "webhooks"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(max_length=128)
    kind: str = Field(default="generic", max_length=16)  # slack | teams | generic
    url: str = Field(sa_column=Column(Text))
    enabled: bool = True
    min_severity: str = Field(default="high", max_length=16)
    created_at: datetime = Field(default_factory=utcnow)
