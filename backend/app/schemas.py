from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
TargetStatusT = Literal["ACTIVE", "PAUSED", "ARCHIVED"]
VulnStatusT = Literal["OPEN", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"]


# ---------- Targets ----------
class TargetCreate(BaseModel):
    """Provide one of: `url`, `urls`, or `text` (newline/CSV bulk). All accept optional tags."""

    url: str | None = Field(default=None, examples=["https://app.example.com"])
    urls: list[str] = Field(default_factory=list)
    text: str | None = Field(default=None, description="Newline or CSV list: `url[,tag1;tag2]`")
    tags: list[str] = Field(default_factory=list, examples=[["prod", "middleware"]])
    notes: str | None = None


class TargetUpdate(BaseModel):
    url: str | None = None
    status: TargetStatusT | None = None
    tags: list[str] | None = None
    notes: str | None = None


class VulnCounts(BaseModel):
    open: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TargetOut(BaseModel):
    id: int
    url: str
    host: str
    domain_root: str
    tags: list[str]
    status: TargetStatusT
    notes: str | None
    created_at: datetime
    updated_at: datetime
    last_scanned_at: datetime | None
    last_scan_status: str | None
    risk: Literal["critical", "high", "medium", "low", "none"]
    vuln_counts: VulnCounts
    # Reachability from the pre-scan probe, and the result of the last completed scan.
    reachability: str = "UNKNOWN"
    last_probe_error: str | None = None
    consecutive_probe_failures: int = 0
    last_result: str | None = None  # CLEAN | VULNERABLE | None (never scanned)
    last_open_findings: int = 0


class TargetPage(BaseModel):
    items: list[TargetOut]
    total: int
    page: int
    page_size: int


class BulkImportError(BaseModel):
    input: str
    error: str


class BulkImportResult(BaseModel):
    created: list[TargetOut]
    skipped_duplicates: list[str]
    invalid: list[BulkImportError]


class DomainGroup(BaseModel):
    domain_root: str
    count: int


# ---------- Scans ----------
class ScanTrigger(BaseModel):
    scope: Literal["all", "target", "targets"] = "all"
    target_id: int | None = None
    target_ids: list[int] | None = Field(default=None, description="Required for scope=targets.")
    cve_years: Literal[1, 2, 3, 5, 10] | None = Field(
        default=None, description="Only CVE templates from the latest N years. Omit for all years."
    )
    preset: Literal["quick", "medium3", "medium5", "full", "deep"] | None = Field(
        default=None, description="Named preset. Overrides cve_years, severities, and rate limit."
    )
    severities: list[Severity] | None = Field(
        default=None, description="Defaults to VMDR_NUCLEI_SEVERITIES (critical,high,medium)."
    )


class ScanRunOut(BaseModel):
    id: int
    scope: str
    target_id: int | None
    severities: str
    targets_scanned: int = 0
    chunks_total: int = 0
    chunks_done: int = 0
    cve_years: int | None = None
    preset: str | None = None
    rate_limit: int | None = None
    duration_seconds: float | None = None
    status: str
    requested_by: str
    targets_count: int
    unreachable_count: int = 0
    target_ids: list[int] | None = None
    cancel_requested: bool = False
    findings_count: int
    new_findings: int
    resolved_findings: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ActiveTarget(BaseModel):
    id: int
    url: str
    host: str
    reachability: str


class ReportOut(BaseModel):
    id: int
    run_id: int
    file_name: str
    size_bytes: int
    findings_count: int
    targets_count: int
    created_at: datetime


class LogOut(BaseModel):
    id: int
    run_id: int | None
    ts: datetime
    level: str
    message: str


class TemplateStatus(BaseModel):
    status: str
    updated_at: datetime | None
    error: str | None
    update_requested: bool


class ScanStatus(BaseModel):
    state: Literal["IDLE", "SCANNING", "UPDATING_TEMPLATES", "OFFLINE"]
    worker_online: bool
    heartbeat_at: datetime | None
    current_run: ScanRunOut | None
    # Targets the current run is scanning (or probing). Empty when idle.
    active_targets: list[ActiveTarget] = []
    # Every RUNNING scan. Up to VMDR_MAX_CONCURRENT_RUNS run at once, on disjoint targets.
    active_runs: list[ScanRunOut] = []
    # Server clock, so the UI can show an elapsed timer that is not skewed by the browser clock.
    server_time: datetime | None = None
    live_findings: int | None = None
    queue_length: int
    templates: TemplateStatus
    recent_runs: list[ScanRunOut]
    logs: list[LogOut]


# ---------- Vulnerabilities ----------
class VulnOut(BaseModel):
    id: int
    fingerprint: str
    target_id: int
    target_url: str
    domain_root: str
    template_id: str
    cve_id: str | None
    name: str
    severity: str
    cvss_score: float | None
    matched_at: str
    matcher_name: str | None
    curl_command: str | None
    description: str | None
    remediation: str | None
    request: str | None
    response: str | None
    tags: list[str]
    status: VulnStatusT
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    missed_scans: int


class VulnPage(BaseModel):
    items: list[VulnOut]
    total: int
    page: int
    page_size: int


class VulnUpdate(BaseModel):
    status: VulnStatusT


# ---------- Stats ----------
class DayBucket(BaseModel):
    date: str
    new_findings: int
    critical_high: int


class StatsOut(BaseModel):
    total_monitored_endpoints: int
    active_targets: int
    paused_targets: int
    archived_targets: int
    active_critical: int
    active_high: int
    severity_distribution: dict[str, int]
    scans_run_last_24h: int
    new_findings_last_24h: int
    new_findings_previous_24h: int
    spike: bool
    mttr_hours: float | None
    last_7_days: list[DayBucket]
    scanner: ScanStatus


# ---------- Webhooks ----------
class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["slack", "teams", "generic"] = "generic"
    url: str
    min_severity: Literal["critical", "high", "medium", "low"] = "high"
    enabled: bool = True


class WebhookOut(WebhookCreate):
    id: int
