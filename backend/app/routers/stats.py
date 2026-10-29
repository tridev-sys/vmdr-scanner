from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlmodel import Session, func, select

from app.db import get_session
from app.models import RunStatus, ScanRun, Target, TargetStatus, Vulnerability, VulnStatus, utcnow
from app.schemas import DayBucket, StatsOut
from app.services.status import get_scan_status

router = APIRouter(prefix="/stats", tags=["stats"])
SPIKE_MIN_FINDINGS = 5
SPIKE_MULTIPLIER = 2


@router.get("", response_model=StatsOut)
def get_stats(session: Session = Depends(get_session)) -> StatsOut:
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    two_days_ago = now - timedelta(hours=48)

    def target_count(s: str | None = None) -> int:
        stmt = select(func.count(Target.id))
        stmt = stmt.where(Target.status == s) if s else stmt.where(Target.status != TargetStatus.ARCHIVED)
        return session.exec(stmt).one()

    open_rows = session.exec(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.status == VulnStatus.OPEN)
        .group_by(Vulnerability.severity)
    ).all()
    open_by_sev = Counter({sev: n for sev, n in open_rows})
    distribution = {k: open_by_sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")}

    scans_24h = session.exec(
        select(func.count(ScanRun.id)).where(ScanRun.created_at >= day_ago, ScanRun.status == RunStatus.COMPLETED)
    ).one()

    new_24h = session.exec(
        select(func.count(Vulnerability.id)).where(Vulnerability.first_seen_at >= day_ago)
    ).one()
    new_prev = session.exec(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.first_seen_at >= two_days_ago, Vulnerability.first_seen_at < day_ago
        )
    ).one()
    spike = new_24h >= SPIKE_MIN_FINDINGS and new_24h >= SPIKE_MULTIPLIER * max(new_prev, 1)

    resolved_recent = session.exec(select(Vulnerability).where(
        Vulnerability.status == VulnStatus.RESOLVED,
        Vulnerability.resolved_at.is_not(None),
        Vulnerability.resolved_at >= now - timedelta(days=90),
    )).all()
    mttr_hours = None
    if resolved_recent:
        total = sum((v.resolved_at - v.first_seen_at).total_seconds() for v in resolved_recent)
        mttr_hours = round(total / len(resolved_recent) / 3600, 1)

    # 7-day daily buckets for the trend sparkline.
    week = session.exec(select(Vulnerability.first_seen_at, Vulnerability.severity).where(
        Vulnerability.first_seen_at >= now - timedelta(days=7)
    )).all()
    buckets: dict[str, DayBucket] = {}
    for i in range(7, -1, -1):
        day = (now - timedelta(days=i)).date().isoformat()
        buckets[day] = DayBucket(date=day, new_findings=0, critical_high=0)
    for first_seen, severity in week:
        key = first_seen.date().isoformat()
        if key in buckets:
            buckets[key].new_findings += 1
            if severity in ("critical", "high"):
                buckets[key].critical_high += 1

    return StatsOut(
        total_monitored_endpoints=target_count(),
        active_targets=target_count(TargetStatus.ACTIVE),
        paused_targets=target_count(TargetStatus.PAUSED),
        archived_targets=target_count(TargetStatus.ARCHIVED),
        active_critical=distribution["critical"],
        active_high=distribution["high"],
        severity_distribution=distribution,
        scans_run_last_24h=scans_24h,
        new_findings_last_24h=new_24h,
        new_findings_previous_24h=new_prev,
        spike=spike,
        mttr_hours=mttr_hours,
        last_7_days=list(buckets.values()),
        scanner=get_scan_status(session, log_limit=20),
    )
