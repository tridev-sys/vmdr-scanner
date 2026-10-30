"""Rolling schedule: scan each ACTIVE target about once per cycle, in daily batches.

Instead of one ALL-scope run per day (which grows with the target list), each day enqueues a
TARGETS run holding at most ceil(active / cycle_days) of the targets that are due. Targets that
have never been scanned come first, then the least recently scanned, then by id.
"""

import math
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from app.config import get_settings
from app.models import RunScope, RunStatus, ScanRun, Target, TargetStatus
from app.services.concurrency import busy_target_ids, run_target_ids
from app.services.presets import PRESETS
from app.services.scanner import log_line


def _naive_utc(value: datetime) -> datetime:
    """SQLite stores naive UTC timestamps; normalise any aware input to that form."""
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def daily_quota(active_count: int, cycle_days: int) -> int:
    """Targets to scan per day so every active target is covered once per cycle."""
    if active_count <= 0:
        return 0
    return max(1, math.ceil(active_count / cycle_days))


def _covered_by_pending_runs(session: Session) -> set[int]:
    """Targets covered by a RUNNING run, or by a QUEUED run (not yet started)."""
    busy = busy_target_ids(session)
    for run in session.exec(select(ScanRun).where(ScanRun.status == RunStatus.QUEUED)).all():
        busy |= run_target_ids(session, run)
    return busy


def due_target_ids(
    session: Session, cycle_days: int, now: datetime, limit: int | None = None, field: str = "last_scanned_at",
) -> list[int]:
    """ACTIVE targets not covered within cycle_days (by `field`) and not in a queued or running run.

    `field` is last_scanned_at for quick and medium cycles, and last_deep_scanned_at for the deep cycle.
    Order: never covered first, then oldest, then id.
    """
    column = getattr(Target, field)
    cutoff = _naive_utc(now) - timedelta(days=cycle_days)
    query = (
        select(Target.id)
        .where(Target.status == TargetStatus.ACTIVE)
        .where((column.is_(None)) | (column < cutoff))
    )
    busy = _covered_by_pending_runs(session)
    if busy:
        query = query.where(Target.id.not_in(busy))
    query = query.order_by(
        column.is_(None).desc(),
        column.asc(),
        Target.id.asc(),
    )
    if limit is not None:
        query = query.limit(limit)
    return list(session.exec(query).all())


def enqueue_rolling_batch(
    session: Session, preset: str, cycle_days: int, now: datetime | None = None, field: str = "last_scanned_at",
) -> int | None:
    """Queue one TARGETS run with today's share of due targets. Returns the run id, or None if nothing is due."""
    if preset not in PRESETS:
        raise ValueError(f"unknown preset: {preset!r}")
    now = _naive_utc(now) if now is not None else datetime.now(UTC).replace(tzinfo=None)
    active_count = len(session.exec(select(Target.id).where(Target.status == TargetStatus.ACTIVE)).all())
    quota = daily_quota(active_count, cycle_days)
    if quota == 0:
        return None
    ids = due_target_ids(session, cycle_days, now, limit=quota, field=field)
    if not ids:
        return None

    cfg = PRESETS[preset]
    severities = cfg["severities"] or get_settings().severity_list
    run = ScanRun(
        scope=RunScope.TARGETS,
        target_ids=ids,
        severities=",".join(severities),
        requested_by="scheduler",
        cve_years=cfg["cve_years"],
        preset=preset,
        rate_limit=cfg["rate_limit"],
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    window = f", CVE window {cfg['cve_years']}y" if cfg["cve_years"] else ""
    log_line(
        session, run.id,
        f"Queued rolling {preset} batch: {len(ids)} of {active_count} active targets "
        f"(cycle {cycle_days}d{window})",
    )
    return run.id
