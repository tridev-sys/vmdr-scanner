"""Read-side helpers that assemble scanner status for the API."""

from datetime import timedelta
from pathlib import Path

from sqlmodel import Session, func, select

from app.models import RunStatus, ScanLog, ScanRun, WorkerState, WorkerStatus, utcnow
from app.models import RunScope, Target, TargetStatus
from app.schemas import ActiveTarget, LogOut, ScanRunOut, ScanStatus, TemplateStatus

HEARTBEAT_STALE_AFTER = timedelta(minutes=2)


def run_out(run: ScanRun) -> ScanRunOut:
    out = ScanRunOut.model_validate(run, from_attributes=True)
    if run.started_at and run.finished_at:
        out.duration_seconds = round((run.finished_at - run.started_at).total_seconds(), 1)
    return out


def _count_lines(path: str | None) -> int | None:
    if not path or not Path(path).exists():
        return None
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def _active_targets(session: Session, run: ScanRun | None) -> list[ActiveTarget]:
    if run is None or run.status != RunStatus.RUNNING:
        return []
    if run.scope == RunScope.ALL:
        query = select(Target).where(Target.status == TargetStatus.ACTIVE)
    elif run.scope == RunScope.TARGET:
        query = select(Target).where(Target.id == run.target_id)
    else:
        query = select(Target).where(Target.id.in_(run.target_ids or []))
    rows = session.exec(query.order_by(Target.id)).all()
    return [ActiveTarget(id=t.id, url=t.url, host=t.host, reachability=t.reachability) for t in rows]


def get_scan_status(session: Session, log_limit: int = 100) -> ScanStatus:
    state = session.get(WorkerState, 1) or WorkerState(id=1)
    now = utcnow()
    online = state.heartbeat_at is not None and now - state.heartbeat_at <= HEARTBEAT_STALE_AFTER

    current = session.get(ScanRun, state.current_run_id) if state.current_run_id else None
    if current is None:
        current = session.exec(
            select(ScanRun).where(ScanRun.status == RunStatus.RUNNING).order_by(ScanRun.id.desc())
        ).first()

    queue_length = session.exec(
        select(func.count(ScanRun.id)).where(ScanRun.status == RunStatus.QUEUED)
    ).one()

    recent = session.exec(select(ScanRun).order_by(ScanRun.id.desc()).limit(10)).all()

    log_run_id = current.id if current else (recent[0].id if recent else None)
    logs = []
    if log_run_id is not None:
        logs = session.exec(
            select(ScanLog).where(ScanLog.run_id == log_run_id).order_by(ScanLog.id.desc()).limit(log_limit)
        ).all()
        logs.reverse()

    if not online:
        display_state = "OFFLINE"
    elif state.status in (WorkerStatus.SCANNING, WorkerStatus.UPDATING_TEMPLATES):
        display_state = state.status
    else:
        display_state = WorkerStatus.IDLE

    return ScanStatus(
        state=display_state,
        worker_online=online,
        heartbeat_at=state.heartbeat_at,
        current_run=run_out(current) if current else None,
        active_targets=_active_targets(session, current),
        server_time=now,
        live_findings=_count_lines(current.output_path) if current and current.status == RunStatus.RUNNING else None,
        queue_length=queue_length,
        templates=TemplateStatus(
            status=state.template_status,
            updated_at=state.template_updated_at,
            error=state.template_error,
            update_requested=state.template_update_requested,
        ),
        recent_runs=[run_out(r) for r in recent],
        logs=[LogOut.model_validate(log, from_attributes=True) for log in logs],
    )
