"""Read-side helpers that assemble scanner status for the API."""

from datetime import timedelta
from pathlib import Path

from sqlmodel import Session, func, select

from app.models import RunStatus, ScanLog, ScanRun, WorkerState, WorkerStatus, utcnow
from app.schemas import LogOut, ScanRunOut, ScanStatus, TemplateStatus

HEARTBEAT_STALE_AFTER = timedelta(minutes=2)


def run_out(run: ScanRun) -> ScanRunOut:
    return ScanRunOut.model_validate(run, from_attributes=True)


def _count_lines(path: str | None) -> int | None:
    if not path or not Path(path).exists():
        return None
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


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
