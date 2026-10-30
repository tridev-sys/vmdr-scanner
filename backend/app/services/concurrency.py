"""Which targets a run covers, and which runs may execute at the same time.

Two runs may run together only if their target sets do not overlap. Overlapping runs would
write the same findings at once, so the API rejects them and the worker never starts them together.
"""

from sqlmodel import Session, select

from app.models import RunScope, RunStatus, ScanRun, Target, TargetStatus


def run_target_ids(session: Session, run: ScanRun) -> set[int]:
    if run.scope == RunScope.TARGET:
        return {run.target_id} if run.target_id else set()
    if run.scope == RunScope.TARGETS:
        return set(run.target_ids or [])
    return set(session.exec(select(Target.id).where(Target.status == TargetStatus.ACTIVE)).all())


def busy_target_ids(session: Session, run_ids: set[int] | None = None) -> set[int]:
    """Targets covered by runs that are RUNNING, plus the given run ids (already claimed by a worker)."""
    busy: set[int] = set()
    runs = session.exec(select(ScanRun).where(ScanRun.status == RunStatus.RUNNING)).all()
    if run_ids:
        runs += session.exec(select(ScanRun).where(ScanRun.id.in_(run_ids))).all()
    for run in runs:
        busy |= run_target_ids(session, run)
    return busy


def conflicting_run(session: Session, targets: set[int]) -> ScanRun | None:
    """A QUEUED or RUNNING run that covers any of the given targets, if one exists."""
    for run in session.exec(select(ScanRun).where(ScanRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]))).all():
        if run_target_ids(session, run) & targets:
            return run
    return None
