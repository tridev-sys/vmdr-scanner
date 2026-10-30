from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select

from app.auth import require_api_key
from app.config import get_settings
from app.db import get_session
from app.models import RunScope, RunStatus, ScanRun, Target, TargetStatus, WorkerState, utcnow
from app.schemas import ScanRunOut, ScanStatus, ScanTrigger
from app.services.scanner import log_line, set_worker_state
from app.services.status import get_scan_status, run_out

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/trigger", response_model=ScanRunOut, status_code=status.HTTP_202_ACCEPTED,
             dependencies=[Depends(require_api_key)])
def trigger_scan(payload: ScanTrigger, session: Session = Depends(get_session)) -> ScanRunOut:
    """Queue a scan. The worker picks it up within VMDR_WORKER_POLL_SECONDS."""
    severities = payload.severities or get_settings().severity_list
    target_ids: list[int] | None = None
    if payload.scope == "target":
        if payload.target_id is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "target_id is required for scope=target")
        target = session.get(Target, payload.target_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
        if target.status != TargetStatus.ACTIVE:
            raise HTTPException(status.HTTP_409_CONFLICT, f"target is {target.status}; set it ACTIVE to scan")
        scope, target_id = RunScope.TARGET, target.id
    elif payload.scope == "targets":
        ids = sorted(set(payload.target_ids or []))
        if not ids:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "target_ids is required for scope=targets")
        found = {t.id: t for t in session.exec(select(Target).where(Target.id.in_(ids))).all()}
        missing = [i for i in ids if i not in found]
        if missing:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"targets not found: {missing}")
        inactive = [i for i in ids if found[i].status != TargetStatus.ACTIVE]
        if inactive:
            raise HTTPException(status.HTTP_409_CONFLICT, f"targets not ACTIVE: {inactive}")
        scope, target_id, target_ids = RunScope.TARGETS, None, ids
    else:
        pending = session.exec(select(ScanRun).where(
            ScanRun.scope == RunScope.ALL,
            ScanRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]),
        )).first()
        if pending:
            raise HTTPException(status.HTTP_409_CONFLICT, f"full scan {pending.id} already {pending.status}")
        scope, target_id = RunScope.ALL, None

    run = ScanRun(scope=scope, target_id=target_id, target_ids=target_ids,
                  severities=",".join(severities), requested_by="api")
    session.add(run)
    session.commit()
    session.refresh(run)
    count = f" ({len(target_ids)} targets)" if target_ids else ""
    log_line(session, run.id, f"Queued {scope.lower()} scan via API{count}")
    return run_out(run)


@router.post("/{run_id}/cancel", response_model=ScanRunOut, dependencies=[Depends(require_api_key)])
def cancel_run(run_id: int, session: Session = Depends(get_session)) -> ScanRunOut:
    """Stop a run. QUEUED runs are cancelled at once. RUNNING runs get a flag, and the worker
    terminates Nuclei within one heartbeat slice (about 15s)."""
    run = session.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    if run.status == RunStatus.QUEUED:
        run.status = RunStatus.CANCELLED
        run.error = "cancelled by user"
        run.finished_at = utcnow()
        session.add(run)
        session.commit()
        log_line(session, run.id, "Cancelled by user while queued", "WARN")
    elif run.status == RunStatus.RUNNING:
        run.cancel_requested = True
        session.add(run)
        session.commit()
        log_line(session, run.id, "Cancel requested by user; stopping Nuclei", "WARN")
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, f"run is {run.status}; nothing to cancel")
    session.refresh(run)
    return run_out(run)


@router.get("/status", response_model=ScanStatus)
def scan_status(
    session: Session = Depends(get_session),
    log_limit: int = Query(100, ge=1, le=500),
) -> ScanStatus:
    return get_scan_status(session, log_limit=log_limit)


@router.get("/runs", response_model=list[ScanRunOut])
def list_runs(session: Session = Depends(get_session), limit: int = Query(20, ge=1, le=200)) -> list[ScanRunOut]:
    rows = session.exec(select(ScanRun).order_by(ScanRun.id.desc()).limit(limit)).all()
    return [run_out(r) for r in rows]


@router.post("/templates/update", status_code=status.HTTP_202_ACCEPTED,
             dependencies=[Depends(require_api_key)])
def request_template_update(session: Session = Depends(get_session)) -> dict:
    state = session.get(WorkerState, 1) or WorkerState(id=1)
    state.template_update_requested = True
    session.add(state)
    session.commit()
    return {"requested": True}
