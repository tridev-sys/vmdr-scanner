from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select

from app.auth import require_api_key
from app.config import get_settings
from app.db import get_session
from app.models import RunScope, RunStatus, ScanRun, Target, TargetStatus, WorkerState
from app.schemas import ScanRunOut, ScanStatus, ScanTrigger
from app.services.scanner import log_line, set_worker_state
from app.services.status import get_scan_status, run_out

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/trigger", response_model=ScanRunOut, status_code=status.HTTP_202_ACCEPTED,
             dependencies=[Depends(require_api_key)])
def trigger_scan(payload: ScanTrigger, session: Session = Depends(get_session)) -> ScanRunOut:
    """Queue a scan. The worker picks it up within VMDR_WORKER_POLL_SECONDS."""
    severities = payload.severities or get_settings().severity_list
    if payload.scope == "target":
        if payload.target_id is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "target_id is required for scope=target")
        target = session.get(Target, payload.target_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
        if target.status != TargetStatus.ACTIVE:
            raise HTTPException(status.HTTP_409_CONFLICT, f"target is {target.status}; set it ACTIVE to scan")
        scope, target_id = RunScope.TARGET, target.id
    else:
        pending = session.exec(select(ScanRun).where(
            ScanRun.scope == RunScope.ALL,
            ScanRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]),
        )).first()
        if pending:
            raise HTTPException(status.HTTP_409_CONFLICT, f"full scan {pending.id} already {pending.status}")
        scope, target_id = RunScope.ALL, None

    run = ScanRun(scope=scope, target_id=target_id, severities=",".join(severities), requested_by="api")
    session.add(run)
    session.commit()
    session.refresh(run)
    log_line(session, run.id, f"Queued {scope.lower()} scan via API")
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
