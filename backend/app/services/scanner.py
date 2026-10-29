"""Executes one ScanRun: builds the runtime target file, runs Nuclei, ingests results, updates worker state."""

import logging
import subprocess
import time
from pathlib import Path

from sqlmodel import Session, select

from app.config import get_settings
from app.db import engine
from app.models import RunScope, RunStatus, ScanLog, ScanRun, Target, TargetStatus, WorkerState, WorkerStatus, utcnow
from app.services.ingest import ingest
from app.services.nuclei import build_command, parse_jsonl
from app.services.webhooks import dispatch_alerts

logger = logging.getLogger(__name__)
HEARTBEAT_INTERVAL_S = 15


def log_line(session: Session, run_id: int | None, message: str, level: str = "INFO") -> None:
    logger.log(getattr(logging, level, logging.INFO), "[run %s] %s", run_id, message)
    session.add(ScanLog(run_id=run_id, level=level, message=message[:4000], ts=utcnow()))
    session.commit()


def set_worker_state(session: Session, **fields) -> None:
    state = session.get(WorkerState, 1)
    if state is None:
        state = WorkerState(id=1)
    for key, value in fields.items():
        setattr(state, key, value)
    state.heartbeat_at = utcnow()
    session.add(state)
    session.commit()


def _fail(session: Session, run: ScanRun, message: str) -> None:
    run.status = RunStatus.FAILED
    run.error = message
    run.finished_at = utcnow()
    session.add(run)
    session.commit()
    log_line(session, run.id, message, "ERROR")


def _select_targets(session: Session, run: ScanRun) -> list[Target]:
    if run.scope == RunScope.TARGET:
        target = session.get(Target, run.target_id) if run.target_id else None
        if target is None or target.status != TargetStatus.ACTIVE:
            return []
        return [target]
    return list(session.exec(
        select(Target).where(Target.status == TargetStatus.ACTIVE).order_by(Target.id)
    ).all())


def execute_run(run_id: int) -> None:
    settings = get_settings()
    with Session(engine) as session:
        run = session.get(ScanRun, run_id)
        if run is None or run.status != RunStatus.QUEUED:
            return

        # Dynamic sync: read the ACTIVE set at execution time, never from a static list.
        targets = _select_targets(session, run)
        run.started_at = utcnow()
        run.status = RunStatus.RUNNING
        run.targets_count = len(targets)
        session.add(run)
        session.commit()
        set_worker_state(session, status=WorkerStatus.SCANNING, current_run_id=run.id)

        if not targets:
            run.status = RunStatus.COMPLETED
            run.finished_at = utcnow()
            session.add(run)
            session.commit()
            log_line(session, run.id, "No ACTIVE targets matched; nothing to scan.", "WARN")
            set_worker_state(session, status=WorkerStatus.IDLE, current_run_id=None)
            return

        workdir = settings.scan_workdir / f"run-{run.id}"
        workdir.mkdir(parents=True, exist_ok=True)
        targets_file = workdir / "targets_active.txt"
        output_file = workdir / "scan_output.jsonl"
        nuclei_log = workdir / "nuclei.log"
        targets_file.write_text("\n".join(t.url for t in targets) + "\n", encoding="utf-8")
        output_file.unlink(missing_ok=True)
        run.output_path = str(output_file)
        session.add(run)
        session.commit()

        severities = run.severities.split(",")
        cmd = build_command(targets_file, output_file, severities)
        log_line(session, run.id, f"Scanning {len(targets)} ACTIVE target(s) at severities={run.severities}")

        timed_out = False
        returncode: int | None = None
        try:
            with nuclei_log.open("w", encoding="utf-8") as fh:
                proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + settings.nuclei_run_timeout_s
                # Wait in short slices and refresh the heartbeat, so long scans don't look offline.
                while True:
                    try:
                        returncode = proc.wait(timeout=HEARTBEAT_INTERVAL_S)
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= deadline:
                            proc.kill()
                            proc.wait()
                            timed_out = True
                            break
                        set_worker_state(session, status=WorkerStatus.SCANNING, current_run_id=run.id)
        except FileNotFoundError:
            _fail(session, run, f"nuclei binary not found at {settings.nuclei_bin}")
            set_worker_state(session, status=WorkerStatus.IDLE, current_run_id=None)
            return

        tail = nuclei_log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-15:]
        for line in tail:
            log_line(session, run.id, f"nuclei: {line}", "DEBUG")

        ok = returncode == 0 and not timed_out
        if timed_out:
            error = f"nuclei exceeded run timeout ({settings.nuclei_run_timeout_s}s)"
        elif returncode != 0:
            error = f"nuclei exited with code {returncode}"
        else:
            error = None

        findings, bad = parse_jsonl(output_file)
        stats = ingest(session, run.id, targets, findings, bad, resolve=ok)

        run.findings_count = stats.findings_total
        run.new_findings = stats.new
        run.resolved_findings = stats.resolved
        run.status = RunStatus.COMPLETED if ok else RunStatus.FAILED
        run.error = error
        run.finished_at = utcnow()
        session.add(run)
        session.commit()
        log_line(
            session, run.id,
            f"Done: {stats.findings_total} findings, {stats.new} new, {stats.reopened} reopened, "
            f"{stats.resolved} resolved, {stats.unmatched} unmatched, {bad} unparseable lines"
            + ("" if ok else f" — results NOT used for resolution ({error})"),
            "INFO" if ok else "WARN",
        )

        if stats.alerts:
            for err in dispatch_alerts(session, stats.alerts):
                log_line(session, run.id, f"alert delivery: {err}", "WARN")

        set_worker_state(session, status=WorkerStatus.IDLE, current_run_id=None)
