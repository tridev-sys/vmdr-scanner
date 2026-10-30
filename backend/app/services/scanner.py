"""Executes one ScanRun: probes targets, runs Nuclei on the reachable ones, ingests results.

Guarantees:
  * A run never stays RUNNING because of an exception here. Failures mark it FAILED.
  * A shutdown request interrupts Nuclei immediately. The run is re-queued (up to MAX_RUN_ATTEMPTS).
  * Unreachable targets are skipped, logged, and never auto-resolved. A dead host must not
    make its open findings look fixed.
"""

import logging
import threading
from pathlib import Path

from sqlmodel import Session, select

from app.config import get_settings
from app.db import engine
from app.models import RunScope, RunStatus, ScanLog, ScanRun, Target, TargetStatus, WorkerState, WorkerStatus, utcnow
from app.services.ingest import ingest
from app.services.nuclei import build_command, parse_jsonl
from app.services.probe import probe_urls
from app.services.process import run_process
from app.services.webhooks import dispatch_alerts

logger = logging.getLogger(__name__)
HEARTBEAT_INTERVAL_S = 15
MAX_RUN_ATTEMPTS = 3
# Set by the worker's SIGTERM/SIGINT handler. Checked by every long-running step.
shutdown_event = threading.Event()
UNREACHABLE_STATUS = "SKIPPED_UNREACHABLE"


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


def _finish(session: Session, run_id: int, status: str, error: str | None) -> None:
    run = session.get(ScanRun, run_id)
    run.status = status
    run.error = error
    run.finished_at = utcnow()
    session.add(run)
    session.commit()


def _cancel_requested(run_id: int) -> bool:
    with Session(engine) as session:
        run = session.get(ScanRun, run_id)
        return bool(run and run.cancel_requested)


def _select_targets(session: Session, run: ScanRun) -> list[Target]:
    if run.scope == RunScope.TARGET:
        target = session.get(Target, run.target_id) if run.target_id else None
        if target is None or target.status != TargetStatus.ACTIVE:
            return []
        return [target]
    if run.scope == RunScope.TARGETS:
        ids = run.target_ids or []
        if not ids:
            return []
        return list(session.exec(
            select(Target).where(Target.id.in_(ids), Target.status == TargetStatus.ACTIVE).order_by(Target.id)
        ).all())
    return list(session.exec(
        select(Target).where(Target.status == TargetStatus.ACTIVE).order_by(Target.id)
    ).all())


def _probe_and_split(session: Session, target_ids: list[int]) -> tuple[list[int], list[str]]:
    """Probe every target, record the result on the Target row, return (reachable ids, unreachable urls)."""
    targets = [session.get(Target, tid) for tid in target_ids]
    results = probe_urls([t.url for t in targets])
    now = utcnow()
    reachable: list[int] = []
    unreachable: list[str] = []
    for target, result in zip(targets, results):
        target.last_probed_at = now
        if result.reachable:
            target.reachability = "REACHABLE"
            target.consecutive_probe_failures = 0
            target.last_probe_error = result.error
            reachable.append(target.id)
        else:
            target.reachability = "UNREACHABLE"
            target.consecutive_probe_failures += 1
            target.last_probe_error = result.error
            target.last_scan_status = UNREACHABLE_STATUS
            unreachable.append(target.url)
        session.add(target)
    session.commit()
    return reachable, unreachable


def _requeue_or_fail(session: Session, run_id: int, reason: str) -> None:
    run = session.get(ScanRun, run_id)
    if run.attempts < MAX_RUN_ATTEMPTS:
        run.status = RunStatus.QUEUED
        run.started_at = None
        run.error = f"{reason}; re-queued (attempt {run.attempts} of {MAX_RUN_ATTEMPTS})"
        session.add(run)
        session.commit()
        log_line(session, run_id, run.error, "WARN")
    else:
        _finish(session, run_id, RunStatus.FAILED, f"{reason}; gave up after {run.attempts} attempts")
        log_line(session, run_id, f"{reason}; gave up after {run.attempts} attempts", "ERROR")


def execute_run(run_id: int) -> None:
    settings = get_settings()
    with Session(engine) as session:
        run = session.get(ScanRun, run_id)
        if run is None or run.status != RunStatus.QUEUED or shutdown_event.is_set():
            return

        # Dynamic sync: read the ACTIVE set at execution time, never from a static list.
        target_ids = [t.id for t in _select_targets(session, run)]
        run.started_at = utcnow()
        run.status = RunStatus.RUNNING
        run.attempts += 1
        run.targets_count = len(target_ids)
        session.add(run)
        session.commit()
        set_worker_state(session, status=WorkerStatus.SCANNING, current_run_id=run.id)

        try:
            _execute_started(session, run_id, target_ids, settings)
        except Exception as exc:  # never leave the run RUNNING
            logger.exception("run %s crashed", run_id)
            session.rollback()
            _finish(session, run_id, RunStatus.FAILED, f"internal error: {type(exc).__name__}: {exc}"[:2000])
            log_line(session, run_id, f"internal error: {type(exc).__name__}: {exc}", "ERROR")
        finally:
            set_worker_state(session, status=WorkerStatus.IDLE, current_run_id=None)


def _execute_started(session: Session, run_id: int, target_ids: list[int], settings) -> None:
    run = session.get(ScanRun, run_id)
    if not target_ids:
        _finish(session, run_id, RunStatus.COMPLETED, None)
        log_line(session, run_id, "No ACTIVE targets matched; nothing to scan.", "WARN")
        return

    log_line(session, run_id, f"Probing {len(target_ids)} ACTIVE target(s)")
    reachable_ids, unreachable = _probe_and_split(session, target_ids)
    if _cancel_requested(run_id):
        _finish(session, run_id, RunStatus.CANCELLED, "cancelled by user")
        log_line(session, run_id, "Cancelled by user before Nuclei started", "WARN")
        return
    run = session.get(ScanRun, run_id)
    run.unreachable_count = len(unreachable)
    session.add(run)
    session.commit()
    if unreachable:
        sample = ", ".join(unreachable[:10]) + (" ..." if len(unreachable) > 10 else "")
        log_line(session, run_id, f"Skipping {len(unreachable)} unreachable target(s): {sample}", "WARN")

    if not reachable_ids:
        _finish(session, run_id, RunStatus.COMPLETED, None)
        log_line(session, run_id, "No reachable targets; nothing scanned, no findings resolved.", "WARN")
        return

    targets = [session.get(Target, tid) for tid in reachable_ids]
    workdir: Path = settings.scan_workdir / f"run-{run.id}"
    workdir.mkdir(parents=True, exist_ok=True)
    targets_file = workdir / "targets_active.txt"
    output_file = workdir / "scan_output.jsonl"
    targets_file.write_text("\n".join(t.url for t in targets) + "\n", encoding="utf-8")
    output_file.unlink(missing_ok=True)
    run.output_path = str(output_file)
    session.add(run)
    session.commit()

    cmd = build_command(targets_file, output_file, run.severities.split(","))
    log_line(session, run_id, f"Scanning {len(targets)} reachable target(s) at severities={run.severities}")

    def heartbeat() -> None:
        set_worker_state(session, status=WorkerStatus.SCANNING, current_run_id=run_id)

    try:
        outcome = run_process(
            cmd, workdir / "nuclei.log", settings.nuclei_run_timeout_s, shutdown_event,
            on_heartbeat=heartbeat, pid_path=workdir / "nuclei.pid",
            should_stop=lambda: _cancel_requested(run_id),
        )
    except FileNotFoundError:
        _finish(session, run_id, RunStatus.FAILED, f"nuclei binary not found at {settings.nuclei_bin}")
        log_line(session, run_id, f"nuclei binary not found at {settings.nuclei_bin}", "ERROR")
        return

    if outcome.interrupted:
        # Partial output is never ingested: a half-finished scan must not resolve anything.
        if _cancel_requested(run_id):
            _finish(session, run_id, RunStatus.CANCELLED, "cancelled by user")
            log_line(session, run_id, "Scan cancelled by user; partial output discarded", "WARN")
        else:
            _requeue_or_fail(session, run_id, "interrupted by worker shutdown")
        return

    nuclei_log = workdir / "nuclei.log"
    tail = nuclei_log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-15:]
    for line in tail:
        log_line(session, run_id, f"nuclei: {line}", "DEBUG")

    ok = outcome.returncode == 0 and not outcome.timed_out
    if outcome.timed_out:
        error = f"nuclei exceeded run timeout ({settings.nuclei_run_timeout_s}s)"
    elif outcome.returncode != 0:
        error = f"nuclei exited with code {outcome.returncode}"
    else:
        error = None

    findings, bad = parse_jsonl(output_file)
    stats = ingest(session, run_id, targets, findings, bad, resolve=ok)

    run = session.get(ScanRun, run_id)
    run.findings_count = stats.findings_total
    run.new_findings = stats.new
    run.resolved_findings = stats.resolved
    run.status = RunStatus.COMPLETED if ok else RunStatus.FAILED
    run.error = error
    run.finished_at = utcnow()
    session.add(run)
    session.commit()
    log_line(
        session, run_id,
        f"Done: {stats.findings_total} findings, {stats.new} new, {stats.reopened} reopened, "
        f"{stats.resolved} resolved, {stats.unmatched} unmatched, {bad} unparseable lines"
        + ("" if ok else f" — results NOT used for resolution ({error})"),
        "INFO" if ok else "WARN",
    )

    if stats.alerts:
        for err in dispatch_alerts(session, stats.alerts):
            log_line(session, run_id, f"alert delivery: {err}", "WARN")
