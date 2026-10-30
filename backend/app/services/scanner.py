"""Executes one ScanRun: probes targets, runs Nuclei on the reachable ones, ingests results.

Guarantees:
  * A run never stays RUNNING because of an exception here. Failures mark it FAILED.
  * A shutdown request interrupts Nuclei immediately. The run is re-queued (up to MAX_RUN_ATTEMPTS).
  * Unreachable targets are skipped, logged, and never auto-resolved. A dead host must not
    make its open findings look fixed.
"""

import logging
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from sqlmodel import Session, select

from app.config import get_settings
from app.db import engine
from app.models import RunScope, RunStatus, ScanLog, ScanRun, Target, TargetStatus, WorkerState, WorkerStatus, utcnow
from app.services.ingest import ingest
from app.services.nuclei import build_command, parse_jsonl, recent_cve_dirs
from app.services.probe import probe_urls
from app.services.process import ProcessOutcome, run_process
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


def _run_passes(passes, timeout_s: int, should_stop) -> ProcessOutcome:
    """Run one chunk's passes in order (recent CVE templates first). Stops at the first bad pass."""
    last = ProcessOutcome(0)
    for cmd, _output, log_path, pid_path in passes:
        outcome = run_process(cmd, log_path, timeout_s, shutdown_event, None, pid_path, should_stop)
        if outcome.interrupted or outcome.timed_out or outcome.returncode != 0:
            return outcome
        last = outcome
    return last


def _execute_started(session: Session, run_id: int, target_ids: list[int], settings) -> None:
    run = session.get(ScanRun, run_id)
    if not target_ids:
        _finish(session, run_id, RunStatus.COMPLETED, None)
        log_line(session, run_id, "No ACTIVE targets matched; nothing to scan.", "WARN")
        return

    log_line(session, run_id, f"Probing {len(target_ids)} ACTIVE target(s)")
    reachable_ids, unreachable = _probe_and_split(session, target_ids)
    run = session.get(ScanRun, run_id)
    run.unreachable_count = len(unreachable)
    session.add(run)
    session.commit()
    if unreachable:
        sample = ", ".join(unreachable[:10]) + (" ..." if len(unreachable) > 10 else "")
        log_line(session, run_id, f"Skipping {len(unreachable)} unreachable target(s): {sample}", "WARN")
    if _cancel_requested(run_id):
        _finish(session, run_id, RunStatus.CANCELLED, "cancelled by user")
        log_line(session, run_id, "Cancelled by user before Nuclei started", "WARN")
        return

    if not reachable_ids:
        _finish(session, run_id, RunStatus.COMPLETED, None)
        log_line(session, run_id, "No reachable targets; nothing scanned, no findings resolved.", "WARN")
        return

    targets = [session.get(Target, tid) for tid in reachable_ids]
    workdir: Path = settings.scan_workdir / f"run-{run.id}"
    workdir.mkdir(parents=True, exist_ok=True)
    output_file = workdir / "scan_output.jsonl"
    output_file.unlink(missing_ok=True)

    # Chunks: each chunk is one Nuclei process over a slice of the targets. Several run at once.
    size = max(1, settings.scan_chunk_size)
    chunks = [targets[i:i + size] for i in range(0, len(targets), size)]
    run.output_path = str(output_file)
    run.chunks_total = len(chunks)
    run.chunks_done = 0
    run.targets_scanned = 0
    session.add(run)
    session.commit()
    log_line(
        session, run_id,
        f"Scanning {len(targets)} reachable target(s) in {len(chunks)} chunk(s) of up to {size}, "
        f"{min(settings.scan_parallel_chunks, len(chunks))} at a time, severities={run.severities}",
    )

    # Newest CVEs first: pass 1 runs only the newest CVE template years, pass 2 runs the rest
    # with those excluded, so every template still runs exactly once.
    recent_years = [utcnow().year - i for i in range(settings.recent_cve_years)]
    recent_dirs = recent_cve_dirs(Path(settings.nuclei_templates_dir), recent_years)
    if recent_dirs:
        log_line(session, run_id, f"Recent-first: {len(recent_dirs)} template dir(s) for {recent_years} run before the rest")
    severities = run.severities.split(",")
    labels = (["recent"] if recent_dirs else []) + ["rest"]

    jobs = []
    for index, chunk in enumerate(chunks):
        targets_file = workdir / f"targets_{index:03d}.txt"
        targets_file.write_text("\n".join(t.url for t in chunk) + "\n", encoding="utf-8")
        passes = []
        for label in labels:
            output = workdir / f"output_{index:03d}_{label}.jsonl"
            output.unlink(missing_ok=True)
            cmd = build_command(
                targets_file, output, severities,
                templates=recent_dirs if label == "recent" else None,
                exclude=None if label == "recent" else recent_dirs,
            )
            passes.append((cmd, output, workdir / f"nuclei_{index:03d}_{label}.log",
                           workdir / f"nuclei_{index:03d}_{label}.pid"))
        jobs.append((index, len(chunk), passes))

    outcomes: list[ProcessOutcome] = []
    failed_to_start: str | None = None
    parallel = max(1, min(settings.scan_parallel_chunks, len(jobs)))
    pool = ThreadPoolExecutor(max_workers=parallel)
    pending = {}
    try:
        for index, count, passes in jobs:
            pending[pool.submit(
                _run_passes, passes, settings.nuclei_run_timeout_s, lambda: _cancel_requested(run_id),
            )] = (index, count)
        while pending:
            # Wait in short slices so the heartbeat stays fresh during long chunks.
            done, _ = wait(list(pending), timeout=HEARTBEAT_INTERVAL_S, return_when=FIRST_COMPLETED)
            for future in done:
                index, count = pending.pop(future)
                try:
                    outcome = future.result()
                except FileNotFoundError:
                    failed_to_start = f"nuclei binary not found at {settings.nuclei_bin}"
                    outcome = ProcessOutcome(None, interrupted=True)
                outcomes.append(outcome)
                run = session.get(ScanRun, run_id)
                run.chunks_done += 1
                if outcome.returncode == 0 and not outcome.timed_out and not outcome.interrupted:
                    run.targets_scanned += count
                session.add(run)
                session.commit()
                log_line(session, run_id,
                         f"chunk {index + 1}/{len(jobs)} finished (exit {outcome.returncode}"
                         + (", timed out" if outcome.timed_out else "")
                         + (", interrupted" if outcome.interrupted else "") + ")",
                         "INFO" if outcome.returncode == 0 and not outcome.timed_out else "WARN")
            set_worker_state(session, status=WorkerStatus.SCANNING, current_run_id=run_id)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    if failed_to_start:
        _finish(session, run_id, RunStatus.FAILED, failed_to_start)
        log_line(session, run_id, failed_to_start, "ERROR")
        return

    if any(o.interrupted for o in outcomes):
        # Partial output is never ingested: a half-finished scan must not resolve anything.
        if _cancel_requested(run_id):
            _finish(session, run_id, RunStatus.CANCELLED, "cancelled by user")
            log_line(session, run_id, "Scan cancelled by user; partial output discarded", "WARN")
        else:
            _requeue_or_fail(session, run_id, "interrupted by worker shutdown")
        return

    timed_out = any(o.timed_out for o in outcomes)
    bad_exit = next((o.returncode for o in outcomes if o.returncode != 0), None)
    ok = not timed_out and bad_exit is None
    if timed_out:
        error = f"nuclei exceeded run timeout ({settings.nuclei_run_timeout_s}s)"
    elif bad_exit is not None:
        error = f"nuclei exited with code {bad_exit}"
    else:
        error = None

    # Merge chunk outputs into the run's single results file.
    with output_file.open("w", encoding="utf-8") as merged:
        for part in sorted(workdir.glob("output_*.jsonl")):
            merged.write(part.read_text(encoding="utf-8", errors="replace"))

    for log_file in sorted(workdir.glob("nuclei_*.log")):
        tail = log_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-5:]
        for line in tail:
            log_line(session, run_id, f"nuclei[{log_file.stem}]: {line}", "DEBUG")

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
