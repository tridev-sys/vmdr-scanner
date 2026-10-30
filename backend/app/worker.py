"""24x7 scanner daemon: `python -m app.worker`.

Responsibilities:
  * APScheduler: enqueue the daily full scan (cron) and flag template updates (interval).
  * Template sync: `nuclei -update-templates` when due or requested from the API.
  * Queue consumer: pulls QUEUED ScanRuns from the database, one at a time.

The API never runs Nuclei. Both processes share the SQLite database (WAL), so this works
the same across docker-compose containers (shared volume) and systemd on one host.
"""

import logging
import signal
import time
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlmodel import Session, select

from app.config import get_settings
from app.db import engine, init_db
from app.models import RunScope, RunStatus, ScanRun, WorkerState, WorkerStatus, utcnow
from app.services import nuclei
from app.services import scanner as scanner_mod
from app.services.process import kill_stale_group
from app.services.scanner import MAX_RUN_ATTEMPTS, execute_run, log_line, set_worker_state

logger = logging.getLogger("vmdr.worker")


def enqueue_full_scan(requested_by: str = "scheduler") -> int | None:
    """Queue an ALL-scope run unless one is already queued or running."""
    with Session(engine) as session:
        pending = session.exec(
            select(ScanRun).where(
                ScanRun.scope == RunScope.ALL,
                ScanRun.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]),
            )
        ).first()
        if pending:
            logger.info("skip enqueue: run %s already pending", pending.id)
            return None
        run = ScanRun(
            scope=RunScope.ALL,
            severities=",".join(get_settings().severity_list),
            requested_by=requested_by,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        log_line(session, run.id, f"Queued full scan ({requested_by})")
        return run.id


def request_template_update() -> None:
    with Session(engine) as session:
        set_worker_state(session, template_update_requested=True)


def _template_due(state: WorkerState | None) -> bool:
    if state is None or state.template_attempted_at is None:
        return True
    age = utcnow() - state.template_attempted_at
    return age >= timedelta(hours=get_settings().template_update_hours)


def run_template_update() -> None:
    with Session(engine) as session:
        set_worker_state(session, status=WorkerStatus.UPDATING_TEMPLATES, template_update_requested=False)
        log_line(session, None, "Updating Nuclei templates")
        ok, output = nuclei.update_templates(scanner_mod.shutdown_event)
        if output == "interrupted":
            # Shutdown during a template sync: not a template failure. Retry after restart.
            set_worker_state(session, status=WorkerStatus.IDLE, template_update_requested=True)
            log_line(session, None, "Template update interrupted by shutdown; will retry on next start", "WARN")
            return
        now = utcnow()
        if ok:
            set_worker_state(
                session, template_attempted_at=now, template_updated_at=now, template_status="ok",
                template_error=None, status=WorkerStatus.IDLE,
            )
            log_line(session, None, "Nuclei templates updated")
        else:
            set_worker_state(
                session, template_attempted_at=now, template_status="error",
                template_error=output[-2000:], status=WorkerStatus.IDLE,
            )
            log_line(session, None, f"Template update failed: {output[-500:]}", "ERROR")


def _next_queued_run_id() -> int | None:
    with Session(engine) as session:
        run = session.exec(
            select(ScanRun).where(ScanRun.status == RunStatus.QUEUED).order_by(ScanRun.id)
        ).first()
        return run.id if run else None


def recover_orphaned_runs() -> int:
    """Handle runs left RUNNING by a worker that died without finishing them.

    A leftover Nuclei process group (pid file in the run's workdir) is killed first. The run is
    then re-queued, or FAILED once it has used MAX_RUN_ATTEMPTS. A stuck RUNNING row would
    otherwise block every future full scan.
    """
    settings = get_settings()
    recovered = 0
    with Session(engine) as session:
        for run in session.exec(select(ScanRun).where(ScanRun.status == RunStatus.RUNNING)).all():
            workdir = settings.scan_workdir / f"run-{run.id}"
            killed = [kill_stale_group(pid_file) for pid_file in sorted(workdir.glob("nuclei*.pid"))]
            if any(killed):
                log_line(session, run.id, "killed Nuclei left running by the previous worker", "WARN")
            reason = "interrupted: worker restarted before the run finished"
            if run.attempts < MAX_RUN_ATTEMPTS:
                run.status = RunStatus.QUEUED
                run.started_at = None
                run.error = f"{reason}; re-queued"
            else:
                run.status = RunStatus.FAILED
                run.error = f"{reason}; gave up after {run.attempts} attempts"
                run.finished_at = utcnow()
            session.add(run)
            session.commit()
            log_line(session, run.id, run.error, "WARN")
            recovered += 1
        set_worker_state(session, status=WorkerStatus.IDLE, current_run_id=None)
    return recovered


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = get_settings()
    init_db()
    if recover_orphaned_runs():
        logger.warning("marked orphaned RUNNING run(s) as FAILED")
    # The handler only sets an event. Every long step (Nuclei, template sync, probes) watches it and
    # stops promptly, so a deploy or `systemctl stop` finishes well inside the supervisor's grace period.
    stop = scanner_mod.shutdown_event
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    with Session(engine) as session:
        state = session.get(WorkerState, 1)
        if _template_due(state):
            set_worker_state(session, template_update_requested=True)

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        enqueue_full_scan,
        CronTrigger.from_crontab(settings.full_scan_cron, timezone="UTC"),
        id="full-scan", max_instances=1, coalesce=True,
    )
    scheduler.add_job(
        request_template_update,
        IntervalTrigger(hours=settings.template_update_hours),
        id="template-sync", max_instances=1, coalesce=True,
    )
    scheduler.start()
    logger.info("worker started; full scan cron=%r, template sync every %sh",
                settings.full_scan_cron, settings.template_update_hours)

    last_purge = 0.0
    while not stop.is_set():
        if time.monotonic() - last_purge > 3600:
            last_purge = time.monotonic()
            try:
                from app.services.reports import purge_expired
                with Session(engine) as session:
                    removed = purge_expired(session)
                if removed:
                    logger.info("purged %s expired report(s)", removed)
            except Exception:
                logger.exception("report purge failed")
        try:
            with Session(engine) as session:
                state = session.get(WorkerState, 1)
                template_wanted = state is not None and (state.template_update_requested or _template_due(state))
            if template_wanted:
                run_template_update()
                continue

            run_id = _next_queued_run_id()
            if run_id is not None:
                execute_run(run_id)
                continue

            with Session(engine) as session:
                set_worker_state(session, status=WorkerStatus.IDLE)
        except Exception:  # keep the daemon alive; the error is in the log
            logger.exception("worker loop error")
        stop.wait(settings.worker_poll_seconds)

    scheduler.shutdown(wait=False)
    with Session(engine) as session:
        set_worker_state(session, status=WorkerStatus.IDLE, current_run_id=None)
    logger.info("worker stopped")


if __name__ == "__main__":
    main()
