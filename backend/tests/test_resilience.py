"""Shutdown, reachability, crash-safety, and migration behaviour of the scan path."""

import importlib
import sys
import threading
import time

import pytest
from sqlmodel import Session, select

from tests.test_worker_pipeline import _queue_run, pipeline  # noqa: F401  (fixture)

SLEEPING_NUCLEI = f"""#!{sys.executable}
import sys, time
if "-update-templates" in sys.argv:
    sys.exit(0)
time.sleep(120)
"""


def _sleeping_nuclei(tmp_path, monkeypatch):
    fake = tmp_path / "slow-nuclei"
    fake.write_text(SLEEPING_NUCLEI)
    fake.chmod(0o755)
    from app import config
    monkeypatch.setenv("VMDR_NUCLEI_BIN", str(fake))
    config.get_settings.cache_clear()
    return fake


def _wait_for_pid(workdir):
    """Wait until a chunk's Nuclei process has written its pid file, then return the pid."""
    for _ in range(200):
        files = sorted(workdir.glob("nuclei*.pid"))
        if files:
            return int(files[0].read_text())
        time.sleep(0.05)
    raise AssertionError("nuclei never started")


def _process_alive(pid: int) -> bool:
    import os
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_shutdown_interrupts_scan_and_requeues_run(pipeline, monkeypatch):
    """Regression for the worker-shutdown bug: SIGTERM must stop Nuclei now, not after the scan."""
    from app.models import RunStatus, ScanRun
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
    _sleeping_nuclei(pipeline["tmp"], monkeypatch)

    run_id = _queue_run(db)
    worker_thread = threading.Thread(target=scanner.execute_run, args=(run_id,))
    started = time.monotonic()
    worker_thread.start()

    nuclei_pid = _wait_for_pid(pipeline["tmp"] / "scans" / f"run-{run_id}")

    scanner.shutdown_event.set()  # what the SIGTERM handler does
    worker_thread.join(timeout=30)

    assert not worker_thread.is_alive()
    assert time.monotonic() - started < 25, "shutdown should not wait for the 120s scan"
    assert not _process_alive(nuclei_pid), "nuclei must be terminated with the worker"
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.QUEUED and "shutdown" in run.error
        assert run.attempts == 1
    scanner.shutdown_event.clear()


def test_run_is_failed_after_max_attempts_on_repeated_interruption(pipeline):
    from sqlmodel import Session
    from app.models import RunStatus, ScanRun
    import app.worker as worker

    importlib.reload(worker)
    db = pipeline["db"]
    run_id = _queue_run(db)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        run.status = RunStatus.RUNNING
        run.attempts = 3
        s.add(run)
        s.commit()
    worker.recover_orphaned_runs()
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.FAILED and "gave up" in run.error


def test_unreachable_targets_are_skipped_and_never_resolved(pipeline, monkeypatch):
    """A dead host must not look like a fixed vulnerability."""
    from app.models import ScanRun, Target, Vulnerability, VulnStatus
    from app.services.probe import ProbeResult
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com", "https://clinic.heykoala.ai"])

    # Cycle 1: both reachable, both get a finding.
    scanner.execute_run(_queue_run(db))
    with Session(db.engine) as s:
        assert len(s.exec(select(Vulnerability)).all()) == 2

    # Cycles 2 and 3: clinic is down. Its finding must stay OPEN, not be resolved by the misses.
    def clinic_down(urls):
        return [ProbeResult(u, "clinic" not in u, None if "clinic" not in u else None,
                            None if "clinic" not in u else "ConnectError: refused") for u in urls]
    monkeypatch.setattr(scanner, "probe_urls", clinic_down)
    pipeline["emit"].unlink()  # Nuclei reports nothing for anything it scans
    for _ in range(2):
        scanner.execute_run(_queue_run(db))

    with Session(db.engine) as s:
        clinic = s.exec(select(Target).where(Target.host == "clinic.heykoala.ai")).one()
        assert clinic.reachability == "UNREACHABLE"
        assert clinic.consecutive_probe_failures == 2
        assert clinic.last_scan_status == "SKIPPED_UNREACHABLE"
        statuses = {v.target_url: v.status for v in s.exec(select(Vulnerability)).all()}
        assert statuses["https://clinic.heykoala.ai"] == VulnStatus.OPEN
        last = s.get(ScanRun, s.exec(select(ScanRun).order_by(ScanRun.id.desc())).first().id)
        assert last.unreachable_count == 1 and last.targets_count == 2

    # Clinic recovers: it is scanned again and the reachability counter resets.
    monkeypatch.setattr(scanner, "probe_urls", lambda urls: [ProbeResult(u, True, 200) for u in urls])
    scanner.execute_run(_queue_run(db))
    with Session(db.engine) as s:
        clinic = s.exec(select(Target).where(Target.host == "clinic.heykoala.ai")).one()
        assert clinic.reachability == "REACHABLE" and clinic.consecutive_probe_failures == 0


def test_all_targets_unreachable_completes_without_resolving(pipeline, monkeypatch):
    from sqlmodel import Session
    from app.models import RunStatus, ScanRun, Vulnerability
    from app.services.probe import ProbeResult
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
    monkeypatch.setattr(scanner, "probe_urls", lambda urls: [ProbeResult(u, False, error="timeout") for u in urls])
    run_id = _queue_run(db)
    scanner.execute_run(run_id)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.COMPLETED and run.unreachable_count == 1
        assert s.exec(select(Vulnerability)).all() == []


def test_unexpected_exception_marks_run_failed_not_running(pipeline, monkeypatch):
    from sqlmodel import Session
    from app.models import RunStatus, ScanRun
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])

    def boom(*_args, **_kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(scanner, "ingest", boom)
    run_id = _queue_run(db)
    scanner.execute_run(run_id)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.FAILED
        assert "database is locked" in run.error


def test_migration_adds_missing_columns_to_old_database(tmp_path):
    from sqlalchemy import create_engine, text
    from app.migrations import migrate

    engine = create_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE targets (id INTEGER PRIMARY KEY, url VARCHAR)"))
        conn.execute(text("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY)"))
    added = migrate(engine)
    assert "targets.reachability" in added and "scan_runs.attempts" in added
    assert migrate(engine) == []  # idempotent


def test_cancel_running_scan_kills_nuclei_and_marks_cancelled(pipeline, monkeypatch):
    from app.models import RunStatus, ScanRun
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
    _sleeping_nuclei(pipeline["tmp"], monkeypatch)

    run_id = _queue_run(db)
    thread = threading.Thread(target=scanner.execute_run, args=(run_id,))
    thread.start()
    nuclei_pid = _wait_for_pid(pipeline["tmp"] / "scans" / f"run-{run_id}")

    with Session(db.engine) as s:  # what POST /api/scans/{id}/cancel does for a RUNNING run
        run = s.get(ScanRun, run_id)
        run.cancel_requested = True
        s.add(run)
        s.commit()

    thread.join(timeout=30)
    assert not thread.is_alive()
    assert not _process_alive(nuclei_pid)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.CANCELLED
        assert run.error == "cancelled by user"
    scanner.shutdown_event.clear()


def test_targets_scope_scans_only_selected_ids(pipeline):
    from sqlmodel import Session, select
    from app.models import RunScope, RunStatus, ScanRun, Target, Vulnerability
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com", "https://clinic.heykoala.ai", "https://tour.heykoala.ai"])
        keep = [t.id for t in s.exec(select(Target).where(Target.host.in_(["kai.buckleconsult.com", "tour.heykoala.ai"]))).all()]
    with Session(db.engine) as s:
        run = ScanRun(scope=RunScope.TARGETS, target_ids=keep, severities="critical,high,medium")
        s.add(run)
        s.commit()
        run_id = run.id
    scanner.execute_run(run_id)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.COMPLETED and run.targets_count == 2
        urls = sorted(v.target_url for v in s.exec(select(Vulnerability)).all())
        assert urls == ["https://kai.buckleconsult.com", "https://tour.heykoala.ai"]


def test_status_lists_active_targets_only_while_running(pipeline):
    from sqlmodel import Session
    from app.models import RunStatus, RunScope, ScanRun, WorkerState
    from app.services.status import get_scan_status
    from app.services.targets import add_targets
    from sqlmodel import select
    from app.models import Target

    db = pipeline["db"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com", "https://clinic.heykoala.ai"])
        run = ScanRun(scope=RunScope.ALL, severities="high", status=RunStatus.RUNNING)
        s.add(run)
        s.commit()
        assert [t.host for t in get_scan_status(s).active_targets] == ["kai.buckleconsult.com", "clinic.heykoala.ai"]
        assert get_scan_status(s).server_time is not None
        run.status = RunStatus.COMPLETED
        s.add(run)
        s.commit()
        assert get_scan_status(s).active_targets == []
