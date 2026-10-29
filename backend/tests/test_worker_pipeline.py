"""Runs the real scan executor against a fake `nuclei` script to verify the full pipeline."""

import importlib
import json
import sys

import pytest

FAKE_NUCLEI = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
targets_file = args[args.index("-list") + 1]
targets = [line.strip() for line in open(targets_file) if line.strip()]
emit = os.path.exists(os.environ["FAKE_EMIT_FLAG"])
with open(out, "w") as fh:
    if emit:
        for t in targets:
            fh.write(json.dumps({{
                "template-id": "tmpl-a",
                "info": {{"name": "Fake finding", "severity": "high", "classification": {{"cve-id": ["CVE-2024-9999"]}}}},
                "matcher-name": "m1",
                "host": t,
                "matched-at": t + "/vuln",
            }}) + "\\n")
"""


@pytest.fixture()
def pipeline(tmp_path, monkeypatch):
    fake = tmp_path / "nuclei"
    fake.write_text(FAKE_NUCLEI)
    fake.chmod(0o755)
    emit_flag = tmp_path / "emit"
    emit_flag.write_text("1")

    monkeypatch.setenv("VMDR_DATABASE_URL", f"sqlite:///{tmp_path}/pipe.db")
    monkeypatch.setenv("VMDR_SCAN_WORKDIR", str(tmp_path / "scans"))
    monkeypatch.setenv("VMDR_NUCLEI_BIN", str(fake))
    monkeypatch.setenv("FAKE_EMIT_FLAG", str(emit_flag))
    monkeypatch.setenv("VMDR_RESOLVE_AFTER_MISSES", "2")

    from app import config
    config.get_settings.cache_clear()
    import app.db as db
    importlib.reload(db)
    db.init_db()
    # scanner.py binds `engine` at import time, so reload it against the fresh engine.
    import app.services.scanner as scanner
    importlib.reload(scanner)
    yield {"db": db, "scanner": scanner, "emit": emit_flag, "tmp": tmp_path}
    config.get_settings.cache_clear()


def _queue_run(db, scope="ALL", target_id=None):
    from sqlmodel import Session
    from app.models import ScanRun
    with Session(db.engine) as s:
        run = ScanRun(scope=scope, target_id=target_id, severities="critical,high,medium")
        s.add(run)
        s.commit()
        s.refresh(run)
        return run.id


def test_full_pipeline_dedup_and_resolution(pipeline):
    from sqlmodel import Session, select
    from app.models import RunStatus, ScanRun, Vulnerability, VulnStatus
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com", "https://clinic.heykoala.ai"])

    # Cycle 1: findings appear for both targets.
    run1 = _queue_run(db)
    scanner.execute_run(run1)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run1)
        assert run.status == RunStatus.COMPLETED and run.targets_count == 2
        assert run.new_findings == 2
        assert len(s.exec(select(Vulnerability)).all()) == 2

    # Cycle 2: same findings again -> dedup, no new rows.
    run2 = _queue_run(db)
    scanner.execute_run(run2)
    with Session(db.engine) as s:
        assert len(s.exec(select(Vulnerability)).all()) == 2
        assert s.get(ScanRun, run2).new_findings == 0

    # Cycles 3 and 4: findings disappear -> OPEN after one miss, RESOLVED after two.
    pipeline["emit"].unlink()
    scanner.execute_run(_queue_run(db))
    with Session(db.engine) as s:
        assert {v.status for v in s.exec(select(Vulnerability)).all()} == {VulnStatus.OPEN}
    scanner.execute_run(_queue_run(db))
    with Session(db.engine) as s:
        assert {v.status for v in s.exec(select(Vulnerability)).all()} == {VulnStatus.RESOLVED}


def test_target_scoped_run_only_scans_that_target(pipeline):
    from sqlmodel import Session, select
    from app.models import ScanRun, Target, Vulnerability
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com", "https://clinic.heykoala.ai"])
        clinic = s.exec(select(Target).where(Target.host == "clinic.heykoala.ai")).one()
        clinic_id = clinic.id

    run_id = _queue_run(db, scope="TARGET", target_id=clinic_id)
    scanner.execute_run(run_id)
    with Session(db.engine) as s:
        assert s.get(ScanRun, run_id).targets_count == 1
        vulns = s.exec(select(Vulnerability)).all()
        assert [v.target_url for v in vulns] == ["https://clinic.heykoala.ai"]


def test_missing_binary_marks_run_failed_without_resolving(pipeline, monkeypatch):
    from sqlmodel import Session, select
    from app.models import RunStatus, ScanRun
    from app.services.targets import add_targets

    db, scanner = pipeline["db"], pipeline["scanner"]
    with Session(db.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])

    monkeypatch.setenv("VMDR_NUCLEI_BIN", str(pipeline["tmp"] / "does-not-exist"))
    from app import config
    config.get_settings.cache_clear()

    run_id = _queue_run(db)
    scanner.execute_run(run_id)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.FAILED
        assert "not found" in run.error
    config.get_settings.cache_clear()


def test_orphaned_running_run_is_recovered_on_startup(pipeline):
    from sqlmodel import Session
    from app.models import RunStatus, ScanRun
    import app.worker as worker

    importlib.reload(worker)  # bind worker.engine to this test's database
    db = pipeline["db"]
    run_id = _queue_run(db)
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        run.status = RunStatus.RUNNING
        s.add(run)
        s.commit()

    assert worker.recover_orphaned_runs() == 1
    with Session(db.engine) as s:
        run = s.get(ScanRun, run_id)
        assert run.status == RunStatus.FAILED and "interrupted" in run.error
    assert worker.recover_orphaned_runs() == 0
