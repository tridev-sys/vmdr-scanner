"""Rolling schedule: quota, due-target ordering and exclusion, and batch enqueueing."""

import importlib
from datetime import timedelta

import pytest

@pytest.fixture()
def sched(tmp_path, monkeypatch):
    monkeypatch.setenv("VMDR_DATABASE_URL", f"sqlite:///{tmp_path}/sched.db")
    monkeypatch.setenv("VMDR_SCAN_WORKDIR", str(tmp_path / "scans"))

    from app import config
    config.get_settings.cache_clear()
    import app.db as db
    importlib.reload(db)
    db.init_db()
    import app.services.schedule as schedule
    yield {"db": db, "schedule": schedule}
    config.get_settings.cache_clear()


def _add_target(session, n, last_scanned_at=None, status="ACTIVE"):
    from app.models import Target
    t = Target(url=f"https://t{n}.example.com", host=f"t{n}.example.com",
               domain_root=f"example.com", status=status, last_scanned_at=last_scanned_at)
    session.add(t)
    session.commit()
    session.refresh(t)
    return t.id


def _now():
    from app.models import utcnow
    return utcnow()


# ---- daily_quota -----------------------------------------------------------

def test_daily_quota_zero_active(sched):
    assert sched["schedule"].daily_quota(0, 7) == 0


def test_daily_quota_one_active_is_at_least_one(sched):
    assert sched["schedule"].daily_quota(1, 7) == 1


def test_daily_quota_exact_division(sched):
    assert sched["schedule"].daily_quota(14, 7) == 2


def test_daily_quota_uneven_rounds_up(sched):
    assert sched["schedule"].daily_quota(15, 7) == 3
    assert sched["schedule"].daily_quota(20000, 7) == 2858


# ---- due_target_ids ordering and exclusion --------------------------------

def test_due_order_never_scanned_then_oldest_then_id(sched):
    from sqlmodel import Session
    db, schedule = sched["db"], sched["schedule"]
    now = _now()
    with Session(db.engine) as s:
        t_never_a = _add_target(s, 1)
        t_old = _add_target(s, 2, last_scanned_at=now - timedelta(days=10))
        t_oldest = _add_target(s, 3, last_scanned_at=now - timedelta(days=20))
        t_never_b = _add_target(s, 4)
        ids = schedule.due_target_ids(s, 7, now)
    assert ids == [t_never_a, t_never_b, t_oldest, t_old]


def test_recently_scanned_targets_excluded(sched):
    from sqlmodel import Session
    db, schedule = sched["db"], sched["schedule"]
    now = _now()
    with Session(db.engine) as s:
        fresh = _add_target(s, 1, last_scanned_at=now - timedelta(days=1))
        boundary = _add_target(s, 2, last_scanned_at=now - timedelta(days=7, seconds=5))
        ids = schedule.due_target_ids(s, 7, now)
    assert fresh not in ids
    assert boundary in ids


def test_inactive_targets_excluded(sched):
    from sqlmodel import Session
    db, schedule = sched["db"], sched["schedule"]
    with Session(db.engine) as s:
        paused = _add_target(s, 1, status="PAUSED")
        active = _add_target(s, 2)
        ids = schedule.due_target_ids(s, 7, _now())
    assert ids == [active]
    assert paused not in ids


def test_targets_in_queued_run_excluded(sched):
    from sqlmodel import Session
    from app.models import RunScope, RunStatus, ScanRun
    db, schedule = sched["db"], sched["schedule"]
    with Session(db.engine) as s:
        a = _add_target(s, 1)
        b = _add_target(s, 2)
        s.add(ScanRun(scope=RunScope.TARGETS, target_ids=[a], status=RunStatus.QUEUED))
        s.commit()
        ids = schedule.due_target_ids(s, 7, _now())
    assert ids == [b]


def test_targets_in_running_run_excluded(sched):
    from sqlmodel import Session
    from app.models import RunScope, RunStatus, ScanRun
    db, schedule = sched["db"], sched["schedule"]
    with Session(db.engine) as s:
        a = _add_target(s, 1)
        b = _add_target(s, 2)
        s.add(ScanRun(scope=RunScope.TARGETS, target_ids=[b], status=RunStatus.RUNNING))
        s.commit()
        ids = schedule.due_target_ids(s, 7, _now())
    assert ids == [a]


def test_limit_applies_after_ordering(sched):
    from sqlmodel import Session
    db, schedule = sched["db"], sched["schedule"]
    now = _now()
    with Session(db.engine) as s:
        _add_target(s, 1, last_scanned_at=now - timedelta(days=30))
        oldest_never = _add_target(s, 2)
        _add_target(s, 3, last_scanned_at=now - timedelta(days=9))
        ids = schedule.due_target_ids(s, 7, now, limit=1)
    assert ids == [oldest_never]


# ---- enqueue_rolling_batch --------------------------------------------------

def test_enqueue_creates_one_targets_run_with_quick_preset(sched):
    from sqlmodel import Session, select
    from app.models import RunScope, RunStatus, ScanRun
    db, schedule = sched["db"], sched["schedule"]
    with Session(db.engine) as s:
        for n in range(1, 15):  # 14 active, cycle 7 -> quota 2
            _add_target(s, n)
        run_id = schedule.enqueue_rolling_batch(s, "quick", 7)
        assert run_id is not None
        runs = s.exec(select(ScanRun)).all()
        assert len(runs) == 1
        run = runs[0]
        assert run.id == run_id
        assert run.scope == RunScope.TARGETS
        assert run.status == RunStatus.QUEUED
        assert len(run.target_ids) == 2
        assert run.requested_by == "scheduler"
        assert run.preset == "quick"
        assert run.cve_years == 1
        assert run.rate_limit == 150
        assert run.severities == "critical,high"


def test_enqueue_deep_preset_has_no_cve_window(sched):
    from sqlmodel import Session
    db, schedule = sched["db"], sched["schedule"]
    from app.models import ScanRun
    with Session(db.engine) as s:
        _add_target(s, 1)
        run_id = schedule.enqueue_rolling_batch(s, "deep", 30)
        run = s.get(ScanRun, run_id)
        assert run.preset == "deep"
        assert run.cve_years is None
        assert run.rate_limit is None
        assert run.target_ids == [1]


def test_enqueue_returns_none_when_nothing_due(sched):
    from sqlmodel import Session, select
    db, schedule = sched["db"], sched["schedule"]
    from app.models import ScanRun
    now = _now()
    with Session(db.engine) as s:
        _add_target(s, 1, last_scanned_at=now - timedelta(hours=2))
        assert schedule.enqueue_rolling_batch(s, "quick", 7, now=now) is None
        assert s.exec(select(ScanRun)).all() == []


def test_enqueue_returns_none_with_no_active_targets(sched):
    from sqlmodel import Session
    db, schedule = sched["db"], sched["schedule"]
    with Session(db.engine) as s:
        _add_target(s, 1, status="ARCHIVED")
        assert schedule.enqueue_rolling_batch(s, "quick", 7) is None


def test_enqueue_skips_targets_already_queued(sched):
    from sqlmodel import Session
    from app.models import RunScope, RunStatus, ScanRun
    db, schedule = sched["db"], sched["schedule"]
    with Session(db.engine) as s:
        a = _add_target(s, 1)
        b = _add_target(s, 2)
        s.add(ScanRun(scope=RunScope.TARGETS, target_ids=[a], status=RunStatus.QUEUED))
        s.commit()
        run_id = schedule.enqueue_rolling_batch(s, "quick", 7)
        run = s.get(ScanRun, run_id)
        assert run.target_ids == [b]


def test_deep_cycle_ignores_recent_quick_scans(sched):
    """A quick scan must not make a target look deep-covered: deep uses its own column."""
    from datetime import timedelta
    from sqlmodel import Session
    from app.models import Target
    db, schedule = sched["db"], sched["schedule"]
    now = _now()
    with Session(db.engine) as s:
        tid = _add_target(s, 1, last_scanned_at=now - timedelta(days=1))  # quick-scanned yesterday
    with Session(db.engine) as s:
        assert schedule.due_target_ids(s, 30, now) == []  # quick coverage is recent
        assert schedule.due_target_ids(s, 30, now, field="last_deep_scanned_at") == [tid]  # never deep-scanned
        t = s.get(Target, tid)
        t.last_deep_scanned_at = now - timedelta(days=1)
        s.add(t)
        s.commit()
        assert schedule.due_target_ids(s, 30, now, field="last_deep_scanned_at") == []
