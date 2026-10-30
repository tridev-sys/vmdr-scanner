"""Bulk ingest behaviour: counts and statuses match the per-row semantics, and query count does not scale with findings."""

from types import SimpleNamespace

import pytest
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

import app.services.ingest as ingest_mod
from app.models import Target, Vulnerability, VulnStatus
from app.services.nuclei import Finding
from app.services.ingest import ingest

SEVERITIES = ["critical", "high", "medium", "low"]
HOSTS = ["https://alpha.example.com", "https://beta.example.com", "https://gamma.example.com"]


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setattr(ingest_mod, "get_settings", lambda: SimpleNamespace(resolve_after_misses=2))


def _engine(path):
    engine = create_engine(f"sqlite:///{path}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        for url in HOSTS:
            host = url.split("://", 1)[1]
            s.add(Target(url=url, host=host, domain_root=host.split(".", 1)[1]))
        s.commit()
    return engine


def _finding(host, index, severity=None, template=None):
    return Finding(
        template_id=template or f"tpl-{index:04d}",
        cve_id=None,
        name=f"Finding {index}",
        severity=severity or SEVERITIES[index % 4],
        host=host,
        matched_at=f"{host}/p/{index}",
        matcher_name=None,
        curl_command=None,
        description=None,
        remediation=None,
        cvss_score=None,
    )


def _batch(count, skip=frozenset()):
    """`count` findings spread across the three targets; `skip` holds indexes to leave out."""
    return [_finding(HOSTS[i % 3], i) for i in range(count) if i not in skip]


def _run(engine, findings, run_id=1, resolve=True):
    with Session(engine) as s:
        targets = s.exec(select(Target).order_by(Target.id)).all()
        return ingest(s, run_id, targets, findings, 0, resolve=resolve)


def _rows(engine):
    with Session(engine) as s:
        return {v.fingerprint: v for v in s.exec(select(Vulnerability)).all()}


def _status_counts(engine):
    counts: dict[str, int] = {}
    for v in _rows(engine).values():
        counts[v.status] = counts.get(v.status, 0) + 1
    return counts


def _count_selects(engine, fn):
    statements: list[str] = []

    def before(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", before)
    try:
        result = fn()
    finally:
        event.remove(engine, "before_cursor_execute", before)
    return len(statements), result


def test_300_findings_across_3_targets_match_expected_counts_and_statuses(tmp_path):
    engine = _engine(tmp_path / "bulk.db")
    all_300 = _batch(300)
    # 100 findings per target; 75 of each severity overall, so 150 critical-or-high alerts.
    stats = _run(engine, all_300 + [_finding("https://unknown.example.org", i) for i in range(5)], run_id=1)
    assert (stats.findings_total, stats.new, stats.updated, stats.reopened, stats.resolved) == (300, 300, 0, 0, 0)
    assert stats.unmatched == 5
    assert len(stats.alerts) == 150
    assert _status_counts(engine) == {VulnStatus.OPEN: 300}

    # Run 2: the 10 lowest-index findings per target disappear. One miss keeps them OPEN.
    gone = {i for i in range(300) if i // 3 < 10}  # 10 per target, since index % 3 picks the target
    stats = _run(engine, _batch(300, skip=frozenset(gone)), run_id=2)
    assert (stats.new, stats.updated, stats.resolved) == (0, 270, 0)
    assert _status_counts(engine) == {VulnStatus.OPEN: 300}

    # Run 3: the second miss resolves them.
    stats = _run(engine, _batch(300, skip=frozenset(gone)), run_id=3)
    assert (stats.new, stats.updated, stats.resolved) == (0, 270, 30)
    assert _status_counts(engine) == {VulnStatus.OPEN: 270, VulnStatus.RESOLVED: 30}
    with Session(engine) as s:
        targets = s.exec(select(Target).order_by(Target.id)).all()
        assert [(t.last_open_findings, t.last_result) for t in targets] == [(90, "VULNERABLE")] * 3
        assert all(t.last_scan_status == "COMPLETED" and t.last_scanned_at for t in targets)

    # Run 4: everything is back. The 30 RESOLVED rows reopen.
    stats = _run(engine, _batch(300), run_id=4)
    assert (stats.new, stats.reopened, stats.updated, stats.resolved) == (0, 30, 300, 0)
    assert _status_counts(engine) == {VulnStatus.OPEN: 300}
    rows = _rows(engine)
    assert all(v.missed_scans == 0 and v.resolved_at is None and v.last_run_id == 4 for v in rows.values())


def test_select_count_does_not_grow_with_findings(tmp_path):
    counts = {}
    for n in (50, 500):
        engine = _engine(tmp_path / f"q{n}.db")
        findings = _batch(n)
        selects, stats = _count_selects(engine, lambda: _run(engine, findings, run_id=1))
        assert stats.new == n
        counts[n] = selects
    assert counts[50] == counts[500], counts
    assert counts[500] <= 6, counts


def test_batch_larger_than_in_chunk_size_is_fully_matched(tmp_path):
    """1200 fingerprints need three IN-list chunks; every existing row must still be found and updated."""
    engine = _engine(tmp_path / "chunks.db")
    findings = _batch(1200)
    assert _run(engine, findings, run_id=1).new == 1200
    stats = _run(engine, findings, run_id=2)
    assert (stats.new, stats.updated) == (0, 1200)
    assert len(_rows(engine)) == 1200


def test_duplicate_fingerprint_in_one_batch_creates_one_row(tmp_path):
    engine = _engine(tmp_path / "dup.db")
    dupes = [_finding(HOSTS[0], 1, severity="critical"), _finding(HOSTS[0], 1, severity="critical")]
    stats = _run(engine, dupes)
    assert (stats.new, stats.updated) == (1, 1)
    assert len(_rows(engine)) == 1


def test_resolved_finding_reopens_and_auto_resolution_needs_threshold(tmp_path):
    engine = _engine(tmp_path / "lifecycle.db")
    finding = [_finding(HOSTS[0], 7, severity="high")]
    assert _run(engine, finding, run_id=1).new == 1

    # One miss: still OPEN, counter at 1.
    stats = _run(engine, [], run_id=2)
    assert stats.resolved == 0
    (row,) = _rows(engine).values()
    assert row.status == VulnStatus.OPEN and row.missed_scans == 1

    # Second miss: auto-resolved.
    stats = _run(engine, [], run_id=3)
    assert stats.resolved == 1
    (row,) = _rows(engine).values()
    assert row.status == VulnStatus.RESOLVED and row.resolved_at is not None

    # Finding returns: reopened, resolved_at cleared, counter reset.
    stats = _run(engine, finding, run_id=4)
    assert (stats.reopened, stats.updated, stats.new) == (1, 1, 0)
    (row,) = _rows(engine).values()
    assert row.status == VulnStatus.OPEN and row.resolved_at is None and row.missed_scans == 0


def test_partial_run_never_counts_misses(tmp_path):
    engine = _engine(tmp_path / "partial.db")
    finding = [_finding(HOSTS[1], 3)]
    _run(engine, finding, run_id=1)
    for run_id in (2, 3, 4):
        stats = _run(engine, [], run_id=run_id, resolve=False)
        assert stats.resolved == 0
    (row,) = _rows(engine).values()
    assert row.status == VulnStatus.OPEN and row.missed_scans == 0
