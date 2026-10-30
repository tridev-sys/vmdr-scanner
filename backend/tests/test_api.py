"""End-to-end API + dedup/resolve tests against a throwaway SQLite database."""

import importlib

import pytest


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("VMDR_DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("VMDR_SCAN_WORKDIR", str(tmp_path / "scan"))
    monkeypatch.setenv("VMDR_RESOLVE_AFTER_MISSES", "2")
    monkeypatch.delenv("VMDR_API_KEY", raising=False)
    from app import config
    config.get_settings.cache_clear()
    import app.db as db
    importlib.reload(db)
    db.init_db()
    yield db
    config.get_settings.cache_clear()


def _finding_event(host: str, template: str = "tmpl-a", matcher: str | None = "m1", severity="high"):
    ev = {
        "template-id": template,
        "info": {"name": template, "severity": severity, "classification": {"cve-id": ["CVE-2024-0001"]}},
        "host": host,
        "matched-at": host + "/x",
    }
    if matcher:
        ev["matcher-name"] = matcher
    return ev


def test_add_targets_dedupes_and_reports_invalid(env):
    from sqlmodel import Session
    from app.services.targets import add_targets
    with Session(env.engine) as s:
        r1 = add_targets(s, urls=["app.koala.cx", "https://app.koala.cx/"], text="ftp://bad\nmail.koala.cx,prod")
    assert len(r1.created) == 2
    assert r1.skipped_duplicates == ["https://app.koala.cx"]
    assert [i.input for i in r1.invalid] == ["ftp://bad"]
    with Session(env.engine) as s:
        r2 = add_targets(s, urls=["app.koala.cx"])
    assert r2.created == [] and r2.skipped_duplicates == ["https://app.koala.cx"]


def test_ingest_dedup_then_resolve_after_two_missed_cycles(env):
    from sqlmodel import Session, select
    from app.models import Target, Vulnerability, VulnStatus
    from app.services.ingest import ingest
    from app.services.nuclei import normalize_event
    from app.services.targets import add_targets

    with Session(env.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
        targets = s.exec(select(Target)).all()
        findings = [normalize_event(_finding_event("https://kai.buckleconsult.com"))]

        r1 = ingest(s, 1, targets, findings, 0, resolve=True)
        assert r1.new == 1 and r1.resolved == 0

        # Same finding again: no duplicate row, just refreshed.
        r2 = ingest(s, 2, targets, findings, 0, resolve=True)
        assert r2.new == 0 and r2.updated == 1
        assert len(s.exec(select(Vulnerability)).all()) == 1

        # Missing once: still OPEN.
        r3 = ingest(s, 3, targets, [], 0, resolve=True)
        v = s.exec(select(Vulnerability)).one()
        assert v.status == VulnStatus.OPEN and v.missed_scans == 1 and r3.resolved == 0

        # Missing twice in a row: RESOLVED.
        r4 = ingest(s, 4, targets, [], 0, resolve=True)
        v = s.exec(select(Vulnerability)).one()
        assert v.status == VulnStatus.RESOLVED and r4.resolved == 1 and v.resolved_at is not None


def test_failed_run_never_resolves(env):
    from sqlmodel import Session, select
    from app.models import Target, Vulnerability, VulnStatus
    from app.services.ingest import ingest
    from app.services.nuclei import normalize_event
    from app.services.targets import add_targets

    with Session(env.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
        targets = s.exec(select(Target)).all()
        ingest(s, 1, targets, [normalize_event(_finding_event("https://kai.buckleconsult.com"))], 0, resolve=True)
        for run in (2, 3, 4):
            ingest(s, run, targets, [], 0, resolve=False)
        assert s.exec(select(Vulnerability)).one().status == VulnStatus.OPEN


def test_triage_false_positive_is_not_auto_resolved(env):
    from sqlmodel import Session, select
    from app.models import Target, Vulnerability, VulnStatus
    from app.services.ingest import ingest
    from app.services.nuclei import normalize_event
    from app.services.targets import add_targets

    with Session(env.engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
        targets = s.exec(select(Target)).all()
        ingest(s, 1, targets, [normalize_event(_finding_event("https://kai.buckleconsult.com"))], 0, resolve=True)
        v = s.exec(select(Vulnerability)).one()
        v.status = VulnStatus.FALSE_POSITIVE
        s.add(v)
        s.commit()
        ingest(s, 2, targets, [], 0, resolve=True)
        ingest(s, 3, targets, [], 0, resolve=True)
        assert s.exec(select(Vulnerability)).one().status == VulnStatus.FALSE_POSITIVE


def test_api_targets_crud_and_scan_trigger(env):
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        assert client.get("/api/health").json() == {"status": "ok"}

        r = client.post("/api/targets", json={"text": "https://a.koala.cx,prod\nhttps://b.heykoala.ai"})
        assert r.status_code == 201
        body = r.json()
        assert len(body["created"]) == 2
        target_id = body["created"][0]["id"]

        page = client.get("/api/targets", params={"domain": "koala.cx"}).json()
        assert page["total"] == 1

        r = client.patch(f"/api/targets/{target_id}", json={"status": "PAUSED"})
        assert r.json()["status"] == "PAUSED"

        # Paused target cannot be scanned on demand.
        assert client.post("/api/scans/trigger", json={"scope": "target", "target_id": target_id}).status_code == 409

        client.patch(f"/api/targets/{target_id}", json={"status": "ACTIVE"})
        r = client.post("/api/scans/trigger", json={"scope": "target", "target_id": target_id})
        assert r.status_code == 202 and r.json()["status"] == "QUEUED"

        # A full scan covers every active target, so it is refused while the target run is queued.
        full = client.post("/api/scans/trigger", json={"scope": "all"})
        assert full.status_code == 409 and f"run {r.json()['id']}" in full.json()["detail"]

        status = client.get("/api/scans/status").json()
        assert status["queue_length"] == 1
        assert status["state"] == "OFFLINE"  # no worker heartbeat in tests

        stats = client.get("/api/stats").json()
        assert stats["total_monitored_endpoints"] == 2
        assert len(stats["last_7_days"]) == 8

        assert client.delete(f"/api/targets/{target_id}").status_code == 204
        assert client.get("/api/targets", params={"domain": "koala.cx"}).json()["total"] == 0


def test_api_key_guards_writes(env, monkeypatch):
    monkeypatch.setenv("VMDR_API_KEY", "s3cret")
    from app import config
    config.get_settings.cache_clear()
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        assert client.post("/api/targets", json={"url": "https://x.koala.cx"}).status_code == 401
        ok = client.post("/api/targets", json={"url": "https://x.koala.cx"}, headers={"X-API-Key": "s3cret"})
        assert ok.status_code == 201
        assert client.get("/api/targets").status_code == 200  # reads stay open
    config.get_settings.cache_clear()


def test_targets_search_by_url_and_tag_does_not_500(tmp_path, monkeypatch):
    """Regression: searching the list (q=...) or filtering by tag returned 500 (bad JSON column cast)."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    client.post("/api/targets", json={"url": "http://13.203.218.232:8080", "tags": ["regress-prod"]})
    client.post("/api/targets", json={"url": "https://other.example.com", "tags": ["regress-dev"]})

    def urls(params):
        r = client.get("/api/targets", params=params)
        assert r.status_code == 200
        return [t["url"] for t in r.json()["items"]]

    assert "http://13.203.218.232:8080" in urls({"q": "13.203.218.232"})
    assert urls({"tag": "regress-dev"}) == ["https://other.example.com"]
    assert "http://13.203.218.232:8080" in urls({"q": "regress-prod"})
