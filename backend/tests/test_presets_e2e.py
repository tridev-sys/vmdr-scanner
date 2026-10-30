"""A preset sent to the API must reach the scanner as the right Nuclei arguments."""

import json
import sys

from tests.test_worker_pipeline import pipeline  # noqa: F401  (fixture)

RECORDER = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["REC_LOG"], "a") as fh:
    fh.write(json.dumps(args) + "\\n")
open(args[args.index("-o") + 1], "w").close()
"""


def _setup(pipeline, monkeypatch):
    from app import config
    from app.services.targets import add_targets
    from sqlmodel import Session

    tmp = pipeline["tmp"]
    rec = tmp / "recorder"
    rec.write_text(RECORDER)
    rec.chmod(0o755)
    templates = tmp / "templates"
    year = __import__("datetime").datetime.now().year
    for path in [f"http/cves/{year}", f"http/cves/{year - 15}", "http/misc"]:
        (templates / path).mkdir(parents=True)
    monkeypatch.setenv("VMDR_NUCLEI_BIN", str(rec))
    monkeypatch.setenv("VMDR_NUCLEI_TEMPLATES_DIR", str(templates))
    monkeypatch.setenv("REC_LOG", str(tmp / "rec.log"))
    config.get_settings.cache_clear()
    with Session(pipeline["db"].engine) as s:
        add_targets(s, urls=["https://kai.buckleconsult.com"])
        from sqlmodel import select
        from app.models import Target
        return s.exec(select(Target.id)).first(), year


def _calls(tmp):
    log = tmp / "rec.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_quick_preset_reaches_scanner_with_window_and_rate(pipeline, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlmodel import Session
    from app.main import app
    from app.models import ScanRun

    target_id, year = _setup(pipeline, monkeypatch)
    client = TestClient(app)
    resp = client.post("/api/scans/trigger", json={"scope": "targets", "target_ids": [target_id], "preset": "quick"})
    assert resp.status_code == 202
    body = resp.json()
    assert body["preset"] == "quick" and body["cve_years"] == 1 and body["rate_limit"] == 150

    with Session(pipeline["db"].engine) as s:
        run = s.get(ScanRun, body["id"])
        assert run.severities == "critical,high"

    pipeline["scanner"].execute_run(body["id"])

    calls = _calls(pipeline["tmp"])
    assert len(calls) == 2, calls  # window pass, then non-CVE pass
    window, rest = calls
    # Window pass: only the current-year CVE folder, at the preset rate.
    assert window[window.index("-t") + 1].endswith(f"http/cves/{year}")
    assert window.count("-t") == 1 and "-et" not in window
    assert window[window.index("-rate-limit") + 1] == "150"
    assert window[window.index("-severity") + 1] == "critical,high"
    # Rest pass: every CVE folder excluded, nothing else restricted.
    excluded = [rest[i + 1] for i, a in enumerate(rest) if a == "-et"]
    assert any(p.endswith(f"http/cves/{year}") for p in excluded)
    assert any(p.endswith(f"http/cves/{year - 15}") for p in excluded)
    assert "-t" not in rest
    assert rest[rest.index("-rate-limit") + 1] == "150"

    with Session(pipeline["db"].engine) as s:
        assert s.get(ScanRun, body["id"]).status == "COMPLETED"
