import json
from pathlib import Path

from app.services.nuclei import build_command, normalize_event, parse_jsonl

SAMPLE = {
    "template-id": "CVE-2021-44228",
    "info": {
        "name": "Apache Log4j RCE",
        "severity": "critical",
        "description": "Log4j JNDI lookup",
        "remediation": "Upgrade to 2.17.1",
        "tags": "cve,rce,log4j",
        "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0},
    },
    "matcher-name": "jndi",
    "host": "https://kai.buckleconsult.com",
    "matched-at": "https://kai.buckleconsult.com/login",
    "curl-command": "curl -X GET https://kai.buckleconsult.com/login",
    "timestamp": "2026-10-29T02:00:00Z",
}


def test_normalize_event_extracts_fields():
    f = normalize_event(SAMPLE)
    assert f is not None
    assert f.cve_id == "CVE-2021-44228"
    assert f.severity == "critical"
    assert f.cvss_score == 10.0
    assert f.tags == ["cve", "rce", "log4j"]
    assert f.matcher_name == "jndi"
    assert f.matched_at == "https://kai.buckleconsult.com/login"


def test_normalize_event_rejects_missing_template_and_maps_unknown_severity():
    assert normalize_event({"info": {}}) is None
    ev = {**SAMPLE, "info": {**SAMPLE["info"], "severity": "bogus"}}
    assert normalize_event(ev).severity == "unknown"


def test_parse_jsonl_counts_bad_lines(tmp_path: Path):
    path = tmp_path / "out.jsonl"
    path.write_text(json.dumps(SAMPLE) + "\nnot-json\n\n" + json.dumps({"x": 1}) + "\n", encoding="utf-8")
    findings, bad = parse_jsonl(path)
    assert len(findings) == 1
    assert bad == 2


def test_parse_jsonl_missing_file(tmp_path: Path):
    assert parse_jsonl(tmp_path / "nope.jsonl") == ([], 0)


def test_build_command_matches_production_flags(tmp_path: Path):
    cmd = build_command(tmp_path / "t.txt", tmp_path / "o.jsonl", ["critical", "high", "medium"])
    joined = " ".join(cmd)
    for flag in ("-list", "-rate-limit 50", "-concurrency 10", "-retries 1", "-timeout 5", "-jsonl", "-o"):
        assert flag in joined
    assert "-severity critical,high,medium" in joined


def test_command_sets_bulk_size(tmp_path, monkeypatch):
    from app import config
    from app.services.nuclei import build_command
    monkeypatch.setenv("VMDR_NUCLEI_BULK_SIZE", "50")
    config.get_settings.cache_clear()
    cmd = build_command(tmp_path / "t.txt", tmp_path / "o.jsonl", ["high"])
    assert cmd[cmd.index("-bulk-size") + 1] == "50"
    config.get_settings.cache_clear()


def test_recent_cve_dirs_picks_only_requested_years(tmp_path):
    from app.services.nuclei import recent_cve_dirs
    for path in ["http/cves/2026", "http/cves/2025", "http/cves/2014", "code/cves/2026", "http/misc"]:
        (tmp_path / path).mkdir(parents=True)
    dirs = recent_cve_dirs(tmp_path, [2026, 2025])
    assert len(dirs) == 3
    assert all(d.endswith(("2026", "2025")) for d in dirs)
    assert recent_cve_dirs(tmp_path, []) == []
    assert recent_cve_dirs(tmp_path / "missing", [2026]) == []


def test_build_command_templates_and_exclusions(tmp_path):
    from app.services.nuclei import build_command
    cmd = build_command(tmp_path / "t", tmp_path / "o", ["high"], templates=["/x/2026"], exclude=["/x/2026", "/x/2025"])
    assert cmd.count("-t") == 1 and cmd[cmd.index("-t") + 1] == "/x/2026"
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "-et"] == ["/x/2026", "/x/2025"]
