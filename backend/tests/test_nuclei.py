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
