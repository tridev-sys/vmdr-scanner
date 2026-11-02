"""The benchmark must be honest: every planted flaw responds to its exploit, and the scorer is exact."""

import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen
from urllib.error import HTTPError

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import app as bench_app  # noqa: E402
import manifest  # noqa: E402
import score  # noqa: E402

EXPLOIT = {
    "sqli": ("1'", "SQL syntax"),
    "xss": ("<script>x</script>", "<script>x</script>"),
    "ssti": ("{{7*7}}", "49"),
    "lfi": ("../../etc/passwd", "root:x:0:0"),
    "rce": ("1;id", "uid=0(root)"),
    "ssrf": ("http://127.0.0.1/", "ami-id"),
}


@pytest.fixture(scope="module")
def base():
    server = ThreadingHTTPServer(("127.0.0.1", 0), bench_app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _get(url):
    try:
        with urlopen(url, timeout=5) as r:
            return r.status, r.read().decode()
    except HTTPError as e:
        return e.code, e.read().decode()


def test_manifest_has_expected_shape():
    flaws = manifest.flaws()
    assert len(flaws) == 84
    ids = [f["id"] for f in flaws]
    assert len(ids) == len(set(ids))
    assert {f["cls"] for f in flaws} == set(EXPLOIT) | {"idor", "exposure"}


@pytest.mark.parametrize("flaw", [f for f in manifest.flaws() if f["location"] == "query"], ids=lambda f: f["id"])
def test_every_query_flaw_responds_to_its_exploit(base, flaw):
    payload, marker = EXPLOIT[flaw["cls"]]
    _, body = _get(f"{base}{flaw['path']}?{flaw['param']}={quote(payload)}")
    assert marker in body, f"{flaw['id']} did not respond to its exploit"


@pytest.mark.parametrize("flaw", [f for f in manifest.flaws() if f["location"] == "path"], ids=lambda f: f["id"])
def test_every_path_flaw_is_reachable(base, flaw):
    status, body = _get(f"{base}{flaw['path']}")
    assert status == 200 and body


def test_clean_input_does_not_trigger_lfi_or_rce(base):
    _, body = _get(f"{base}/bm/rce/0?host=localhost")
    assert "uid=0" not in body
    _, body = _get(f"{base}/bm/lfi/0?file=readme.txt")
    assert "root:x" not in body


def _finding(path, template_id, matched=None):
    return {"template_id": template_id, "name": "", "tags": [], "matched_at": matched or f"http://h{path}?x=1"}


def test_scorer_full_recall_passes():
    key = manifest.answer_key()
    findings = []
    keyword = {"sqli": "sql-injection", "xss": "xss-reflected", "ssti": "ssti-math", "lfi": "lfi-linux",
               "rce": "rce-cmd", "ssrf": "ssrf-generic", "idor": "idor-notes", "exposure": "env-exposure"}
    for flaw in key["flaws"]:
        findings.append(_finding(flaw["path"], keyword[flaw["cls"]]))
    result = score.score(key, findings)
    assert result["recall"] == 1.0
    assert all(s["recall"] == 1.0 for s in result["classes"].values())


def test_scorer_counts_misses_per_class():
    key = manifest.answer_key()
    sqli_paths = [f["path"] for f in key["flaws"] if f["cls"] == "sqli"]
    findings = [_finding(p, "sql-injection-error") for p in sqli_paths[:6]]
    result = score.score(key, findings)
    assert result["classes"]["sqli"]["found"] == 6
    assert result["classes"]["sqli"]["total"] == len(sqli_paths)
    assert result["classes"]["xss"]["found"] == 0


def test_wrong_class_on_right_endpoint_is_a_miss():
    key = {"flaws": [{"id": "x", "cls": "xss", "path": "/bm/xss/0"}]}
    result = score.score(key, [_finding("/bm/xss/0", "sql-injection")])
    assert result["found"] == 0


def test_path_match_is_exact_not_prefix():
    key = {"flaws": [{"id": "x", "cls": "xss", "path": "/bm/xss/1"}]}
    result = score.score(key, [_finding("/bm/xss/10", "xss-reflected")])
    assert result["found"] == 0


def test_answer_key_file_matches_manifest(tmp_path):
    on_disk = json.loads((HERE / "answer_key.json").read_text(encoding="utf-8"))
    assert on_disk == manifest.answer_key()


def test_index_links_every_flaw(base):
    _, body = _get(f"{base}/")
    for flaw in manifest.flaws():
        assert f'href="{flaw["path"]}' in body, f"index does not link {flaw['id']}"
