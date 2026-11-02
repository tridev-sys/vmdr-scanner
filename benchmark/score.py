"""Score a VMDR scan against the benchmark answer key.

A flaw counts as found when some finding has (a) matched_at on the flaw's endpoint path and
(b) a template_id, name, or tag that belongs to the flaw's class. Recall is found / total per class.

Input: a JSON list of findings, e.g. the `items` of GET /api/vulnerabilities?target_id=<id>&page_size=500
(only the fields template_id, name, tags, matched_at are read).

Usage: python score.py findings.json [--gate 0.95]
Exit status 1 when any class (or the total) is below the gate, so a nightly run can block a release.
"""

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

CLASS_KEYWORDS = {
    "sqli": ["sql"],
    "xss": ["xss"],
    "ssti": ["ssti", "template-injection", "template injection"],
    "lfi": ["lfi", "traversal", "file-inclusion", "file inclusion", "local-file"],
    "rce": ["rce", "command", "cmdi", "os-command"],
    "ssrf": ["ssrf"],
    "idor": ["idor", "bola", "authorization"],
    "exposure": ["exposure", "disclosure", "env", "misconfig"],
}


def _belongs(finding: dict, cls: str) -> bool:
    text = " ".join([
        str(finding.get("template_id") or ""),
        str(finding.get("name") or ""),
        " ".join(finding.get("tags") or []),
    ]).lower()
    return any(keyword in text for keyword in CLASS_KEYWORDS[cls])


def _on_path(finding: dict, path: str) -> bool:
    matched = str(finding.get("matched_at") or finding.get("target_url") or "")
    return re.search(re.escape(path) + r"(?:[?/#]|$)", matched) is not None


def score(answer_key: dict, findings: list[dict]) -> dict:
    per_class: dict[str, dict] = {}
    for flaw in answer_key["flaws"]:
        stats = per_class.setdefault(flaw["cls"], {"total": 0, "found": 0, "missed": []})
        stats["total"] += 1
        hit = any(_on_path(f, flaw["path"]) and _belongs(f, flaw["cls"]) for f in findings)
        if hit:
            stats["found"] += 1
        else:
            stats["missed"].append(flaw["id"])
    for stats in per_class.values():
        stats["recall"] = stats["found"] / stats["total"] if stats["total"] else 0.0
    total = sum(s["total"] for s in per_class.values())
    found = sum(s["found"] for s in per_class.values())
    return {"total": total, "found": found, "recall": found / total if total else 0.0, "classes": per_class}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("findings", type=Path)
    parser.add_argument("--key", type=Path, default=HERE / "answer_key.json")
    parser.add_argument("--gate", type=float, default=0.95)
    args = parser.parse_args()

    answer_key = json.loads(args.key.read_text(encoding="utf-8"))
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    if isinstance(findings, dict):
        findings = findings.get("items", [])
    result = score(answer_key, findings)

    print(f"overall recall {result['found']}/{result['total']} = {result['recall']:.1%} (gate {args.gate:.0%})")
    failed = result["recall"] < args.gate
    for cls, stats in sorted(result["classes"].items()):
        mark = "FAIL" if stats["recall"] < args.gate else "ok"
        print(f"  {cls:10s} {stats['found']:3d}/{stats['total']:<3d} {stats['recall']:.1%}  {mark}")
        if stats["missed"]:
            print(f"             missed: {', '.join(stats['missed'])}")
        failed = failed or stats["recall"] < args.gate
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
