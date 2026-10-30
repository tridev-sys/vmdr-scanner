"""Thin wrapper around the ProjectDiscovery Nuclei CLI: command build, template update, JSONL parsing."""

import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.services.process import run_process
from app.utils import SEVERITIES, hostname_of

logger = logging.getLogger(__name__)
MAX_EXCERPT = 4000


@dataclass
class Finding:
    template_id: str
    cve_id: str | None
    name: str
    severity: str
    host: str
    matched_at: str
    matcher_name: str | None
    curl_command: str | None
    description: str | None
    remediation: str | None
    cvss_score: float | None
    tags: list[str] = field(default_factory=list)
    request: str | None = None
    response: str | None = None
    timestamp: str | None = None


def recent_cve_dirs(root: Path, years: list[int]) -> list[str]:
    """Template directories holding CVEs from the given years, e.g. <root>/http/cves/2026."""
    if not years or not root.is_dir():
        return []
    dirs = {str(p) for year in years for p in root.glob(f"**/cves/{year}") if p.is_dir()}
    return sorted(dirs)


def all_cve_dirs(root: Path) -> list[str]:
    """Every year-named CVE template directory, for excluding CVE templates from a pass."""
    if not root.is_dir():
        return []
    return sorted(str(p) for p in root.glob("**/cves/*") if p.is_dir() and p.name.isdigit())


def build_command(
    targets_file: Path,
    output_file: Path,
    severities: list[str],
    templates: list[str] | None = None,
    exclude: list[str] | None = None,
    rate_limit: int | None = None,
) -> list[str]:
    s = get_settings()
    cmd = [
        s.nuclei_bin,
        "-list", str(targets_file),
        "-severity", ",".join(severities),
        "-rate-limit", str(rate_limit or s.nuclei_rate_limit),
        "-concurrency", str(s.nuclei_concurrency),
        "-bulk-size", str(s.nuclei_bulk_size),
        "-retries", str(s.nuclei_retries),
        "-timeout", str(s.nuclei_timeout),
        "-jsonl",
        "-o", str(output_file),
        "-silent",
        "-no-color",
        # Progress lines go to the run log so a long scan shows what it is doing.
        "-stats", "-stats-interval", "15",
    ]
    for path in templates or []:
        cmd += ["-t", path]
    for path in exclude or []:
        cmd += ["-et", path]
    return cmd


def update_templates(stop_event: threading.Event | None = None, log_path: Path | None = None) -> tuple[bool, str]:
    """Run `nuclei -update-templates`. Returns (ok, last output lines). An interrupted update returns (False, "interrupted")."""
    s = get_settings()
    cmd = [s.nuclei_bin, "-update-templates", "-silent", "-no-color"]
    log_path = log_path or Path(s.scan_workdir) / "template-update.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        outcome = run_process(cmd, log_path, s.nuclei_template_update_timeout_s, stop_event or threading.Event())
    except FileNotFoundError:
        return False, f"nuclei binary not found at {s.nuclei_bin}"
    if outcome.interrupted:
        return False, "interrupted"
    if outcome.timed_out:
        return False, "template update timed out"
    tail = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-20:])
    return outcome.returncode == 0, tail


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _truncate(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= MAX_EXCERPT else text[:MAX_EXCERPT] + "\n…[truncated]"


def normalize_event(ev: dict[str, Any]) -> Finding | None:
    info = ev.get("info") or {}
    classification = info.get("classification") or {}
    template_id = ev.get("template-id") or ev.get("template_id") or ev.get("templateID")
    if not template_id:
        return None

    severity = str(info.get("severity") or "unknown").lower()
    if severity not in SEVERITIES:
        severity = "unknown"

    cve = _first(classification.get("cve-id"))
    cvss = _first(classification.get("cvss-score"))
    try:
        cvss = float(cvss) if cvss not in (None, "") else None
    except (TypeError, ValueError):
        cvss = None

    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    host = ev.get("host") or ev.get("input") or ""
    return Finding(
        template_id=str(template_id),
        cve_id=str(cve).upper() if cve else None,
        name=str(info.get("name") or template_id),
        severity=severity,
        host=str(host),
        matched_at=str(ev.get("matched-at") or host),
        matcher_name=ev.get("matcher-name") or None,
        curl_command=ev.get("curl-command") or None,
        description=info.get("description") or None,
        remediation=info.get("remediation") or None,
        cvss_score=cvss,
        tags=[str(t) for t in tags],
        request=_truncate(ev.get("request")),
        response=_truncate(ev.get("response")),
        timestamp=ev.get("timestamp"),
    )


def parse_jsonl(path: Path) -> tuple[list[Finding], int]:
    """Parse Nuclei JSONL output. Returns (findings, count_of_unparseable_lines)."""
    findings: list[Finding] = []
    bad = 0
    if not path.exists():
        return findings, bad
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            finding = normalize_event(ev) if isinstance(ev, dict) else None
            if finding is None:
                bad += 1
            else:
                findings.append(finding)
    return findings, bad


def match_target_host(finding: Finding) -> str | None:
    return hostname_of(finding.host) or hostname_of(finding.matched_at)
