"""Scan reports: one downloadable JSON file per completed run, with CVE and patch details.

A report is written for every completed run, including runs that found nothing.
Reports older than the retention window (VMDR_REPORT_RETENTION_DAYS, default 5) are deleted.
"""

import json
import logging
from datetime import timedelta
from pathlib import Path

from sqlmodel import Session, select

from app.config import get_settings
from app.models import Report, RunScope, ScanRun, Target, TargetStatus, Vulnerability, VulnStatus, utcnow

logger = logging.getLogger(__name__)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def reports_dir() -> Path:
    path = get_settings().scan_workdir / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cvss_band(score: float | None, severity: str) -> str:
    """CVSS v3 band; falls back to the Nuclei severity when no score is present."""
    if score is None:
        return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM"}.get(severity, "LOW")
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _run_targets(session: Session, run: ScanRun) -> list[Target]:
    if run.scope == RunScope.TARGET:
        target = session.get(Target, run.target_id) if run.target_id else None
        return [target] if target else []
    if run.scope == RunScope.TARGETS:
        ids = run.target_ids or []
        return list(session.exec(select(Target).where(Target.id.in_(ids)).order_by(Target.id)).all()) if ids else []
    return list(session.exec(
        select(Target).where(Target.status == TargetStatus.ACTIVE).order_by(Target.id)
    ).all())


def build_payload(session: Session, run: ScanRun) -> dict:
    targets = _run_targets(session, run)
    findings = session.exec(
        select(Vulnerability).where(Vulnerability.last_run_id == run.id).order_by(Vulnerability.id)
    ).all()

    target_rows = [{
        "id": t.id,
        "url": t.url,
        "host": t.host,
        "reachability": t.reachability,
        "result": t.last_result or ("UNREACHABLE" if t.reachability == "UNREACHABLE" else "NOT_SCANNED"),
        "open_findings": t.last_open_findings,
        "probe_error": t.last_probe_error,
    } for t in targets]

    finding_rows = [{
        "cve_id": v.cve_id,
        "cvss_v3_score": v.cvss_score,
        "cvss_band": cvss_band(v.cvss_score, v.severity),
        "severity": v.severity,
        "name": v.name,
        "template_id": v.template_id,
        "target_url": v.target_url,
        "matched_at": v.matched_at,
        "matcher_name": v.matcher_name,
        "status": v.status,
        "description": v.description,
        "patch_guidance": v.remediation,
        "reproduce_curl": v.curl_command,
        "first_seen_at": v.first_seen_at.isoformat(),
        "last_seen_at": v.last_seen_at.isoformat(),
    } for v in findings]

    # One entry per CVE (or per template when no CVE id), listing every affected target and its patch guidance.
    cves: dict[str, dict] = {}
    for row in finding_rows:
        key = row["cve_id"] or f"template:{row['template_id']}"
        entry = cves.setdefault(key, {
            "cve_id": row["cve_id"],
            "name": row["name"],
            "cvss_v3_score": row["cvss_v3_score"],
            "cvss_band": row["cvss_band"],
            "severity": row["severity"],
            "description": row["description"],
            "patch_guidance": row["patch_guidance"],
            "affected_targets": [],
        })
        if row["target_url"] not in entry["affected_targets"]:
            entry["affected_targets"].append(row["target_url"])
    cve_rows = sorted(
        cves.values(),
        key=lambda c: (-(c["cvss_v3_score"] or 0), SEVERITY_ORDER.index(c["severity"]) if c["severity"] in SEVERITY_ORDER else 99),
    )

    by_severity = {s: 0 for s in SEVERITY_ORDER}
    for row in finding_rows:
        by_severity[row["severity"] if row["severity"] in by_severity else "unknown"] += 1

    return {
        "report_version": 1,
        "generated_at": utcnow().isoformat(),
        "retention_days": get_settings().report_retention_days,
        "run": {
            "id": run.id,
            "scope": run.scope,
            "preset": run.preset,
            "cve_years": run.cve_years,
            "severities": run.severities.split(",") if run.severities else [],
            "status": run.status,
            "requested_by": run.requested_by,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "duration_seconds": (
                round((run.finished_at - run.started_at).total_seconds(), 1)
                if run.started_at and run.finished_at else None
            ),
        },
        "summary": {
            "targets_total": len(target_rows),
            "targets_scanned": run.targets_scanned,
            "targets_unreachable": run.unreachable_count,
            "targets_clean": sum(1 for t in target_rows if t["result"] == "CLEAN"),
            "targets_vulnerable": sum(1 for t in target_rows if t["result"] == "VULNERABLE"),
            "findings_total": len(finding_rows),
            "cves_total": len({c["cve_id"] for c in cve_rows if c["cve_id"]}),
            "by_severity": by_severity,
        },
        "targets": target_rows,
        "cves": cve_rows,
        "findings": finding_rows,
    }


def write_report(session: Session, run: ScanRun) -> Report:
    payload = build_payload(session, run)
    stamp = utcnow().strftime("%Y%m%dT%H%M%S")
    file_name = f"report-run{run.id}-{stamp}.json"
    path = reports_dir() / file_name
    text = json.dumps(payload, indent=2, default=str)
    path.write_text(text, encoding="utf-8")
    report = Report(
        run_id=run.id,
        file_name=file_name,
        size_bytes=path.stat().st_size,
        findings_count=payload["summary"]["findings_total"],
        targets_count=payload["summary"]["targets_total"],
    )
    session.add(report)
    session.commit()
    session.refresh(report)
    return report


def purge_expired(session: Session, now=None) -> int:
    """Delete reports (file and row) older than the retention window. Returns how many were removed."""
    now = now or utcnow()
    cutoff = now - timedelta(days=get_settings().report_retention_days)
    removed = 0
    for report in session.exec(select(Report).where(Report.created_at < cutoff)).all():
        (reports_dir() / report.file_name).unlink(missing_ok=True)
        session.delete(report)
        removed += 1
    session.commit()
    return removed
