"""Deduplicate Nuclei findings into the Vulnerability table and resolve findings that disappear."""

from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from sqlmodel import Session, col, select

from app.config import get_settings
from app.models import Target, Vulnerability, VulnStatus, utcnow
from app.services.nuclei import Finding, match_target_host
from app.utils import fingerprint, normalize_target_url

# SQLite caps bound parameters per statement, so IN lists are split into chunks of this size.
IN_CHUNK = 500

T = TypeVar("T")


@dataclass
class IngestStats:
    findings_total: int = 0
    new: int = 0
    reopened: int = 0
    updated: int = 0
    resolved: int = 0
    unmatched: int = 0
    bad_lines: int = 0
    alerts: list[Vulnerability] = field(default_factory=list)


def _chunks(items: Sequence[T], size: int = IN_CHUNK) -> Iterator[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _match_target(f: Finding, by_url: dict[str, Target], by_host: dict[str, Target]) -> Target | None:
    try:
        exact = by_url.get(normalize_target_url(f.host))
    except ValueError:
        exact = None
    return exact or by_host.get(match_target_host(f) or "")


def _apply(vuln: Vulnerability, f: Finding, run_id: int, now) -> None:
    vuln.cve_id = f.cve_id
    vuln.name = f.name
    vuln.severity = f.severity
    vuln.cvss_score = f.cvss_score
    vuln.matched_at = f.matched_at
    vuln.matcher_name = f.matcher_name
    vuln.curl_command = f.curl_command
    vuln.description = f.description
    vuln.remediation = f.remediation
    vuln.request = f.request
    vuln.response = f.response
    vuln.tags = f.tags
    vuln.last_seen_at = now
    vuln.missed_scans = 0
    vuln.last_run_id = run_id


def ingest(
    session: Session,
    run_id: int,
    targets: list[Target],
    findings: list[Finding],
    bad_lines: int,
    resolve: bool,
) -> IngestStats:
    """Upsert findings and, when `resolve` is True (run completed cleanly), age out missing ones.

    `resolve` is False for failed or timed-out runs, so a partial scan never marks findings as fixed.

    Queries are batched: one SELECT loads every existing row whose fingerprint appears in this batch,
    and one SELECT loads the open findings of all scanned targets. Everything else happens in memory.
    """
    now = utcnow()
    settings = get_settings()
    by_url = {t.url: t for t in targets}
    by_host: dict[str, Target] = {}
    for t in targets:
        by_host.setdefault(t.host, t)

    stats = IngestStats(bad_lines=bad_lines)
    seen: dict[int, set[str]] = defaultdict(set)

    matched: list[tuple[Target, Finding, str]] = []
    for f in findings:
        target = _match_target(f, by_url, by_host)
        if target is None:
            stats.unmatched += 1
            continue
        stats.findings_total += 1
        fp = fingerprint(target.url, f.template_id, f.matcher_name)
        seen[target.id].add(fp)
        matched.append((target, f, fp))

    # One round trip per 500 fingerprints: load every existing row this batch can touch.
    existing: dict[str, Vulnerability] = {}
    for chunk in _chunks(list({fp for _, _, fp in matched})):
        for vuln in session.exec(select(Vulnerability).where(col(Vulnerability.fingerprint).in_(chunk))).all():
            existing[vuln.fingerprint] = vuln

    touched: list[Vulnerability] = []
    for target, f, fp in matched:
        vuln = existing.get(fp)
        if vuln is None:
            vuln = Vulnerability(
                fingerprint=fp,
                target_id=target.id,
                target_url=target.url,
                domain_root=target.domain_root,
                template_id=f.template_id,
                first_seen_at=now,
                status=VulnStatus.OPEN,
                tags=[],
            )
            _apply(vuln, f, run_id, now)
            existing[fp] = vuln  # a duplicate fingerprint later in this batch updates this row
            stats.new += 1
            if f.severity in ("critical", "high"):
                stats.alerts.append(vuln)
        else:
            if vuln.status == VulnStatus.RESOLVED:
                vuln.status = VulnStatus.OPEN
                vuln.resolved_at = None
                stats.reopened += 1
            _apply(vuln, f, run_id, now)
            stats.updated += 1
        touched.append(vuln)

    session.add_all(touched)
    session.flush()

    if resolve:
        scanned_ids = list({t.id for t in targets})
        open_by_target: dict[int, list[Vulnerability]] = defaultdict(list)
        for chunk in _chunks(scanned_ids):
            rows = session.exec(select(Vulnerability).where(
                col(Vulnerability.target_id).in_(chunk), Vulnerability.status == VulnStatus.OPEN,
            )).all()
            for vuln in rows:
                open_by_target[vuln.target_id].append(vuln)

        for target in targets:
            for vuln in open_by_target.get(target.id, []):
                if vuln.fingerprint in seen[target.id]:
                    continue
                vuln.missed_scans += 1
                if vuln.missed_scans >= settings.resolve_after_misses:
                    vuln.status = VulnStatus.RESOLVED
                    vuln.resolved_at = now
                    stats.resolved += 1
                session.add(vuln)
            target.last_scanned_at = now
            target.last_scan_status = "COMPLETED"
            session.add(target)
        session.flush()
        for target in targets:
            open_count = sum(1 for v in open_by_target.get(target.id, []) if v.status == VulnStatus.OPEN)
            target.last_open_findings = open_count
            target.last_result = "CLEAN" if open_count == 0 else "VULNERABLE"
            session.add(target)

    session.commit()
    return stats
