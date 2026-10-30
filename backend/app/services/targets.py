"""Target registry operations shared by the API and the seeder."""

from sqlmodel import Session, select

from app.models import Target, TargetStatus, Vulnerability, VulnStatus, utcnow
from app.schemas import BulkImportError, BulkImportResult, TargetOut, VulnCounts
from app.utils import domain_root, infer_tags, normalize_target_url, parse_bulk_text


def _risk(counts: VulnCounts) -> str:
    for level in ("critical", "high", "medium", "low"):
        if getattr(counts, level) > 0:
            return level
    return "none"


def open_counts(session: Session, target_ids: list[int]) -> dict[int, VulnCounts]:
    """Open-finding counts per target, grouped by severity."""
    result: dict[int, VulnCounts] = {tid: VulnCounts() for tid in target_ids}
    if not target_ids:
        return result
    from sqlalchemy import func

    rows = session.exec(
        select(Vulnerability.target_id, Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.target_id.in_(target_ids), Vulnerability.status == VulnStatus.OPEN)
        .group_by(Vulnerability.target_id, Vulnerability.severity)
    ).all()
    for target_id, severity, count in rows:
        counts = result[target_id]
        counts.open += count
        if severity in ("critical", "high", "medium", "low"):
            setattr(counts, severity, count)
    return result


def to_target_out(target: Target, counts: VulnCounts) -> TargetOut:
    return TargetOut(
        id=target.id,
        url=target.url,
        host=target.host,
        domain_root=target.domain_root,
        tags=target.tags,
        status=target.status,
        notes=target.notes,
        created_at=target.created_at,
        updated_at=target.updated_at,
        last_scanned_at=target.last_scanned_at,
        last_scan_status=target.last_scan_status,
        risk=_risk(counts),
        vuln_counts=counts,
        reachability=target.reachability,
        last_probe_error=target.last_probe_error,
        consecutive_probe_failures=target.consecutive_probe_failures,
        last_result=target.last_result,
        last_open_findings=target.last_open_findings,
    )


def add_targets(
    session: Session,
    *,
    urls: list[str] | None = None,
    text: str | None = None,
    tags: list[str] | None = None,
    notes: str | None = None,
) -> BulkImportResult:
    """Insert targets from a list of URLs and/or a bulk text block. Duplicates and invalid entries are reported, not raised."""
    entries: list[tuple[str, list[str]]] = [(u, []) for u in (urls or [])]
    if text:
        entries.extend(parse_bulk_text(text))

    created: list[Target] = []
    skipped: list[str] = []
    invalid: list[BulkImportError] = []
    seen_in_request: set[str] = set()

    for raw, row_tags in entries:
        try:
            url = normalize_target_url(raw)
        except ValueError as exc:
            invalid.append(BulkImportError(input=raw, error=str(exc)))
            continue
        if url in seen_in_request or session.exec(select(Target).where(Target.url == url)).first():
            skipped.append(url)
            continue
        seen_in_request.add(url)

        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        merged_tags = sorted({*(tags or []), *row_tags, *infer_tags(host)})
        target = Target(
            url=url,
            host=host,
            domain_root=domain_root(host),
            tags=merged_tags,
            notes=notes,
            status=TargetStatus.ACTIVE,
        )
        session.add(target)
        created.append(target)

    session.commit()
    for target in created:
        session.refresh(target)
    counts = open_counts(session, [t.id for t in created])
    return BulkImportResult(
        created=[to_target_out(t, counts[t.id]) for t in created],
        skipped_duplicates=skipped,
        invalid=invalid,
    )


def touch(target: Target) -> None:
    target.updated_at = utcnow()
