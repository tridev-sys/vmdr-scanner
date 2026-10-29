from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_
from sqlmodel import Session, select

from app.auth import require_api_key
from app.db import get_session
from app.models import VulnStatus, Vulnerability, utcnow
from app.schemas import VulnOut, VulnPage, VulnUpdate

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


def _csv(value: str | None) -> list[str]:
    return [v.strip().lower() for v in value.split(",") if v.strip()] if value else []


def _out(v: Vulnerability) -> VulnOut:
    return VulnOut.model_validate(v, from_attributes=True)


@router.get("", response_model=VulnPage)
def list_vulnerabilities(
    session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    q: str | None = Query(None, description="Search CVE ID, template ID, name, or hostname"),
    severity: str | None = Query(None, description="Comma-separated, e.g. critical,high"),
    status_filter: str | None = Query(None, alias="status", description="Comma-separated statuses"),
    cve_id: str | None = None,
    target_id: int | None = None,
    target_url: str | None = None,
    domain: str | None = Query(None, description="Domain root, e.g. koala.cx"),
) -> VulnPage:
    stmt = select(Vulnerability)
    sev = _csv(severity)
    if sev:
        stmt = stmt.where(Vulnerability.severity.in_(sev))
    statuses = [s.upper() for s in _csv(status_filter)]
    if statuses:
        stmt = stmt.where(Vulnerability.status.in_(statuses))
    if cve_id:
        stmt = stmt.where(func.upper(Vulnerability.cve_id) == cve_id.upper())
    if target_id is not None:
        stmt = stmt.where(Vulnerability.target_id == target_id)
    if target_url:
        stmt = stmt.where(Vulnerability.target_url == target_url)
    if domain:
        stmt = stmt.where(Vulnerability.domain_root == domain.lower())
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(
            func.lower(Vulnerability.cve_id).like(needle),
            func.lower(Vulnerability.template_id).like(needle),
            func.lower(Vulnerability.name).like(needle),
            func.lower(Vulnerability.target_url).like(needle),
            func.lower(Vulnerability.matched_at).like(needle),
        ))

    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    rows = session.exec(
        stmt.order_by(Vulnerability.last_seen_at.desc(), Vulnerability.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return VulnPage(items=[_out(v) for v in rows], total=total, page=page, page_size=page_size)


@router.get("/{vuln_id}", response_model=VulnOut)
def get_vulnerability(vuln_id: int, session: Session = Depends(get_session)) -> VulnOut:
    vuln = session.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    return _out(vuln)


@router.patch("/{vuln_id}", response_model=VulnOut, dependencies=[Depends(require_api_key)])
def triage_vulnerability(vuln_id: int, payload: VulnUpdate, session: Session = Depends(get_session)) -> VulnOut:
    vuln = session.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    vuln.status = payload.status
    if payload.status == VulnStatus.RESOLVED:
        vuln.resolved_at = vuln.resolved_at or utcnow()
    elif payload.status == VulnStatus.OPEN:
        vuln.resolved_at = None
        vuln.missed_scans = 0
    session.add(vuln)
    session.commit()
    session.refresh(vuln)
    return _out(vuln)
