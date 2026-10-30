from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import String, cast, func, or_
from sqlmodel import Session, select

from app.auth import require_api_key
from app.db import get_session
from app.models import Target, TargetStatus, Vulnerability
from app.schemas import BulkImportResult, DomainGroup, TargetCreate, TargetOut, TargetPage, TargetUpdate
from app.services.targets import add_targets, open_counts, to_target_out
from app.models import utcnow
from app.utils import domain_root, normalize_target_url

router = APIRouter(prefix="/targets", tags=["targets"])


def _get_or_404(session: Session, target_id: int) -> Target:
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    return target


@router.get("", response_model=TargetPage)
def list_targets(
    session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    q: str | None = Query(None, description="Search URL, host, or tag"),
    status_filter: str | None = Query(None, alias="status", pattern="^(ACTIVE|PAUSED|ARCHIVED)$"),
    domain: str | None = Query(None, description="Domain root, e.g. koala.cx"),
    tag: str | None = None,
    result: str | None = Query(None, pattern="^(CLEAN|VULNERABLE|UNREACHABLE|UNSCANNED)$",
                              description="Last scan outcome"),
) -> TargetPage:
    stmt = select(Target)
    if status_filter:
        stmt = stmt.where(Target.status == status_filter)
    else:
        stmt = stmt.where(Target.status != TargetStatus.ARCHIVED)
    if result == "CLEAN":
        stmt = stmt.where(Target.last_result == "CLEAN")
    elif result == "VULNERABLE":
        stmt = stmt.where(Target.last_result == "VULNERABLE")
    elif result == "UNREACHABLE":
        stmt = stmt.where(Target.reachability == "UNREACHABLE")
    elif result == "UNSCANNED":
        stmt = stmt.where(Target.last_result.is_(None))
    if domain:
        stmt = stmt.where(Target.domain_root == domain.lower())
    if tag:
        stmt = stmt.where(cast(Target.tags, String).like(f'%"{tag}"%'))
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(
            func.lower(Target.url).like(needle),
            func.lower(Target.host).like(needle),
            cast(Target.tags, String).like(needle),
        ))

    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    rows = session.exec(
        stmt.order_by(Target.id).offset((page - 1) * page_size).limit(page_size)
    ).all()
    counts = open_counts(session, [t.id for t in rows])
    return TargetPage(
        items=[to_target_out(t, counts[t.id]) for t in rows],
        total=total, page=page, page_size=page_size,
    )


@router.get("/domains", response_model=list[DomainGroup])
def list_domains(session: Session = Depends(get_session)) -> list[DomainGroup]:
    rows = session.exec(
        select(Target.domain_root, func.count(Target.id))
        .where(Target.status != TargetStatus.ARCHIVED)
        .group_by(Target.domain_root)
        .order_by(Target.domain_root)
    ).all()
    return [DomainGroup(domain_root=d, count=c) for d, c in rows]


@router.post("", response_model=BulkImportResult, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_api_key)])
def create_targets(payload: TargetCreate, session: Session = Depends(get_session)) -> BulkImportResult:
    """Add one URL (`url`), many (`urls`), or a pasted list (`text`). New targets are ACTIVE and picked up by the next scan."""
    if not (payload.url or payload.urls or payload.text):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "provide url, urls, or text")
    urls = list(payload.urls) + ([payload.url] if payload.url else [])
    return add_targets(session, urls=urls, text=payload.text, tags=payload.tags, notes=payload.notes)


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, session: Session = Depends(get_session)) -> TargetOut:
    target = _get_or_404(session, target_id)
    return to_target_out(target, open_counts(session, [target.id])[target.id])


@router.patch("/{target_id}", response_model=TargetOut, dependencies=[Depends(require_api_key)])
def update_target(target_id: int, payload: TargetUpdate, session: Session = Depends(get_session)) -> TargetOut:
    target = _get_or_404(session, target_id)
    data = payload.model_dump(exclude_unset=True)
    if "url" in data and data["url"] is not None:
        try:
            url = normalize_target_url(data["url"])
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
        clash = session.exec(select(Target).where(Target.url == url, Target.id != target.id)).first()
        if clash:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{url} already exists as target {clash.id}")
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        target.url, target.host, target.domain_root = url, host, domain_root(host)
    if data.get("status"):
        target.status = data["status"]
    if "tags" in data and data["tags"] is not None:
        target.tags = sorted(set(data["tags"]))
    if "notes" in data:
        target.notes = data["notes"]
    target.updated_at = utcnow()
    session.add(target)
    session.commit()
    session.refresh(target)
    return to_target_out(target, open_counts(session, [target.id])[target.id])


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
def delete_target(
    target_id: int,
    hard: bool = Query(False, description="Permanently delete the target and its findings"),
    session: Session = Depends(get_session),
) -> Response:
    """Default is a soft delete (ARCHIVED): removed from scanning, history kept."""
    target = _get_or_404(session, target_id)
    if hard:
        for vuln in session.exec(select(Vulnerability).where(Vulnerability.target_id == target.id)).all():
            session.delete(vuln)
        session.delete(target)
    else:
        target.status = TargetStatus.ARCHIVED
        target.updated_at = utcnow()
        session.add(target)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
