from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlmodel import Session, func, select

from app.db import get_session
from app.models import Report
from app.schemas import ReportOut
from app.services.reports import reports_dir

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportOut])
def list_reports(session: Session = Depends(get_session), limit: int = Query(50, ge=1, le=200)) -> list[ReportOut]:
    rows = session.exec(select(Report).order_by(Report.id.desc()).limit(limit)).all()
    return [ReportOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/count")
def count_reports(session: Session = Depends(get_session)) -> dict:
    return {"total": session.exec(select(func.count(Report.id))).one()}


@router.get("/{report_id}/download")
def download_report(report_id: int, session: Session = Depends(get_session)) -> FileResponse:
    report = session.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    path: Path = reports_dir() / report.file_name
    if not path.exists():
        raise HTTPException(status.HTTP_410_GONE, "report file has expired or was removed")
    return FileResponse(path, media_type="application/json", filename=report.file_name)
