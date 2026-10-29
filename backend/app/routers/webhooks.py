from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlmodel import Session, select

from app.auth import require_api_key
from app.db import get_session
from app.models import WebhookConfig
from app.schemas import WebhookCreate, WebhookOut

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _out(cfg: WebhookConfig) -> WebhookOut:
    return WebhookOut(
        id=cfg.id, name=cfg.name, kind=cfg.kind, url=cfg.url,
        enabled=cfg.enabled, min_severity=cfg.min_severity,
    )


@router.get("", response_model=list[WebhookOut])
def list_webhooks(session: Session = Depends(get_session)) -> list[WebhookOut]:
    return [_out(c) for c in session.exec(select(WebhookConfig).order_by(WebhookConfig.id)).all()]


@router.post("", response_model=WebhookOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_api_key)])
def create_webhook(payload: WebhookCreate, session: Session = Depends(get_session)) -> WebhookOut:
    if not payload.url.startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "webhook url must be http(s)")
    cfg = WebhookConfig(**payload.model_dump())
    session.add(cfg)
    session.commit()
    session.refresh(cfg)
    return _out(cfg)


@router.delete("/{hook_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
def delete_webhook(hook_id: int, session: Session = Depends(get_session)) -> Response:
    cfg = session.get(WebhookConfig, hook_id)
    if cfg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook not found")
    session.delete(cfg)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
