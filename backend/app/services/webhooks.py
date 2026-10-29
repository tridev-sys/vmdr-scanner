"""Alert delivery for newly detected critical/high findings (Slack, Microsoft Teams, or generic JSON)."""

import logging

import httpx
from sqlmodel import Session, select

from app.models import Vulnerability, WebhookConfig
from app.utils import SEVERITY_RANK

logger = logging.getLogger(__name__)
MAX_ALERTS_PER_RUN = 25


def _summary(v: Vulnerability) -> str:
    label = v.cve_id or v.template_id
    return f"[{v.severity.upper()}] {label} — {v.name} on {v.matched_at}"


def _payload(cfg: WebhookConfig, v: Vulnerability) -> dict:
    if cfg.kind == "slack":
        return {"text": f":rotating_light: {_summary(v)}"}
    if cfg.kind == "teams":
        color = "D13438" if v.severity == "critical" else "F7630C"
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": _summary(v),
            "themeColor": color,
            "title": _summary(v),
            "text": v.description or v.name,
        }
    return {
        "event": "vulnerability.detected",
        "vulnerability_id": v.id,
        "severity": v.severity,
        "cve_id": v.cve_id,
        "cvss_score": v.cvss_score,
        "name": v.name,
        "template_id": v.template_id,
        "target": v.target_url,
        "matched_at": v.matched_at,
        "first_seen_at": v.first_seen_at.isoformat(),
    }


def dispatch_alerts(session: Session, vulns: list[Vulnerability]) -> list[str]:
    """Send alerts to every enabled webhook whose threshold is met. Returns error messages (empty on success)."""
    errors: list[str] = []
    if not vulns:
        return errors
    configs = session.exec(select(WebhookConfig).where(WebhookConfig.enabled == True)).all()  # noqa: E712
    for cfg in configs:
        threshold = SEVERITY_RANK.get(cfg.min_severity, 4)
        for v in vulns[:MAX_ALERTS_PER_RUN]:
            if SEVERITY_RANK.get(v.severity, 0) < threshold:
                continue
            try:
                resp = httpx.post(cfg.url, json=_payload(cfg, v), timeout=10)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                errors.append(f"webhook '{cfg.name}': {exc}")
    if len(vulns) > MAX_ALERTS_PER_RUN:
        errors.append(f"{len(vulns) - MAX_ALERTS_PER_RUN} alerts suppressed (per-run cap)")
    return errors
