"""Pre-scan reachability probe.

Each ACTIVE target gets one quick HTTP request before a scan. A target counts as reachable if
it returns any HTTP response, including 4xx/5xx and certificate errors (the host answered).
DNS failures, refused connections, and timeouts count as unreachable. Probes run concurrently
and never raise, so one dead host cannot stop a scan.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)
PROBE_TIMEOUT_S = 5.0
PROBE_CONCURRENCY = 20


@dataclass
class ProbeResult:
    url: str
    reachable: bool
    status_code: int | None = None
    error: str | None = None


def _probe_one(url: str) -> ProbeResult:
    try:
        with httpx.Client(timeout=PROBE_TIMEOUT_S, follow_redirects=False) as client:
            resp = client.head(url)
        return ProbeResult(url, True, resp.status_code)
    except httpx.ConnectError as exc:
        # Certificate problems mean the host answered. Retry once without verification to confirm.
        if "certificate" in str(exc).lower() or "ssl" in str(exc).lower():
            try:
                with httpx.Client(timeout=PROBE_TIMEOUT_S, verify=False, follow_redirects=False) as client:
                    resp = client.head(url)
                return ProbeResult(url, True, resp.status_code, "TLS certificate not verified")
            except httpx.HTTPError as retry_exc:
                return ProbeResult(url, False, error=_short(retry_exc))
        return ProbeResult(url, False, error=_short(exc))
    except httpx.HTTPError as exc:
        return ProbeResult(url, False, error=_short(exc))
    except Exception as exc:  # defensive: a probe must never break the scan
        return ProbeResult(url, False, error=_short(exc))


def _short(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return text[:250]


def probe_urls(urls: list[str]) -> list[ProbeResult]:
    """Probe all URLs concurrently. Results are returned in input order."""
    if not urls:
        return []
    with ThreadPoolExecutor(max_workers=min(PROBE_CONCURRENCY, len(urls))) as pool:
        return list(pool.map(_probe_one, urls))
