import hashlib
import re
from urllib.parse import urlsplit

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def normalize_target_url(raw: str) -> str:
    """Return a canonical `scheme://host[:port][/path]` string or raise ValueError."""
    value = (raw or "").strip()
    if not value:
        raise ValueError("empty URL")
    if "://" not in value:
        value = f"https://{value}"
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not a valid http(s) URL: {raw!r}")
    host = parts.hostname.lower()
    port = f":{parts.port}" if parts.port else ""
    path = parts.path.rstrip("/")
    return f"{parts.scheme.lower()}://{host}{port}{path}"


def hostname_of(value: str) -> str | None:
    """Extract the bare hostname from a URL or host:port string."""
    if not value:
        return None
    candidate = value if "://" in value else f"//{value}"
    try:
        return urlsplit(candidate).hostname
    except ValueError:
        return None


def domain_root(host: str) -> str:
    """Group key such as `koala.cx` for `app.koala.cx`. Naive two-label rule by design."""
    labels = host.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def infer_tags(host: str) -> list[str]:
    tags = ["dev"] if re.search(r"(^|[-.])dev", host) else ["prod"]
    if "middleware" in host:
        tags.append("middleware")
    return tags


def fingerprint(target_url: str, template_id: str, matcher_name: str | None) -> str:
    raw = f"{target_url}|{template_id}|{matcher_name or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_bulk_text(text: str) -> list[tuple[str, list[str]]]:
    """Parse newline- or CSV-delimited input.

    Each line is `url` or `url,tag1;tag2`. Blank lines, `#` comments and a `url` header are skipped.
    """
    rows: list[tuple[str, list[str]]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        url, tags = line, []
        if "," in line:
            url, tag_part = (p.strip() for p in line.split(",", 1))
            tags = [t.strip() for t in re.split(r"[;|]", tag_part) if t.strip()]
        if url.lower() in ("url", "target", "host"):
            continue
        rows.append((url, tags))
    return rows
