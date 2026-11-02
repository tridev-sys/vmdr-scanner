"""Endpoint discovery for the payload pass.

Customers add base URLs only. Payload templates fuzz query parameters, so before the payload pass the
scanner collects parameterized URLs from the target's own pages: links, src/action attributes, URLs or
paths written in page text, and GET forms. Crawling is same-host and bounded (pages, URLs, time per
target), so the cost per target stays flat as the target list grows.
"""

import re
from urllib.parse import urljoin, urlparse, urlunparse, urlencode

import httpx

# Absolute or root-relative URL/path with a query string, anywhere in the body (text, attributes, scripts).
PARAM_URL_RE = re.compile(r"""(?:https?://[^\s"'<>]+|/[^\s"'<>]*)\?[^\s"'<>]*""")
ATTR_RE = re.compile(r"""\b(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
FORM_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
FORM_METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
INPUT_NAME_RE = re.compile(r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

TEXT_TYPES = ("text/", "application/json", "application/xml", "application/javascript")


def _same_host(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def _clean(url: str) -> str:
    """Drop the fragment so one page is not crawled twice."""
    parts = urlparse(url)
    return urlunparse(parts._replace(fragment=""))


def parameterized_urls(body: str, page_url: str) -> set[str]:
    """URLs with a query string found in one page body, made absolute against the page URL."""
    found: set[str] = set()
    for match in PARAM_URL_RE.finditer(body):
        url = _clean(urljoin(page_url, match.group(0).rstrip(".,;)")))
        if urlparse(url).query:
            found.add(url)
    for form in FORM_RE.finditer(body):
        attrs, inner = form.group(1), form.group(2)
        method = (FORM_METHOD_RE.search(attrs).group(1) if FORM_METHOD_RE.search(attrs) else "get").lower()
        if method != "get":
            continue  # only GET parameters are in the query string the payload templates fuzz
        names = INPUT_NAME_RE.findall(inner)
        if not names:
            continue
        action = FORM_ACTION_RE.search(attrs)
        target = urljoin(page_url, action.group(1) if action else "")
        query = urlencode({name: "test" for name in names})
        found.add(_clean(urlunparse(urlparse(target)._replace(query=query))))
    return found


def page_links(body: str, page_url: str, base_url: str) -> set[str]:
    """Same-host links from one page body, for the crawl queue."""
    links: set[str] = set()
    for match in ATTR_RE.finditer(body):
        url = _clean(urljoin(page_url, match.group(1)))
        if urlparse(url).scheme in ("http", "https") and _same_host(url, base_url):
            links.add(url)
    return links


def discover(
    base_url: str,
    max_pages: int = 15,
    max_urls: int = 50,
    timeout: float = 5.0,
    client: httpx.Client | None = None,
) -> list[str]:
    """Parameterized URLs found by crawling same-host pages from base_url, in discovery order."""
    own_client = client is None
    client = client or httpx.Client(follow_redirects=True, timeout=timeout, verify=False)
    queue: list[str] = [_clean(base_url)]
    visited: set[str] = set()
    found: list[str] = []
    seen_urls: set[str] = set()
    try:
        while queue and len(visited) < max_pages and len(found) < max_urls:
            page = queue.pop(0)
            if page in visited:
                continue
            visited.add(page)
            try:
                response = client.get(page)
            except httpx.HTTPError:
                continue
            content_type = response.headers.get("content-type", "")
            if not content_type.startswith(TEXT_TYPES) and "html" not in content_type:
                continue
            body = response.text[:500_000]
            final_url = str(response.url)
            for url in sorted(parameterized_urls(body, final_url)):
                if url not in seen_urls and _same_host(url, base_url):
                    seen_urls.add(url)
                    found.append(url)
                    if len(found) >= max_urls:
                        break
            for link in sorted(page_links(body, final_url, base_url)):
                if link not in visited and link not in queue:
                    queue.append(link)
    finally:
        if own_client:
            client.close()
    return found
