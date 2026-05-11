# =============================================================================
# crawler/static_crawler.py — Crawl HTML bằng HTTP request
#
# Nguồn thu thập:
#   - robots.txt  → path ẩn (/admin, /backup...)
#   - sitemap.xml → danh sách URL công khai
#   - <a href>    → internal links
#   - <form>      → action URL + input fields
#   - <script>    → URL ẩn trong JS
# =============================================================================

import re
import time
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from crawler.models import Endpoint
from crawler.utils  import normalize_url, in_scope, is_static, extract_params, dedup_key

log = logging.getLogger(__name__)

HEADERS    = {"User-Agent": "WebSentinel/1.0"}
JS_URL_RE  = re.compile(
    r"""(?:url|href|src|action|api)['":\s]+['"](\/[^\s'"<>]{2,}|https?://[^\s'"<>]+)['"]""",
    re.IGNORECASE,
)


def static_crawl(target_url: str, scope: str, max_depth: int = 2, delay: float = 0.3) -> list[Endpoint]:
    """
    BFS crawl toàn bộ website.

    Args:
        target_url: URL bắt đầu
        scope:      Domain giới hạn
        max_depth:  Độ sâu tối đa
        delay:      Giây chờ giữa request

    Returns:
        Danh sách Endpoint tìm được
    """
    visited   = set()
    endpoints = []
    seen_keys = set()
    queue     = [(target_url, 0)]

    # Seed thêm URL từ robots.txt và sitemap.xml
    _seed_robots(target_url, scope, queue)
    _seed_sitemap(target_url, scope, queue)

    while queue:
        url, depth = queue.pop(0)
        url = normalize_url(url, target_url)

        if url in visited or depth > max_depth: continue
        if is_static(url) or not in_scope(url, scope): continue

        visited.add(url)
        log.info(f"[static] depth={depth} → {url}")

        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        except requests.RequestException as e:
            log.warning(f"[static] Lỗi: {e}")
            continue

        time.sleep(delay)

        # Thu thập param từ URL hiện tại
        _add_endpoint(url, "GET", "static", seen_keys, endpoints, resp)

        if "html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Thu thập <a href>
        for a in soup.find_all("a", href=True):
            new_url = normalize_url(a["href"], url)
            if in_scope(new_url, scope) and new_url not in visited:
                queue.append((new_url, depth + 1))
            _add_endpoint(new_url, "GET", "static", seen_keys, endpoints)

        # Thu thập <form>
        for form in soup.find_all("form"):
            ep = _parse_form(form, url)
            if ep and in_scope(ep.url, scope):
                k = dedup_key(ep.url, ep.method, ep.params)
                if k not in seen_keys:
                    seen_keys.add(k)
                    endpoints.append(ep)

        # Thu thập URL trong <script>
        for script in soup.find_all("script"):
            if script.get("src"):
                _mine_js_file(normalize_url(script["src"], url), scope, seen_keys, endpoints)
            elif script.string:
                _mine_js_text(script.string, url, scope, seen_keys, endpoints)

    log.info(f"[static] Xong — {len(endpoints)} endpoints")
    return endpoints


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _add_endpoint(url, method, source, seen_keys, endpoints, resp=None):
    if is_static(url): return
    clean, param_types = extract_params(url)
    if not param_types:  return
    k = dedup_key(clean, method, list(param_types))
    if k in seen_keys:   return
    seen_keys.add(k)
    endpoints.append(Endpoint(
        url=clean, method=method,
        params=list(param_types), param_types=param_types,
        source=source,
        response_sample={"status": resp.status_code, "length": len(resp.content)} if resp else {},
    ))


def _parse_form(form, base_url: str) -> Endpoint | None:
    action = form.get("action") or base_url
    method = (form.get("method") or "GET").upper()
    url    = normalize_url(action, base_url)
    param_types = {}
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if name:
            param_types[name] = _html_type(inp.get("type", "text"))
    if not param_types: return None
    return Endpoint(
        url=url, method=method,
        params=list(param_types), param_types=param_types,
        source="static", content_type="application/x-www-form-urlencoded",
    )


def _html_type(t: str) -> str:
    return {"number": "integer", "email": "email",
            "password": "string", "checkbox": "boolean", "date": "date"}.get(t, "string")


def _mine_js_text(js, base_url, scope, seen_keys, endpoints):
    for m in JS_URL_RE.finditer(js):
        full = normalize_url(m.group(1), base_url)
        if in_scope(full, scope):
            _add_endpoint(full, "GET", "static_js", seen_keys, endpoints)


def _mine_js_file(js_url, scope, seen_keys, endpoints):
    if not in_scope(js_url, scope): return
    try:
        r = requests.get(js_url, headers=HEADERS, timeout=6)
        _mine_js_text(r.text, js_url, scope, seen_keys, endpoints)
    except Exception: pass


def _seed_robots(target_url, scope, queue):
    try:
        r = requests.get(urljoin(target_url, "/robots.txt"), headers=HEADERS, timeout=5)
        for line in r.text.splitlines():
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    full = urljoin(target_url, path)
                    if in_scope(full, scope):
                        queue.append((full, 1))
    except Exception: pass


def _seed_sitemap(target_url, scope, queue):
    try:
        r    = requests.get(urljoin(target_url, "/sitemap.xml"), headers=HEADERS, timeout=5)
        root = ET.fromstring(r.text)
        ns   = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc in root.findall(".//sm:loc", ns):
            if in_scope(loc.text.strip(), scope):
                queue.append((loc.text.strip(), 1))
    except Exception: pass