# =============================================================================
# crawler/static_crawler.py — Crawl web bằng HTTP request thông thường
#
# Hoạt động:
#   1. Đọc robots.txt → lấy path ẩn (/admin, /backup...)
#   2. Đọc sitemap.xml → lấy tất cả URL công khai
#   3. BFS crawl từng trang HTML → tìm <a>, <form>, query params
#   4. Parse inline <script> → tìm URL ẩn trong JS
#
# Giới hạn: Không thấy endpoint trong SPA (React/Vue) → dùng js_crawler
# =============================================================================

import re
import time
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from crawler.models import Endpoint
from crawler.utils  import (
    normalize_url, in_scope, is_static_asset,
    extract_params_from_url, guess_type, dedup_key,
)

log = logging.getLogger(__name__)

# User-agent để tránh bị block
HEADERS = {"User-Agent": "WebSentinel/1.0 (security-scanner)"}

# Regex tìm URL trong code JavaScript
JS_URL_PATTERN = re.compile(
    r"""(?:url|href|src|action|endpoint|api)['":\s]+['"](\/[^\s'"<>]{2,}|https?://[^\s'"<>]+)['"]""",
    re.IGNORECASE,
)


def static_crawl(
    target_url: str,
    scope:      str,
    max_depth:  int   = 2,
    delay:      float = 0.3,
    headers:    dict  = None,
) -> list[Endpoint]:
    """
    Crawl website bằng HTTP request + BeautifulSoup.

    Args:
        target_url: URL bắt đầu crawl
        scope:      Domain regex giới hạn phạm vi (vd: 'target.com')
        max_depth:  Độ sâu crawl tối đa
        delay:      Giây chờ giữa các request
        headers:    Header bổ sung (cookie session nếu cần auth)

    Returns:
        Danh sách Endpoint tìm được
    """
    hdrs      = {**HEADERS, **(headers or {})}
    visited   = set()                       # URL đã visit
    endpoints = []                          # Kết quả trả về
    seen_keys = set()                       # Chữ ký endpoint đã thêm (dedup)
    queue     = [(target_url, 0)]           # Hàng đợi BFS: (url, depth)

    # Seed thêm URL từ robots.txt và sitemap
    _seed_from_robots(target_url, scope, queue, hdrs)
    _seed_from_sitemap(target_url, scope, queue, hdrs)

    while queue:
        url, depth = queue.pop(0)
        url = normalize_url(url, target_url)

        # Bỏ qua nếu đã visit, quá sâu, là file tĩnh, hoặc ngoài scope
        if url in visited or depth > max_depth:  continue
        if is_static_asset(url):                  continue
        if not in_scope(url, scope):              continue

        visited.add(url)
        log.info(f"[static] depth={depth} → {url}")

        try:
            resp = requests.get(url, headers=hdrs, timeout=8, allow_redirects=True)
        except requests.RequestException as e:
            log.warning(f"[static] Lỗi request {url}: {e}")
            continue

        time.sleep(delay)

        # Thu thập param từ URL hiện tại (nếu có query string)
        _add_url_endpoint(url, "GET", "static", seen_keys, endpoints, resp)

        # Chỉ parse HTML — bỏ qua JSON, binary, etc.
        if "html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Thu thập từ <a href>
        for a in soup.find_all("a", href=True):
            new_url = normalize_url(a["href"], url)
            if in_scope(new_url, scope) and new_url not in visited:
                queue.append((new_url, depth + 1))
            _add_url_endpoint(new_url, "GET", "static", seen_keys, endpoints)

        # Thu thập từ <form>
        for form in soup.find_all("form"):
            ep = _parse_form(form, url)
            if ep and in_scope(ep.url, scope):
                k = dedup_key(ep.url, ep.method, ep.params)
                if k not in seen_keys:
                    seen_keys.add(k)
                    endpoints.append(ep)

        # Thu thập URL ẩn từ <script>
        for script in soup.find_all("script"):
            js_src = script.get("src")
            if js_src:
                # External JS file → tải về rồi parse
                _mine_js_file(normalize_url(js_src, url), scope, seen_keys, endpoints, hdrs)
            elif script.string:
                # Inline JS → parse trực tiếp
                _mine_js_text(script.string, url, scope, seen_keys, endpoints)

    log.info(f"[static] Hoàn thành — {len(endpoints)} endpoints")
    return endpoints


# ─── Helper functions ────────────────────────────────────────────────────────

def _add_url_endpoint(url, method, source, seen_keys, endpoints, resp=None):
    """Thêm endpoint từ URL có query params."""
    if is_static_asset(url):
        return
    clean, param_types = extract_params_from_url(url)
    if not param_types:  # Không có param → bỏ qua
        return
    k = dedup_key(clean, method, list(param_types.keys()))
    if k in seen_keys:
        return
    seen_keys.add(k)
    endpoints.append(Endpoint(
        url=clean, method=method,
        params=list(param_types.keys()), param_types=param_types,
        source=source,
        response_sample={"status": resp.status_code, "length": len(resp.content)} if resp else {},
    ))


def _parse_form(form, base_url: str) -> Endpoint | None:
    """Trích xuất thông tin endpoint từ thẻ <form>."""
    action = form.get("action") or base_url
    method = (form.get("method") or "GET").upper()
    url    = normalize_url(action, base_url)

    # Thu thập tất cả input fields
    param_types = {}
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if not name:
            continue
        itype = inp.get("type", "text").lower()
        param_types[name] = _input_type_map(itype)

    if not param_types:
        return None

    return Endpoint(
        url=url, method=method,
        params=list(param_types.keys()), param_types=param_types,
        source="static",
        content_type="application/x-www-form-urlencoded",
    )


def _input_type_map(html_type: str) -> str:
    """Chuyển HTML input type → kiểu dữ liệu nội bộ."""
    return {
        "number": "integer", "email": "email",
        "password": "string", "checkbox": "boolean", "date": "date",
    }.get(html_type, "string")


def _mine_js_text(js_text: str, base_url: str, scope, seen_keys, endpoints):
    """Tìm URL ẩn trong code JavaScript bằng regex."""
    for m in JS_URL_PATTERN.finditer(js_text):
        full = normalize_url(m.group(1), base_url)
        if in_scope(full, scope):
            _add_url_endpoint(full, "GET", "static_js", seen_keys, endpoints)


def _mine_js_file(js_url: str, scope, seen_keys, endpoints, hdrs):
    """Tải file JS external rồi tìm URL bên trong."""
    if not in_scope(js_url, scope):
        return
    try:
        r = requests.get(js_url, headers=hdrs, timeout=6)
        _mine_js_text(r.text, js_url, scope, seen_keys, endpoints)
    except Exception as e:
        log.debug(f"[static] Không tải được JS {js_url}: {e}")


def _seed_from_robots(target_url: str, scope, queue, hdrs):
    """Đọc robots.txt → thêm Disallowed paths vào queue (thường có /admin, /backup...)."""
    try:
        r = requests.get(urljoin(target_url, "/robots.txt"), headers=hdrs, timeout=5)
        for line in r.text.splitlines():
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    full = urljoin(target_url, path)
                    if in_scope(full, scope):
                        queue.append((full, 1))
                        log.debug(f"[robots] seeded: {full}")
    except Exception:
        pass  # robots.txt không tồn tại → bỏ qua


def _seed_from_sitemap(target_url: str, scope, queue, hdrs):
    """Đọc sitemap.xml → thêm tất cả URL vào queue."""
    try:
        r    = requests.get(urljoin(target_url, "/sitemap.xml"), headers=hdrs, timeout=5)
        root = ET.fromstring(r.text)
        ns   = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc in root.findall(".//sm:loc", ns):
            url = loc.text.strip()
            if in_scope(url, scope):
                queue.append((url, 1))
        log.debug(f"[sitemap] seeded {len(root.findall('.//sm:loc', ns))} URLs")
    except Exception:
        pass  # sitemap không tồn tại → bỏ qua