# =============================================================================
# crawler/js_crawler.py — Dynamic crawler dùng Playwright headless browser
#
# Vấn đề với static crawler:
#   React/Vue/Angular load HTML rỗng + bundle JS
#   → API chỉ xuất hiện khi JS chạy và user tương tác
#   → Static crawler hoàn toàn bỏ sót
#
# Giải pháp:
#   Dùng Playwright mở browser thật (headless)
#   → Hook TẤT CẢ network request browser gửi (XHR/fetch/API)
#   → Thực hiện một số hành động UI để kích hoạt thêm API
#   → Convert request → Endpoint
# =============================================================================

import json
import logging
import asyncio
from urllib.parse import urlparse, parse_qs

from playwright.async_api import async_playwright, Request, Page

from crawler.models import Endpoint
from crawler.utils  import normalize_url, in_scope, is_static, guess_type, dedup_key

log = logging.getLogger(__name__)

# Giới hạn để tránh explosion
MAX_CLICKS   = 20    # số lần click tối đa
WAIT_MS      = 2000  # ms đợi sau mỗi action
NAV_TIMEOUT  = 15000 # ms timeout khi load trang

# Selector các element có thể click để kích hoạt API
CLICKABLE = ["nav a", "button", "[role='tab']", "[data-link]", ".menu-item", "a[href]"]

# Tránh click các element này (gây logout/xóa data)
BLACKLIST  = ["logout", "signout", "delete", "remove", "log out", "sign out"]


def js_crawl(target_url: str, scope: str, cookies: list[dict] = None) -> list[Endpoint]:
    """
    Wrapper đồng bộ — gọi từ crawler.py bình thường.

    Args:
        target_url: URL mục tiêu
        scope:      Domain giới hạn
        cookies:    Cookie session nếu cần đăng nhập

    Returns:
        Danh sách Endpoint phát hiện từ browser
    """
    return asyncio.run(_crawl_async(target_url, scope, cookies or []))


async def _crawl_async(target_url: str, scope: str, cookies: list[dict]) -> list[Endpoint]:
    endpoints = []
    seen_keys = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        context = await browser.new_context(ignore_https_errors=True)

        # Inject cookie nếu có session
        if cookies:
            await context.add_cookies(cookies)

        page = await context.new_page()

        # ── Hook network request ───────────────────────────────────────────
        # Đây là core của JS crawler: bắt MỌI request browser gửi
        def on_request(req: Request):
            _capture_request(req, scope, seen_keys, endpoints)

        page.on("request", on_request)

        # ── Load trang, đợi JS chạy xong ──────────────────────────────────
        log.info(f"[js] Mở {target_url}")
        try:
            await page.goto(target_url, wait_until="networkidle", timeout=NAV_TIMEOUT)
        except Exception as e:
            log.warning(f"[js] Load cảnh báo (tiếp tục): {e}")

        # Thu thập endpoint từ DOM sau khi JS render
        await _collect_from_dom(page, target_url, scope, seen_keys, endpoints)

        # ── Scroll để kích hoạt lazy-load API ─────────────────────────────
        await _scroll_page(page)

        # ── Click các element để kích hoạt thêm API ───────────────────────
        await _auto_interact(page, target_url, scope, seen_keys, endpoints)

        await browser.close()

    log.info(f"[js] Xong — {len(endpoints)} endpoints từ browser")
    return endpoints


# ─── Network Capture ──────────────────────────────────────────────────────────

def _capture_request(req: Request, scope: str, seen_keys: set, endpoints: list):
    """
    Bắt XHR/fetch request → convert thành Endpoint.
    Đây là lý do chính cần JS crawler: static crawler không thấy các request này.
    """
    # Chỉ quan tâm XHR/fetch (API calls), bỏ qua ảnh/CSS/JS files
    if req.resource_type not in ("xhr", "fetch", "document"):
        return

    url = req.url
    if not in_scope(url, scope) or is_static(url):
        return

    method      = req.method.upper()
    parsed      = urlparse(url)
    param_types = {}

    # Lấy query params (GET)
    for k, vals in parse_qs(parsed.query).items():
        param_types[k] = guess_type(vals[0] if vals else "")

    # Lấy body params (POST/PUT)
    if method in ("POST", "PUT", "PATCH") and req.post_data:
        _parse_body(req.post_data, req.headers.get("content-type", ""), param_types)

    clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    k     = dedup_key(clean, method, list(param_types.keys()))
    if k in seen_keys:
        return
    seen_keys.add(k)

    ep = Endpoint(
        url          = clean,
        method       = method,
        params       = list(param_types.keys()),
        param_types  = param_types,
        source       = "js_intercept",
        content_type = req.headers.get("content-type", "application/json"),
        post_body_sample = req.post_data if method != "GET" else None,
    )
    endpoints.append(ep)
    log.debug(f"[js] Bắt được: {method} {clean} params={list(param_types)}")


def _parse_body(body: str, content_type: str, out: dict):
    """Parse request body (JSON hoặc form) để lấy param names."""
    try:
        if "json" in content_type:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    out[k] = guess_type(str(v))
        elif "form" in content_type:
            for k, vals in parse_qs(body).items():
                out[k] = guess_type(vals[0] if vals else "")
    except Exception:
        pass


# ─── DOM Collection ───────────────────────────────────────────────────────────

async def _collect_from_dom(page: Page, base_url: str, scope: str, seen_keys: set, endpoints: list):
    """Thu thập link và form từ DOM sau khi JS render xong."""

    # Links có query params
    try:
        links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        for href in links:
            url = normalize_url(href, base_url)
            if not in_scope(url, scope) or is_static(url):
                continue
            parsed = urlparse(url)
            if not parsed.query:
                continue
            param_types = {k: guess_type(v[0]) for k, v in parse_qs(parsed.query).items()}
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            k     = dedup_key(clean, "GET", list(param_types))
            if k not in seen_keys:
                seen_keys.add(k)
                endpoints.append(Endpoint(
                    url=clean, method="GET",
                    params=list(param_types), param_types=param_types,
                    source="js_render",
                ))
    except Exception as e:
        log.debug(f"[js] DOM links lỗi: {e}")

    # Forms
    try:
        forms = await page.evaluate("""() =>
            Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action || location.href,
                method: (f.method || 'get').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                            .filter(i => i.name)
                            .map(i => ({name: i.name, type: i.type || 'text'}))
            }))
        """)
        for form in forms:
            if not form["inputs"]:
                continue
            url = normalize_url(form["action"], base_url)
            if not in_scope(url, scope):
                continue
            param_types = {i["name"]: _html_type(i["type"]) for i in form["inputs"]}
            k = dedup_key(url, form["method"], list(param_types))
            if k not in seen_keys:
                seen_keys.add(k)
                endpoints.append(Endpoint(
                    url=url, method=form["method"],
                    params=list(param_types), param_types=param_types,
                    source="js_render",
                    content_type="application/x-www-form-urlencoded",
                ))
    except Exception as e:
        log.debug(f"[js] DOM forms lỗi: {e}")


# ─── Auto Interact ────────────────────────────────────────────────────────────

async def _scroll_page(page: Page):
    """Scroll xuống cuối trang để kích hoạt lazy-load API."""
    try:
        await page.evaluate("""async () => {
            await new Promise(resolve => {
                let total = 0;
                const step = window.innerHeight;
                const timer = setInterval(() => {
                    window.scrollBy(0, step);
                    total += step;
                    if (total >= document.body.scrollHeight) {
                        clearInterval(timer);
                        resolve();
                    }
                }, 300);
            });
        }""")
        await page.wait_for_timeout(1000)
        log.debug("[js] Scroll xong")
    except Exception:
        pass


async def _auto_interact(page: Page, base_url: str, scope: str, seen_keys: set, endpoints: list):
    """
    Click các element UI để kích hoạt API ẩn.
    Đây là cách duy nhất để bắt được API trong React/Vue:
    nhiều API chỉ được gọi khi user click vào tab/menu/button.
    """
    clicked = 0

    for selector in CLICKABLE:
        if clicked >= MAX_CLICKS:
            break
        try:
            elements = await page.query_selector_all(selector)
        except Exception:
            continue

        for el in elements:
            if clicked >= MAX_CLICKS:
                break
            try:
                # Lấy text để kiểm tra blacklist
                text = (await el.inner_text()).lower().strip()
                href = (await el.get_attribute("href") or "").lower()

                # Bỏ qua logout, delete...
                if any(b in text or b in href for b in BLACKLIST):
                    continue

                # Bỏ qua link ngoài scope
                if href.startswith("http") and not in_scope(href, scope):
                    continue

                await el.click(timeout=3000)
                await page.wait_for_timeout(WAIT_MS)

                # Thu thập thêm sau mỗi click
                await _collect_from_dom(page, base_url, scope, seen_keys, endpoints)
                clicked += 1

            except Exception as e:
                log.debug(f"[js] Click lỗi: {e}")

    log.info(f"[js] Auto-interact: {clicked} clicks")


def _html_type(t: str) -> str:
    return {"number": "integer", "email": "email",
            "password": "string", "checkbox": "boolean", "date": "date"}.get(t, "string")