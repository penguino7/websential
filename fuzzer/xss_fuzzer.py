# =============================================================================
# fuzzer/xss_fuzzer.py — Kiểm thử XSS với adaptive fuzzing + Playwright
#
# Pipeline:
#   Bước 1: Probe reflection → bỏ qua param không reflect (tránh false positive)
#   Bước 2: Vòng 1 HTTP fuzz → detect reflection cơ bản
#   Bước 3: Adaptive rounds → AI sinh payload bypass filter
#   Bước 4: Playwright xác nhận alert() → HIGH confidence chắc chắn
#
# Tham chiếu: OWASP OTG-CLIENT-001, CWE-79
# =============================================================================

import time
import asyncio
import logging
import requests

from playwright.async_api import async_playwright

from fuzzer.models          import LogEntry
from fuzzer.payload_planner import refine_plan, MAX_ROUNDS, MIN_NEW_PAYLOADS
import config

log = logging.getLogger(__name__)

HEADERS    = {"User-Agent": "WebSentinel/1.0"}
PROBE_TEXT = "xss_probe_ws_12345"


def fuzz_xss(endpoints: list, plan: dict) -> list[LogEntry]:
    """
    Fuzz XSS với adaptive multi-round và xác nhận Playwright.

    Args:
        endpoints: Danh sách Endpoint
        plan:      {ep_id: {"xss": [payload,...]}}

    Returns:
        Danh sách LogEntry
    """
    targets  = [ep for ep in endpoints if "xss" in ep.likely_vulns]
    all_logs = []

    for ep in targets:
        if ep.id not in plan or "xss" not in plan[ep.id]:
            continue

        log.info(f"[xss] ── Testing {ep.method} {ep.url}")
        ep_logs       = []
        used_payloads = set()
        candidates    = []   # payload cần Playwright xác nhận

        for param in ep.params:
            # Bước 1: Probe reflection — bỏ qua nếu không reflect
            if not _check_reflection(ep, param):
                log.debug(f"[xss] {param} không reflect → bỏ qua")
                continue

            log.debug(f"[xss] {param} có reflection → test")

            # Bước 2: Vòng 1
            payloads   = [p for p in plan[ep.id]["xss"] if p not in used_payloads]
            round_logs = _fuzz_http(ep, param, payloads, used_payloads)
            ep_logs.extend(round_logs)

            # Thu thập candidate cho Playwright
            candidates += [l.payload for l in round_logs
                           if l.is_vulnerable and l.payload not in candidates]

            # Bước 3: Adaptive rounds
            for round_num in range(2, MAX_ROUNDS + 1):
                # Dừng nếu Playwright đã xác nhận
                if any(getattr(l, "playwright_confirmed", False) for l in ep_logs):
                    break

                new_plan = refine_plan(ep, [l.to_dict() for l in ep_logs], round_num)
                new_xss  = [p for p in new_plan.get("xss", []) if p not in used_payloads]

                if len(new_xss) < MIN_NEW_PAYLOADS:
                    log.info(f"[xss] Vòng {round_num}: AI sinh {len(new_xss)} payload mới → dừng")
                    break

                log.info(f"[xss] Vòng {round_num}: thử {len(new_xss)} payload mới")
                round_logs = _fuzz_http(ep, param, new_xss, used_payloads)
                ep_logs.extend(round_logs)
                candidates += [l.payload for l in round_logs
                               if l.is_vulnerable and l.payload not in candidates]

        # Bước 4: Playwright xác nhận candidates
        if candidates:
            confirmed = asyncio.run(_playwright_confirm(ep, candidates))
            for l in ep_logs:
                if l.payload in confirmed:
                    l.confidence          = "high"
                    l.playwright_confirmed = True
                    log.warning(
                        f"[xss] ✅ PLAYWRIGHT CONFIRMED: {ep.url} payload={l.payload!r}"
                    )

        all_logs.extend(ep_logs)

    total_vuln = sum(1 for l in all_logs if l.is_vulnerable)
    total_pw   = sum(1 for l in all_logs if getattr(l, "playwright_confirmed", False))
    log.info(f"[xss] Xong — {len(all_logs)} requests | {total_vuln} suspect | {total_pw} confirmed")
    return all_logs


# ─── Probe reflection ─────────────────────────────────────────────────────────

def _check_reflection(ep, param) -> bool:
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


# ─── HTTP fuzz ────────────────────────────────────────────────────────────────

def _fuzz_http(ep, param, payloads: list, used: set) -> list[LogEntry]:
    logs = []
    for payload in payloads:
        if payload in used:
            continue
        try:
            params = {p: ("test" if p != param else payload) for p in ep.params}
            if ep.method == "GET":
                resp = requests.get(ep.url, params=params, headers=HEADERS,
                                    timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
                req  = {"url": resp.url, "method": "GET", "params": params, "payload": payload}
            else:
                resp = requests.post(ep.url, data=params, headers=HEADERS,
                                     timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
                req  = {"url": ep.url, "method": "POST", "params": params, "payload": payload}

            used.add(payload)
            snippet    = _extract_snippet(resp.text, payload)
            vuln, conf = _detect_http(payload, resp.text)

            logs.append(LogEntry(
                endpoint_id=ep.id, url=ep.url, param=param,
                vuln_type="xss", payload=payload, technique="http_reflection",
                request=req,
                response={"status": resp.status_code,
                          "length": len(resp.content), "body_snippet": snippet},
                baseline={}, is_vulnerable=vuln, confidence=conf,
            ))
        except requests.RequestException as e:
            log.debug(f"[xss] HTTP lỗi: {e}")
        time.sleep(config.FUZZ_DELAY)
    return logs


def _detect_http(payload: str, body: str) -> tuple[bool, str]:
    body_lower = body.lower()
    if payload.lower() in body_lower:
        return True, "medium"   # reflect → suspect, chờ Playwright xác nhận
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
    if encoded.lower() in body_lower:
        return True, "low"
    return False, "none"


# ─── Playwright xác nhận alert() ─────────────────────────────────────────────

async def _playwright_confirm(ep, candidate_payloads: list) -> list[str]:
    """
    Mở browser thật → inject payload → kiểm tra alert() trigger.
    Đây là bằng chứng dứt khoát: XSS HIGH 100%.
    """
    confirmed = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        context = await browser.new_context()

        for payload in candidate_payloads:
            page            = await context.new_page()
            alert_triggered = False

            async def on_dialog(dialog):
                nonlocal alert_triggered
                alert_triggered = True
                await dialog.accept()

            page.on("dialog", on_dialog)

            try:
                from urllib.parse import urlencode
                params = {p: ("test" if p != ep.params[0] else payload)
                          for p in ep.params}
                if ep.method == "GET":
                    url = f"{ep.url}?{urlencode(params)}"
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                else:
                    await page.goto(ep.url, wait_until="domcontentloaded", timeout=10000)
                    await page.evaluate(
                        _build_form_js(params)
                    )

                await page.wait_for_timeout(2000)

            except Exception as e:
                log.debug(f"[xss] Playwright lỗi: {e}")
            finally:
                await page.close()

            if alert_triggered:
                confirmed.append(payload)

        await browser.close()

    return confirmed


def _build_form_js(params: dict) -> str:
    lines = ["() => {", "  const f = document.querySelector('form');",
             "  if (!f) return;"]
    for name, value in params.items():
        safe = value.replace("'", "\\'").replace("\n", "\\n")
        lines.append(
            f"  const el = f.querySelector('[name=\"{name}\"]');"
            f" if(el) el.value='{safe}';"
        )
    lines += ["  f.submit();", "}"]
    return "\n".join(lines)


def _extract_snippet(body: str, payload: str) -> str:
    idx = body.lower().find(payload.lower()[:15])
    if idx != -1:
        return body[max(0, idx-100): idx+500]
    return body[:800]