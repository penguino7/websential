# =============================================================================
# fuzzer/fuzzer.py — Gửi payload vào endpoint và phát hiện lỗ hổng
#
# Hỗ trợ: SQLi (error-based, time-based), XSS (reflected), IDOR
# =============================================================================

import time
import logging
import requests

from fuzzer.models import LogEntry
import config

log = logging.getLogger(__name__)

HEADERS = {"User-Agent": "WebSentinel/1.0"}

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "warning: mysql", "ora-01756", "unclosed quotation",
    "microsoft ole db", "jdbc", "sqlstate", "syntax error",
]

XSS_MARKERS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]


def fuzz(endpoints: list, payload_plan: dict) -> list[LogEntry]:
    """
    Fuzz tất cả endpoint theo payload plan.

    Args:
        endpoints:    Danh sách Endpoint cần fuzz
        payload_plan: {ep_id: [{param, vuln_type, payloads}]}

    Returns:
        Danh sách LogEntry chứa kết quả
    """
    all_logs = []

    for ep in endpoints:
        if ep.id not in payload_plan:
            continue

        log.info(f"[fuzzer] Testing {ep.method} {ep.url}")
        baseline  = _baseline(ep)
        req_count = 0

        for item in payload_plan[ep.id]:
            if req_count >= config.MAX_REQ_PER_EP:
                break

            for payload in item["payloads"]:
                if req_count >= config.MAX_REQ_PER_EP:
                    break

                entry = _send(ep, item["param"], payload, item["vuln_type"], baseline)
                if entry:
                    all_logs.append(entry)
                    req_count += 1
                    if entry.is_vulnerable:
                        log.warning(f"[fuzzer] ⚠ [{item['vuln_type'].upper()}] {ep.url} param={item['param']} conf={entry.confidence}")

                time.sleep(config.FUZZ_DELAY)

    vuln = sum(1 for l in all_logs if l.is_vulnerable)
    log.info(f"[fuzzer] Xong — {len(all_logs)} requests, {vuln} vulnerable")
    return all_logs


def _send(ep, param, payload, vuln_type, baseline) -> LogEntry | None:
    """Gửi 1 request fuzz và kiểm tra kết quả."""
    try:
        t0 = time.time()

        if ep.method == "GET":
            params = {p: ("1" if p != param else payload) for p in ep.params}
            resp   = requests.get(ep.url, params=params, headers=HEADERS,
                                  timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            req    = {"url": resp.url, "method": "GET", "params": params, "payload": payload}
        else:
            data = {p: ("test" if p != param else payload) for p in ep.params}
            resp = requests.post(ep.url, data=data, headers=HEADERS,
                                 timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
            req  = {"url": ep.url, "method": "POST", "params": data, "payload": payload}

        ms       = int((time.time() - t0) * 1000)
        vuln, cf = _detect(vuln_type, payload, resp, baseline, ms)

        return LogEntry(
            endpoint_id=ep.id, url=ep.url, param=param,
            vuln_type=vuln_type, payload=payload,
            request=req,
            response={"status": resp.status_code, "length": len(resp.content),
                      "body_snippet": resp.text[:500]},
            baseline=baseline,
            is_vulnerable=vuln, confidence=cf, duration_ms=ms,
        )
    except requests.RequestException as e:
        log.debug(f"[fuzzer] Request lỗi: {e}")
        return None


def _detect(vuln_type, payload, resp, baseline, ms) -> tuple[bool, str]:
    """Phân tích response để phát hiện lỗ hổng."""
    body = resp.text.lower()

    if vuln_type == "sqli":
        for sig in SQLI_ERRORS:
            if sig in body: return True, "high"
        if "sleep" in payload.lower() and ms > 2500:
            return True, "medium"
        if resp.status_code == 500 and baseline.get("status") == 200:
            return True, "low"

    elif vuln_type == "xss":
        for m in XSS_MARKERS:
            if m.lower() in body: return True, "high"
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded.lower() in body: return True, "medium"
        if resp.status_code == 500 and baseline.get("status") == 200:
            if any(c in payload for c in ["<", ">", '"']): return True, "low"

    elif vuln_type == "idor":
        base_len = baseline.get("length", 0)
        if resp.status_code == 200 and base_len > 0:
            if abs(len(resp.content) - base_len) / base_len > 0.2:
                return True, "medium"

    return False, "none"


def _baseline(ep) -> dict:
    """Request baseline với giá trị bình thường để so sánh."""
    try:
        if ep.method == "GET":
            r = requests.get(ep.url, params={p: "1" for p in ep.params},
                             headers=HEADERS, timeout=config.REQUEST_TIMEOUT)
        else:
            r = requests.post(ep.url, data={p: "test" for p in ep.params},
                              headers=HEADERS, timeout=config.REQUEST_TIMEOUT)
        return {"status": r.status_code, "length": len(r.content)}
    except Exception:
        return {"status": 0, "length": 0}