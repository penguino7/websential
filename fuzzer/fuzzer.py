# =============================================================================
# fuzzer/fuzzer.py — Engine gửi payload vào endpoint và phát hiện lỗ hổng
#
# Hoạt động:
#   1. Nhận endpoint + payload plan
#   2. Gửi baseline request (giá trị bình thường) để so sánh
#   3. Gửi fuzz request với từng payload
#   4. So sánh response với baseline → phát hiện lỗ hổng
#   5. Trả về danh sách LogEntry
#
# Hỗ trợ: SQLi (error-based, time-based), XSS (reflected), IDOR
# =============================================================================

import time
import logging
import requests

from fuzzer.models import LogEntry

log = logging.getLogger(__name__)

HEADERS = {"User-Agent": "WebSentinel/1.0 (security-scanner)"}

# ─── Dấu hiệu SQL error trong response ───────────────────────────────────────
SQLI_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-01756", "sqlite_",
    "pg_query", "you have an error in your sql",
    "warning: mysql", "unclosed quotation mark",
    "microsoft ole db", "jdbc", "sqlstate",
    "odbc driver", "syntax error",
]

# ─── Payload XSS để kiểm tra reflection ──────────────────────────────────────
XSS_MARKERS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]


def fuzz(
    endpoints:    list,          # list[Endpoint]
    payload_plan: dict,          # {ep_id: [{param, vuln_type, payloads}]}
    timeout:      int   = 8,
    delay:        float = 0.5,
    max_per_ep:   int   = 20,
    headers:      dict  = None,
) -> list[LogEntry]:
    """
    Fuzz tất cả endpoint theo payload plan.

    Args:
        endpoints:    Danh sách endpoint cần fuzz
        payload_plan: Kế hoạch payload {ep_id: [{param, vuln_type, payloads}]}
        timeout:      Timeout mỗi request (giây)
        delay:        Chờ giữa các request (giây)
        max_per_ep:   Số request tối đa mỗi endpoint
        headers:      Header bổ sung (cookie auth...)

    Returns:
        Danh sách LogEntry chứa toàn bộ kết quả
    """
    hdrs     = {**HEADERS, **(headers or {})}
    all_logs = []

    for ep in endpoints:
        if ep.id not in payload_plan:
            continue

        log.info(f"[fuzzer] Testing {ep.method} {ep.url}")

        # Lấy baseline để so sánh
        baseline = _get_baseline(ep, hdrs, timeout)
        req_count = 0

        for item in payload_plan[ep.id]:
            if req_count >= max_per_ep:
                log.warning(f"[fuzzer] Đã đạt giới hạn {max_per_ep} requests cho {ep.id}")
                break

            param     = item["param"]
            vuln_type = item["vuln_type"]

            for payload in item["payloads"]:
                if req_count >= max_per_ep:
                    break

                entry = _send_one_request(ep, param, payload, vuln_type, baseline, hdrs, timeout)
                if entry:
                    all_logs.append(entry)
                    req_count += 1

                    if entry.is_vulnerable:
                        log.warning(
                            f"[fuzzer] ⚠ [{vuln_type.upper()}] {ep.url} "
                            f"param={param} confidence={entry.confidence}"
                        )

                time.sleep(delay)

    vuln_count = sum(1 for l in all_logs if l.is_vulnerable)
    log.info(f"[fuzzer] Xong — {len(all_logs)} requests, {vuln_count} vulnerable")
    return all_logs


# ─── Gửi 1 request fuzz ──────────────────────────────────────────────────────

def _send_one_request(ep, param, payload, vuln_type, baseline, hdrs, timeout) -> LogEntry | None:
    """Gửi 1 request fuzz và kiểm tra kết quả."""
    try:
        t0 = time.time()

        if ep.method == "GET":
            # Giữ nguyên các param khác, chỉ thay param đang test
            params = {p: ("1" if p != param else payload) for p in ep.params}
            resp   = requests.get(ep.url, params=params, headers=hdrs,
                                  timeout=timeout, allow_redirects=True)
            req_info = {"url": resp.url, "method": "GET", "params": params, "payload": payload}

        else:  # POST
            data   = {p: ("test" if p != param else payload) for p in ep.params}
            resp   = requests.post(ep.url, data=data, headers=hdrs,
                                   timeout=timeout, allow_redirects=True)
            req_info = {"url": ep.url, "method": "POST", "params": data, "payload": payload}

        duration_ms = int((time.time() - t0) * 1000)

        resp_info = {
            "status":       resp.status_code,
            "length":       len(resp.content),
            "body_snippet": resp.text[:500],
        }

        # Phân tích kết quả
        is_vuln, confidence = _detect_vulnerability(vuln_type, payload, resp, baseline, duration_ms)

        return LogEntry(
            endpoint_id  = ep.id,
            url          = ep.url,
            param        = param,
            vuln_type    = vuln_type,
            payload      = payload,
            request      = req_info,
            response     = resp_info,
            baseline     = baseline,
            is_vulnerable= is_vuln,
            confidence   = confidence,
            duration_ms  = duration_ms,
        )

    except requests.RequestException as e:
        log.debug(f"[fuzzer] Request lỗi: {e}")
        return None


# ─── Detection logic ──────────────────────────────────────────────────────────

def _detect_vulnerability(vuln_type, payload, resp, baseline, duration_ms) -> tuple[bool, str]:
    """
    Phân tích response để phát hiện lỗ hổng.
    Trả về (is_vulnerable, confidence_level).
    """
    body = resp.text.lower()

    if vuln_type == "sqli":
        # Error-based: SQL error xuất hiện trong response → HIGH
        for sig in SQLI_ERROR_SIGNATURES:
            if sig in body:
                return True, "high"
        # Time-based: response rất chậm khi có SLEEP() → MEDIUM
        if "sleep" in payload.lower() and duration_ms > 2500:
            return True, "medium"
        # Status 500 khác baseline → LOW (có thể do injection gây lỗi)
        if resp.status_code == 500 and baseline.get("status") == 200:
            return True, "low"

    elif vuln_type == "xss":
        # Reflected nguyên xi → HIGH
        for marker in XSS_MARKERS:
            if marker.lower() in body:
                return True, "high"
        # HTML encoded: <script> → &lt;script&gt; → MEDIUM
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded.lower() in body:
            return True, "medium"
        # Status 500 do ký tự đặc biệt → LOW
        if resp.status_code == 500 and baseline.get("status") == 200:
            if any(c in payload for c in ["<", ">", '"']):
                return True, "low"

    elif vuln_type == "idor":
        # Response khác baseline >20% length → MEDIUM (có thể lấy được data khác)
        base_len = baseline.get("length", 0)
        curr_len = len(resp.content)
        if resp.status_code == 200 and base_len > 0:
            diff = abs(curr_len - base_len) / base_len
            if diff > 0.2:
                return True, "medium"

    return False, "none"


# ─── Baseline request ──────────────────────────────────────────────────────────

def _get_baseline(ep, hdrs, timeout) -> dict:
    """
    Gửi request với giá trị bình thường để làm mốc so sánh.
    Giúp phát hiện thay đổi bất thường trong response.
    """
    try:
        if ep.method == "GET":
            r = requests.get(ep.url, params={p: "1" for p in ep.params},
                             headers=hdrs, timeout=timeout)
        else:
            r = requests.post(ep.url, data={p: "test" for p in ep.params},
                              headers=hdrs, timeout=timeout)
        return {"status": r.status_code, "length": len(r.content)}
    except Exception:
        return {"status": 0, "length": 0}