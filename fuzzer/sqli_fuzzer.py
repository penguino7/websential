# =============================================================================
# fuzzer/sqli_fuzzer.py — Kiểm thử SQL Injection với adaptive fuzzing
#
# Pipeline:
#   Vòng 1: payload từ Payload Planner (DB cứng + AI chọn backend)
#   Vòng 2-N: AI đọc response vòng trước → sinh payload mới bypass filter
#   Dừng khi: tìm được vuln rõ ràng | hết vòng | AI không sinh payload mới
#
# Kỹ thuật: error-based, time-based, boolean-based
# Tham chiếu: OWASP OTG-INPVAL-005, CWE-89
# =============================================================================

import time
import logging
import requests

from fuzzer.models          import LogEntry
from fuzzer.payload_planner import refine_plan, MAX_ROUNDS, MIN_NEW_PAYLOADS
import config

log = logging.getLogger(__name__)

HEADERS = {"User-Agent": "WebSentinel/1.0"}

SQL_ERROR_SIGNATURES = [
    "microsoft ole db", "odbc microsoft access", "odbc sql server",
    "unclosed quotation mark", "incorrect syntax near",
    "syntax error converting", "[microsoft][odbc", "sql server",
    "you have an error in your sql", "warning: mysql",
    "mysql_fetch", "ora-01756", "ora-00907",
    "jdbc", "sqlstate", "division by zero",
    "quoted string not properly terminated",
]

TIME_THRESHOLD_MS = 3500


def fuzz_sqli(endpoints: list, plan: dict) -> list[LogEntry]:
    """
    Fuzz SQL Injection với adaptive multi-round.

    Args:
        endpoints: Danh sách Endpoint
        plan:      {ep_id: {"sqli": {"error":[], "time":[], "boolean":[], "union":[]}}}

    Returns:
        Danh sách LogEntry
    """
    targets  = [ep for ep in endpoints if "sqli" in ep.likely_vulns]
    all_logs = []

    for ep in targets:
        if ep.id not in plan or "sqli" not in plan[ep.id]:
            continue

        log.info(f"[sqli] ── Testing {ep.method} {ep.url}")
        baseline  = _get_baseline(ep)
        ep_logs   = []        # log của endpoint này
        used_payloads = set() # tránh test trùng

        # ── Vòng 1: payload từ plan ───────────────────────────────────────
        sqli_plan = plan[ep.id]["sqli"]
        round_logs = _fuzz_one_round(ep, sqli_plan, baseline, used_payloads)
        ep_logs.extend(round_logs)

        # ── Vòng 2 → MAX_ROUNDS: adaptive ────────────────────────────────
        for round_num in range(2, MAX_ROUNDS + 1):
            # Dừng nếu đã tìm được high confidence
            high_found = any(
                l.is_vulnerable and l.confidence == "high" for l in ep_logs
            )
            if high_found:
                log.info(f"[sqli] Đã tìm được HIGH → dừng adaptive tại vòng {round_num}")
                break

            # Gọi AI sinh payload mới
            new_plan = refine_plan(ep, [l.to_dict() for l in ep_logs], round_num)
            new_sqli = new_plan.get("sqli", [])

            # Lọc payload thực sự mới
            new_sqli = [p for p in new_sqli if p not in used_payloads]
            if len(new_sqli) < MIN_NEW_PAYLOADS:
                log.info(f"[sqli] Vòng {round_num}: AI chỉ sinh {len(new_sqli)} payload mới → dừng")
                break

            log.info(f"[sqli] Vòng {round_num}: thử {len(new_sqli)} payload mới từ AI")
            round_plan = {"error": new_sqli, "time": [], "boolean": [], "union": []}
            round_logs = _fuzz_one_round(ep, round_plan, baseline, used_payloads)
            ep_logs.extend(round_logs)

        all_logs.extend(ep_logs)
        vuln = sum(1 for l in ep_logs if l.is_vulnerable)
        log.info(f"[sqli] {ep.url}: {len(ep_logs)} requests | {vuln} vulnerable")

    total_vuln = sum(1 for l in all_logs if l.is_vulnerable)
    log.info(f"[sqli] Xong — {len(all_logs)} requests | {total_vuln} vulnerable")
    return all_logs


def _fuzz_one_round(ep, sqli_plan: dict, baseline: dict, used: set) -> list[LogEntry]:
    """Fuzz 1 vòng với payload plan cho sẵn."""
    logs      = []
    req_count = 0

    for param in ep.params:
        if ep.param_types.get(param) not in ("integer", "string"):
            continue

        # Error-based
        for payload in sqli_plan.get("error", []):
            if req_count >= config.MAX_REQ_PER_EP or payload in used:
                break
            entry = _send(ep, param, payload, "error_based", baseline)
            if entry:
                logs.append(entry)
                used.add(payload)
                req_count += 1
                if entry.is_vulnerable and entry.confidence == "high":
                    return logs   # tìm được ngay → trả về
            time.sleep(config.FUZZ_DELAY)

        # Time-based
        for payload in sqli_plan.get("time", []):
            if req_count >= config.MAX_REQ_PER_EP or payload in used:
                break
            entry = _send(ep, param, payload, "time_based", baseline)
            if entry:
                logs.append(entry)
                used.add(payload)
                req_count += 1
            time.sleep(config.FUZZ_DELAY)

        # Boolean-based
        for true_p, false_p in sqli_plan.get("boolean", []):
            if req_count >= config.MAX_REQ_PER_EP:
                break
            key = f"{true_p}||{false_p}"
            if key in used:
                continue
            entry = _send_boolean(ep, param, true_p, false_p, baseline)
            if entry:
                logs.append(entry)
                used.add(key)
                req_count += 1
            time.sleep(config.FUZZ_DELAY)

        # Union-based
        for payload in sqli_plan.get("union", []):
            if req_count >= config.MAX_REQ_PER_EP or payload in used:
                break
            entry = _send(ep, param, payload, "union_based", baseline)
            if entry:
                logs.append(entry)
                used.add(payload)
                req_count += 1
            time.sleep(config.FUZZ_DELAY)

    return logs


# ─── Request + detection ──────────────────────────────────────────────────────

def _send(ep, param, payload, technique, baseline) -> LogEntry | None:
    try:
        t0 = time.time()
        resp, req_info = _make_request(ep, param, payload)
        ms      = int((time.time() - t0) * 1000)
        snippet = _extract_snippet(resp.text, payload)
        vuln, conf = _detect(technique, resp, baseline, ms, snippet)

        if vuln:
            log.warning(f"[sqli] ⚠ [{technique}] {ep.url} param={param} conf={conf}")

        return LogEntry(
            endpoint_id=ep.id, url=ep.url, param=param,
            vuln_type="sqli", payload=payload, technique=technique,
            request=req_info,
            response={"status": resp.status_code,
                      "length": len(resp.content), "body_snippet": snippet},
            baseline=baseline,
            is_vulnerable=vuln, confidence=conf, duration_ms=ms,
        )
    except requests.RequestException as e:
        log.debug(f"[sqli] Request lỗi: {e}")
        return None


def _send_boolean(ep, param, true_p, false_p, baseline) -> LogEntry | None:
    try:
        r_true,  _        = _make_request(ep, param, true_p)
        time.sleep(0.3)
        r_false, req_info = _make_request(ep, param, false_p)

        diff = abs(len(r_true.content) - len(r_false.content))
        vuln = diff > 100 and r_true.status_code == r_false.status_code == 200
        conf = "medium" if vuln else "none"

        if vuln:
            log.warning(f"[sqli] ⚠ [boolean] {ep.url} param={param} diff={diff}B")

        return LogEntry(
            endpoint_id=ep.id, url=ep.url, param=param,
            vuln_type="sqli",
            payload=f"TRUE:{true_p} | FALSE:{false_p}",
            technique="boolean_based", request=req_info,
            response={"status": r_true.status_code,
                      "length": len(r_true.content),
                      "body_snippet": f"TRUE_len={len(r_true.content)} FALSE_len={len(r_false.content)} diff={diff}"},
            baseline=baseline, is_vulnerable=vuln, confidence=conf,
        )
    except Exception as e:
        log.debug(f"[sqli] Boolean lỗi: {e}")
        return None


def _detect(technique, resp, baseline, ms, snippet) -> tuple[bool, str]:
    body   = snippet.lower()
    status = resp.status_code
    bl_st  = baseline.get("status", 200)

    if technique in ("error_based", "union_based"):
        for sig in SQL_ERROR_SIGNATURES:
            if sig in body:
                return True, "high"
        if status == 500 and bl_st == 200:
            return True, "low"

    elif technique == "time_based":
        if ms > TIME_THRESHOLD_MS:
            return True, "medium"

    return False, "none"


def _make_request(ep, param, payload):
    params = {p: ("1" if p != param else payload) for p in ep.params}
    if ep.method == "GET":
        resp = requests.get(ep.url, params=params, headers=HEADERS,
                            timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
        return resp, {"url": resp.url, "method": "GET", "params": params, "payload": payload}
    else:
        resp = requests.post(ep.url, data=params, headers=HEADERS,
                             timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
        return resp, {"url": ep.url, "method": "POST", "params": params, "payload": payload}


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
    for sig in ["error", "syntax", "odbc", "microsoft", "warning", "sql"]:
        idx = body.lower().find(sig)
        if idx != -1:
            return body[max(0, idx-50): idx+600]
    return body[:800]