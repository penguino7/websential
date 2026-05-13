# =============================================================================
# fuzzer/payload_planner.py — Sinh payload bổ sung bằng AI
#
# Dùng kỹ thuật RAG đơn giản:
#   Nhúng tài liệu OWASP/CWE vào prompt → Ollama sinh payload dựa trên tài liệu
#   → Payload chính xác hơn, bám sát thực tế, tránh hallucination
#
# Tài liệu tham chiếu:
#   OWASP Testing Guide OTG-INPVAL-005 (SQLi), OTG-CLIENT-001 (XSS)
#   CWE-89 (SQL Injection), CWE-79 (XSS)
# =============================================================================

import json
import logging

from llm.ollama_client import call_json

log = logging.getLogger(__name__)

# ─── Tài liệu nhúng vào prompt (RAG) ─────────────────────────────────────────

SQLI_KNOWLEDGE = """
[Tài liệu OWASP CWE-89 - SQL Injection]
SQL Injection xảy ra khi input người dùng được nối trực tiếp vào câu SQL mà không dùng Prepared Statements.

Các kỹ thuật kiểm thử (OWASP OTG-INPVAL-005):
1. Error-based: chèn ký tự đặc biệt (', ", --, #) để trigger SQL error message
2. Union-based: dùng UNION SELECT để extract data từ bảng khác
3. Boolean-based: dùng điều kiện TRUE/FALSE để phân biệt response
4. Time-based: dùng SLEEP/WAITFOR để đo thời gian response

Dấu hiệu vulnerable:
- Response chứa SQL error: "microsoft ole db", "unclosed quotation mark",
  "incorrect syntax near", "you have an error in your sql"
- Response thay đổi theo điều kiện TRUE vs FALSE
- Response chậm bất thường khi dùng SLEEP/WAITFOR

Context đặc biệt cho MSSQL/ASP Classic:
- Comment: -- hoặc /**/
- Time-based: WAITFOR DELAY '0:0:3'
- Version: @@version, @@servername
"""

XSS_KNOWLEDGE = """
[Tài liệu OWASP CWE-79 - Cross-Site Scripting]
Reflected XSS xảy ra khi input được phản chiếu trong response HTML mà không encode output.

Các context cần test (OWASP OTG-CLIENT-001):
1. HTML body context: <script>alert(1)</script>
2. HTML attribute context: " onmouseover="alert(1)
3. JavaScript context: '; alert(1)//

Dấu hiệu vulnerable:
- Payload xuất hiện nguyên xi trong HTML response
- Browser thực sự trigger alert() khi mở URL với payload

Kỹ thuật bypass filter phổ biến:
- Case variation: <ScRiPt>alert(1)</ScRiPt>
- Event handler: <img src=x onerror=alert(1)>
- SVG: <svg onload=alert(1)>
- Protocol: <a href=javascript:alert(1)>
"""


def generate_plan(endpoints: list) -> dict:
    """
    Sinh payload bổ sung bằng AI cho từng endpoint.
    AI dùng tài liệu OWASP/CWE để sinh payload phù hợp ngữ cảnh.

    Returns:
        {endpoint_id: [payload_str, ...]}  — chỉ list payload, không có structure phức tạp
    """
    targets = [ep for ep in endpoints if ep.risk_level in ("high", "medium")]
    if not targets:
        log.warning("[planner] Không có endpoint cần plan")
        return {}

    plan = {}
    for ep in targets:
        ep_plan = _plan_one(ep)
        if ep_plan:
            plan[ep.id] = ep_plan

    log.info(f"[planner] Sinh plan cho {len(plan)} endpoints")
    return plan


def _plan_one(ep) -> list[str]:
    """Sinh payload cho 1 endpoint, tách riêng SQLi và XSS."""
    payloads = []
    vulns    = ep.likely_vulns or []

    if "sqli" in vulns:
        sqli_payloads = _ai_generate_sqli(ep)
        payloads.extend(sqli_payloads)

    if "xss" in vulns:
        xss_payloads = _ai_generate_xss(ep)
        payloads.extend(xss_payloads)

    return payloads


def _ai_generate_sqli(ep) -> list[str]:
    prompt = f"""
{SQLI_KNOWLEDGE}

Dựa vào tài liệu trên, sinh 5 payload SQL Injection phù hợp nhất để test endpoint sau:
- URL: {ep.url}
- Method: {ep.method}
- Params: {ep.params}
- Param types: {ep.param_types}

Chú ý:
- Endpoint này có vẻ dùng MSSQL/ASP nên ưu tiên payload MSSQL
- Chỉ sinh payload từ kiến thức trong tài liệu, không bịa

Trả về JSON array đơn giản (chỉ strings, không object):
["payload1", "payload2", "payload3", "payload4", "payload5"]
"""
    result = call_json(prompt)
    if isinstance(result, list) and all(isinstance(p, str) for p in result):
        log.info(f"[planner] AI sinh {len(result)} SQLi payload cho {ep.id}")
        return result
    log.warning(f"[planner] SQLi AI thất bại cho {ep.id}")
    return []


def _ai_generate_xss(ep) -> list[str]:
    prompt = f"""
{XSS_KNOWLEDGE}

Dựa vào tài liệu trên, sinh 5 payload XSS phù hợp nhất để test endpoint sau:
- URL: {ep.url}
- Method: {ep.method}
- Params: {ep.params}
- Param types: {ep.param_types}

Chú ý:
- Ưu tiên payload có thể trigger alert() trong browser thật
- Chỉ sinh payload từ kiến thức trong tài liệu, không bịa

Trả về JSON array đơn giản (chỉ strings, không object):
["payload1", "payload2", "payload3", "payload4", "payload5"]
"""
    result = call_json(prompt)
    if isinstance(result, list) and all(isinstance(p, str) for p in result):
        log.info(f"[planner] AI sinh {len(result)} XSS payload cho {ep.id}")
        return result
    log.warning(f"[planner] XSS AI thất bại cho {ep.id}")
    return []