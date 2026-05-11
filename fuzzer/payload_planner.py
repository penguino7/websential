# =============================================================================
# fuzzer/payload_planner.py — Sinh payload test cho từng endpoint
#
# Dùng Ollama để sinh payload thông minh theo ngữ cảnh endpoint.
# Fallback payload cứng nếu Ollama lỗi.
# =============================================================================

import json
import logging

from llm.ollama_client import call_json

log = logging.getLogger(__name__)

# Payload cứng dùng khi Ollama không khả dụng
DEFAULT_PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "' OR '1'='1' --",
        "' UNION SELECT NULL--", "1' AND SLEEP(3)--", "' OR 1=1#",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>', "<svg onload=alert(1)>",
        "<ScRiPt>alert(1)</ScRiPt>", "xss_probe_ws",
    ],
    "idor": ["1", "2", "3", "0", "-1", "999999"],
}


def generate_plan(endpoints: list) -> dict:
    """
    Sinh payload plan cho tất cả endpoint high/medium.

    Returns:
        {endpoint_id: [{"param": ..., "vuln_type": ..., "payloads": [...]}]}
    """
    targets = [ep for ep in endpoints if ep.risk_level in ("high", "medium")]
    if not targets:
        log.warning("[planner] Không có endpoint cần test")
        return {}

    plan = {}
    for i in range(0, len(targets), 10):
        batch = targets[i:i + 10]
        plan.update(_ai_plan(batch))

    log.info(f"[planner] Plan cho {len(plan)} endpoints")
    return plan


def _ai_plan(batch: list) -> dict:
    """Gửi batch cho Ollama để sinh payload."""
    ep_list = [
        {"id": ep.id, "url": ep.url, "method": ep.method,
         "params": ep.params, "param_types": ep.param_types,
         "likely_vulns": ep.likely_vulns}
        for ep in batch
    ]

    prompt = f"""Bạn là chuyên gia pentest web. Sinh payload kiểm thử cho các endpoint.

Endpoint:
{json.dumps(ep_list, indent=2, ensure_ascii=False)}

Trả về JSON object, không có text thừa:
{{"<endpoint_id>":[{{"param":"...","vuln_type":"sqli|xss|idor","payloads":["p1","p2","p3"]}}]}}

Quy tắc:
- param integer → sqli + idor
- param string  → xss
- Sinh 4-5 payload thực tế cho mỗi loại
- Chỉ test vuln_type trong likely_vulns"""

    result = call_json(prompt)

    if not result or not isinstance(result, dict):
        log.warning("[planner] Ollama thất bại → payload cứng")
        return _default_plan(batch)

    return result


def _default_plan(endpoints: list) -> dict:
    """Fallback: gán payload cứng theo likely_vulns."""
    plan = {}
    for ep in endpoints:
        items = []
        for param in ep.params:
            vulns = ep.likely_vulns or (["sqli", "idor"] if ep.param_types.get(param) == "integer" else ["xss"])
            for vuln in vulns:
                if vuln in DEFAULT_PAYLOADS:
                    items.append({"param": param, "vuln_type": vuln, "payloads": DEFAULT_PAYLOADS[vuln]})
        if items:
            plan[ep.id] = items
    return plan