# =============================================================================
# crawler/classifier.py — Phân loại rủi ro endpoint bằng AI
#
# Hoạt động:
#   1. Gửi danh sách endpoint cho Gemini
#   2. Gemini trả về risk_level + likely_vulns cho từng endpoint
#   3. Nếu Gemini lỗi → tự động dùng rule-based fallback
#
# Output điền vào Endpoint.risk_level và Endpoint.likely_vulns
# Thông tin này quyết định endpoint nào được fuzz và fuzz loại gì
# =============================================================================

import json
import logging
import re

from crawler.models import Endpoint
# Thay bằng:
from llm.router import call_llm_json

log = logging.getLogger(__name__)

BATCH_SIZE = 15  # Số endpoint gửi mỗi lần (tránh prompt quá dài)

# Pattern nhận biết path nguy hiểm
HIGH_RISK_PATHS  = re.compile(
    r"/(admin|user|account|order|payment|api|auth|login|register|profile)", re.I
)
# Param name nguy hiểm → SQLi, IDOR
HIGH_RISK_PARAMS = {"id", "user_id", "account_id", "order_id", "file", "path", "token", "redirect"}
# Param name → XSS
MED_RISK_PARAMS  = {"q", "query", "search", "name", "msg", "message", "comment", "keyword"}


def classify(endpoints: list[Endpoint], api_key: str = "", use_ai: bool = True) -> list[Endpoint]:
    """
    Phân loại risk_level và likely_vulns cho từng endpoint.

    Args:
        endpoints: Danh sách endpoint cần phân loại
        api_key:   Gemini API key (để trống → dùng rule-based)
        use_ai:    False → bắt buộc dùng rule-based

    Returns:
        Danh sách endpoint đã được điền risk_level và likely_vulns
    """
    if not use_ai or not api_key:
        log.info("[classifier] Dùng rule-based (không có AI)")
        return [_rule_classify(ep) for ep in endpoints]

    # Chia batch để tránh prompt quá dài
    for i in range(0, len(endpoints), BATCH_SIZE):
        batch = endpoints[i: i + BATCH_SIZE]
        _classify_batch(batch, api_key)
        log.info(f"[classifier] Batch {i // BATCH_SIZE + 1} xong")

    return endpoints


# ─── AI Classification ────────────────────────────────────────────────────────

def _classify_batch(batch: list[Endpoint], api_key: str):
    """Gửi 1 batch endpoint cho Gemini để phân loại."""
    ep_list = [
        {
            "id":          ep.id,
            "url":         ep.url,
            "method":      ep.method,
            "params":      ep.params,
            "param_types": ep.param_types,
        }
        for ep in batch
    ]

    prompt = f"""Bạn là chuyên gia pentest web. Phân loại risk level cho các endpoint sau.

Danh sách endpoint:
{json.dumps(ep_list, indent=2, ensure_ascii=False)}

Trả về JSON array (chỉ JSON, không có text thừa):
[
  {{
    "id": "<endpoint_id>",
    "risk_level": "high|medium|low|skip",
    "likely_vulns": ["sqli", "xss", "idor", "auth_bypass", "path_traversal"],
    "reason": "<lý do ngắn gọn tiếng Việt>"
  }}
]

Quy tắc phân loại:
- high:   param số nguyên (?id=), path /admin /api/user /login, param tên 'file' 'token'
- medium: param string tự do (?q= ?search= ?name=), form upload
- low:    endpoint không có param nhạy cảm
- skip:   file ảnh/CSS/JS, /ping /health, không có param nào"""

   
    
    result = call_llm_json(prompt)

    if not result or not isinstance(result, list):
        log.warning("[classifier] Gemini thất bại → rule-based cho batch này")
        for ep in batch:
            _rule_classify(ep)
        return

    # Áp dụng kết quả từ Gemini vào từng Endpoint object
    id_map = {ep.id: ep for ep in batch}
    for item in result:
        ep = id_map.get(item.get("id", ""))
        if ep:
            ep.risk_level   = item.get("risk_level", "unknown")
            ep.likely_vulns = item.get("likely_vulns", [])
            ep.risk_reason  = item.get("reason", "")


# ─── Rule-based fallback ──────────────────────────────────────────────────────

def _rule_classify(ep: Endpoint) -> Endpoint:
    """
    Phân loại rủi ro bằng rule cứng — dùng khi Gemini không khả dụng.
    Logic đơn giản nhưng đủ để fuzz đúng hướng.
    """
    params_lower = {p.lower() for p in ep.params}
    path         = ep.url.lower()
    vulns        = []
    risk         = "low"

    # Param kiểu integer → khả năng cao SQLi + IDOR
    if any(t == "integer" for t in ep.param_types.values()):
        vulns += ["sqli", "idor"]
        risk   = "high"

    # Path chứa keyword nhạy cảm
    if HIGH_RISK_PATHS.search(path):
        risk = "high"
        if any(k in path for k in ["login", "auth"]):
            vulns.append("auth_bypass")

    # Param name nguy hiểm
    if params_lower & HIGH_RISK_PARAMS:
        risk = "high"
        if "file" in params_lower or "path" in params_lower:
            vulns.append("path_traversal")
        if "id" in params_lower:
            vulns += ["sqli", "idor"]

    # Param string tự do → XSS
    if params_lower & MED_RISK_PARAMS:
        vulns.append("xss")
        if risk == "low":
            risk = "medium"

    # Không có param → skip
    if not ep.params:
        risk  = "skip"
        vulns = []

    ep.risk_level   = risk
    ep.likely_vulns = list(set(vulns))
    ep.risk_reason  = "rule-based"
    return ep