# =============================================================================
# crawler/classifier.py — AI phân loại rủi ro endpoint
#
# Gửi endpoint cho Ollama → nhận risk_level + likely_vulns
# Fallback rule-based nếu Ollama lỗi
# =============================================================================

import json
import logging
import re

from crawler.models      import Endpoint
from llm.ollama_client   import call_json

log        = logging.getLogger(__name__)
BATCH_SIZE = 15

HIGH_PATHS  = re.compile(r"/(admin|user|account|order|api|auth|login|register|profile)", re.I)
HIGH_PARAMS = {"id", "user_id", "file", "path", "token", "redirect"}
MED_PARAMS  = {"q", "query", "search", "name", "msg", "comment"}


def classify(endpoints: list[Endpoint]) -> list[Endpoint]:
    """
    Phân loại risk_level và likely_vulns cho từng endpoint.
    Dùng Ollama, fallback rule-based nếu lỗi.
    """
    for i in range(0, len(endpoints), BATCH_SIZE):
        batch = endpoints[i: i + BATCH_SIZE]
        _classify_batch(batch)
        log.info(f"[classifier] Batch {i // BATCH_SIZE + 1} xong")
    return endpoints


def _classify_batch(batch: list[Endpoint]):
    ep_list = [
        {"id": ep.id, "url": ep.url, "method": ep.method,
         "params": ep.params, "param_types": ep.param_types}
        for ep in batch
    ]

    prompt = f"""Bạn là chuyên gia pentest web. Phân loại risk level cho các endpoint.

Endpoint:
{json.dumps(ep_list, indent=2, ensure_ascii=False)}

Trả về JSON array, không có text thừa:
[{{"id":"...","risk_level":"high|medium|low|skip","likely_vulns":["sqli","xss","idor","auth_bypass"],"reason":"..."}}]

Quy tắc:
- high:   param số nguyên, path /admin /api /login, param tên 'file' 'token'
- medium: param string tự do (?q= ?search=)
- low:    không có param nhạy cảm
- skip:   file tĩnh, không có param"""

    result = call_json(prompt)

    if not result or not isinstance(result, list):
        log.warning("[classifier] Ollama thất bại → rule-based")
        for ep in batch: _rule_classify(ep)
        return

    id_map = {ep.id: ep for ep in batch}
    for item in result:
        ep = id_map.get(item.get("id", ""))
        if ep:
            ep.risk_level   = item.get("risk_level", "unknown")
            ep.likely_vulns = item.get("likely_vulns", [])
            ep.risk_reason  = item.get("reason", "")


def _rule_classify(ep: Endpoint) -> Endpoint:
    """Fallback: phân loại bằng rule cứng."""
    params = {p.lower() for p in ep.params}
    path   = ep.url.lower()
    vulns  = []
    risk   = "low"

    if any(t == "integer" for t in ep.param_types.values()):
        vulns += ["sqli", "idor"]; risk = "high"
    if HIGH_PATHS.search(path):
        risk = "high"
        if "login" in path or "auth" in path: vulns.append("auth_bypass")
    if params & HIGH_PARAMS:
        risk = "high"
        if "id" in params: vulns += ["sqli", "idor"]
    if params & MED_PARAMS:
        vulns.append("xss")
        if risk == "low": risk = "medium"
    if not ep.params:
        risk = "skip"; vulns = []

    ep.risk_level   = risk
    ep.likely_vulns = list(set(vulns))
    ep.risk_reason  = "rule-based"
    return ep