# =============================================================================
# analyzer/log_analyzer.py — Phân tích log fuzz bằng AI → sinh Finding
#
# Hoạt động:
#   1. Đọc logs.jsonl từ session
#   2. Lọc các log có is_vulnerable=True
#   3. Gửi cho Gemini phân tích → sinh Finding chi tiết
#   4. Lưu findings.json
# =============================================================================

import json
import logging
from collections  import Counter
from dataclasses  import dataclass, field
from pathlib      import Path
import uuid

from llm.gemini_client import call_gemini_json

log = logging.getLogger(__name__)

BATCH_SIZE = 15  # Số log gửi mỗi lần


# ─── Finding model ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    Kết quả phân tích: 1 lỗ hổng được xác nhận.

    Attributes:
        url:         URL bị lỗ hổng
        param:       Param bị ảnh hưởng
        vuln_type:   Loại lỗ hổng (sqli/xss/idor)
        severity:    Mức độ nghiêm trọng (High/Medium/Low)
        description: Mô tả lỗ hổng (tiếng Việt)
        remediation: Hướng dẫn khắc phục + code ví dụ
        owasp:       Mã OWASP (vd: A03:2021-Injection)
        cwe:         Mã CWE (vd: CWE-89)
        payload:     Payload đã khai thác thành công
        evidence:    Bằng chứng (snippet response)
    """
    url:         str
    param:       str
    vuln_type:   str
    severity:    str
    description: str
    remediation: str
    owasp:       str
    cwe:         str
    payload:     str       = ""
    evidence:    str       = ""
    endpoint_id: str       = ""
    log_id:      str       = ""
    finding_id:  str       = field(default_factory=lambda: f"f_{uuid.uuid4().hex[:6]}")

    def to_dict(self) -> dict:
        return {
            "finding_id":  self.finding_id,
            "endpoint_id": self.endpoint_id,
            "log_id":      self.log_id,
            "url":         self.url,
            "param":       self.param,
            "vuln_type":   self.vuln_type,
            "severity":    self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "owasp":       self.owasp,
            "cwe":         self.cwe,
            "payload":     self.payload,
            "evidence":    self.evidence,
        }


# ─── Entry point ──────────────────────────────────────────────────────────────

def analyze(session_dir: str | Path, api_key: str = "") -> list[Finding]:
    """
    Đọc logs → phân tích → trả về danh sách Finding.

    Args:
        session_dir: Thư mục session chứa logs.jsonl
        api_key:     Gemini API key

    Returns:
        Danh sách Finding đã xác nhận
    """
    session_dir = Path(session_dir)
    logs        = _load_logs(session_dir)

    if not logs:
        log.warning("[analyzer] Không có log nào")
        return []

    # Chỉ phân tích log đánh dấu vulnerable
    vuln_logs = [l for l in logs if l.get("is_vulnerable")]
    log.info(f"[analyzer] {len(logs)} logs tổng | {len(vuln_logs)} vulnerable")

    if not vuln_logs:
        log.info("[analyzer] Không có log vulnerable nào")
        return []

    # Phân tích
    if api_key:
        findings = _analyze_with_ai(vuln_logs, api_key)
    else:
        log.info("[analyzer] Không có API key → rule-based")
        findings = _rule_analyze(vuln_logs)

    # Lưu kết quả
    _save_findings(findings, session_dir)
    _print_summary(findings)
    return findings


# ─── AI Analysis ──────────────────────────────────────────────────────────────

def _analyze_with_ai(logs: list[dict], api_key: str) -> list[Finding]:
    findings = []
    for i in range(0, len(logs), BATCH_SIZE):
        batch = logs[i:i + BATCH_SIZE]
        findings += _gemini_batch(batch, api_key)
    return findings


def _gemini_batch(logs: list[dict], api_key: str) -> list[Finding]:
    # Rút gọn log trước khi gửi tránh prompt quá dài
    slim = [
        {
            "log_id":     l["log_id"],
            "endpoint_id":l["endpoint_id"],
            "url":        l["url"],
            "param":      l["param"],
            "vuln_type":  l["vuln_type"],
            "payload":    l["payload"],
            "response": {
                "status":       l["response"]["status"],
                "length":       l["response"]["length"],
                "body_snippet": l["response"].get("body_snippet", "")[:300],
            },
            "baseline":   l.get("baseline", {}),
            "confidence": l.get("confidence", "low"),
        }
        for l in logs
    ]

    prompt = f"""Bạn là chuyên gia pentest web. Phân tích log kiểm thử bảo mật và xác nhận lỗ hổng.

Log kiểm thử:
{json.dumps(slim, indent=2, ensure_ascii=False)}

Với mỗi lỗ hổng thực sự, trả về JSON array (chỉ JSON, không text thừa):
[
  {{
    "log_id":      "<log_id>",
    "endpoint_id": "<endpoint_id>",
    "url":         "<url>",
    "param":       "<param>",
    "vuln_type":   "sqli|xss|idor",
    "severity":    "High|Medium|Low",
    "description": "<mô tả lỗ hổng tiếng Việt, nêu rõ nguy cơ>",
    "remediation": "<hướng dẫn khắc phục tiếng Việt + ví dụ code>",
    "owasp":       "<vd: A03:2021-Injection>",
    "cwe":         "<vd: CWE-89>",
    "payload":     "<payload khai thác>",
    "evidence":    "<đoạn response cho thấy lỗ hổng>"
  }}
]

Quy tắc:
- SQLi High: body có SQL error message rõ ràng
- SQLi Medium: status 500 khi inject, baseline 200
- XSS High: payload phản chiếu nguyên xi trong HTML
- XSS Medium: payload bị encode HTML trước khi reflect
- IDOR Medium: response length khác baseline >20%
- Bỏ qua false positive, trả [] nếu không có finding"""

    result = call_gemini_json(prompt, api_key)

    if not result or not isinstance(result, list):
        log.warning("[analyzer] Gemini thất bại → rule-based")
        return _rule_analyze(logs)

    findings = []
    for item in result:
        try:
            findings.append(Finding(
                url         = item.get("url", ""),
                param       = item.get("param", ""),
                vuln_type   = item.get("vuln_type", "unknown"),
                severity    = item.get("severity", "Medium"),
                description = item.get("description", ""),
                remediation = item.get("remediation", ""),
                owasp       = item.get("owasp", ""),
                cwe         = item.get("cwe", ""),
                payload     = item.get("payload", ""),
                evidence    = item.get("evidence", ""),
                endpoint_id = item.get("endpoint_id", ""),
                log_id      = item.get("log_id", ""),
            ))
        except Exception as e:
            log.debug(f"[analyzer] Parse finding lỗi: {e}")

    return findings


# ─── Rule-based fallback ──────────────────────────────────────────────────────

_OWASP = {
    "sqli": ("A03:2021-Injection",          "CWE-89"),
    "xss":  ("A03:2021-Injection",          "CWE-79"),
    "idor": ("A01:2021-Broken Access Control","CWE-639"),
}
_DESC = {
    "sqli": "Phát hiện SQL Injection. Ứng dụng không lọc đầu vào người dùng, cho phép can thiệp vào câu truy vấn SQL và có thể đọc/sửa/xóa dữ liệu trong database.",
    "xss":  "Phát hiện Cross-Site Scripting (XSS). Ứng dụng phản chiếu input mà không mã hóa, cho phép chèn mã JavaScript độc hại chạy trên trình duyệt nạn nhân.",
    "idor": "Phát hiện Insecure Direct Object Reference (IDOR). Ứng dụng không kiểm tra quyền truy cập tài nguyên theo ID, có thể truy cập dữ liệu của user khác.",
}
_REMED = {
    "sqli": "Dùng Prepared Statements:\npython: cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\nphp: $stmt = $pdo->prepare('SELECT * FROM users WHERE id=?'); $stmt->execute([$id]);",
    "xss":  "Encode output trước khi render:\npython: import html; html.escape(user_input)\njs: element.textContent = input (không dùng innerHTML)",
    "idor": "Kiểm tra quyền sở hữu: if resource.owner_id != session.user_id: return 403",
}


def _rule_analyze(logs: list[dict]) -> list[Finding]:
    findings = []
    for l in logs:
        vtype     = l.get("vuln_type", "unknown")
        owasp, cwe= _OWASP.get(vtype, ("", ""))
        findings.append(Finding(
            url        = l.get("url", ""),
            param      = l.get("param", ""),
            vuln_type  = vtype,
            severity   = "Medium",
            description= _DESC.get(vtype, "Phát hiện dấu hiệu lỗ hổng bảo mật."),
            remediation= _REMED.get(vtype, "Kiểm tra và xử lý đầu vào người dùng."),
            owasp      = owasp,
            cwe        = cwe,
            payload    = l.get("payload", ""),
            evidence   = l.get("response", {}).get("body_snippet", "")[:200],
            endpoint_id= l.get("endpoint_id", ""),
            log_id     = l.get("log_id", ""),
        ))
    return findings


# ─── I/O ──────────────────────────────────────────────────────────────────────

def _load_logs(session_dir: Path) -> list[dict]:
    path = session_dir / "logs.jsonl"
    if not path.exists():
        log.error(f"[analyzer] Không tìm thấy {path}")
        return []
    logs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                logs.append(json.loads(line))
    return logs


def _save_findings(findings: list[Finding], session_dir: Path):
    path = session_dir / "findings.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump([fi.to_dict() for fi in findings], f, indent=2, ensure_ascii=False)
    log.info(f"[analyzer] Đã lưu {len(findings)} findings → {path}")


def _print_summary(findings: list[Finding]):
    sev = Counter(f.severity for f in findings)
    print("\n" + "═" * 55)
    print(f"  PHÂN TÍCH XONG — {len(findings)} findings")
    print(f"  🔴 High: {sev.get('High',0)}  🟡 Medium: {sev.get('Medium',0)}  🟢 Low: {sev.get('Low',0)}")
    print("═" * 55)
    for f in findings:
        icon = {"High":"🔴","Medium":"🟡","Low":"🟢"}.get(f.severity,"⚪")
        print(f"\n  {icon} [{f.severity}] {f.vuln_type.upper()} — {f.url}")
        print(f"     Param  : {f.param}")
        print(f"     Payload: {f.payload}")
        print(f"     OWASP  : {f.owasp} | {f.cwe}")
        print(f"     Mô tả  : {f.description[:80]}...")
    print()