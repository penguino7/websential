# =============================================================================
# analyzer/log_analyzer.py — Phân tích log bằng AI + cross-check rule
#
# Pipeline:
#   1. Đọc logs.jsonl → lọc is_vulnerable=True
#   2. AI phân tích dựa trên tài liệu OWASP/CWE/CVSS (RAG)
#   3. Rule-based cross-check → giảm hallucination
#   4. Playwright-confirmed XSS → tự động HIGH
#   5. Lưu findings.json
# =============================================================================

import json
import logging
from collections  import Counter
from dataclasses  import dataclass, field
from pathlib      import Path
import uuid

from llm.ollama_client import call_json

log        = logging.getLogger(__name__)
BATCH_SIZE = 5   # nhỏ để tránh timeout Ollama


# ─── Tài liệu nhúng vào prompt (RAG) ─────────────────────────────────────────

ANALYSIS_KNOWLEDGE = """
[Tiêu chí xác nhận lỗ hổng — OWASP + CVSS v3.1]

=== SQL INJECTION (CWE-89) ===
CVSS Base Score: 9.8 (Critical) — Confidentiality/Integrity/Availability: HIGH

Xác nhận HIGH (confirmed=true, severity=High):
- Response chứa SQL error rõ ràng: "microsoft ole db", "unclosed quotation mark",
  "incorrect syntax near", "you have an error in your sql", "syntax error converting",
  "[microsoft][odbc", "warning: mysql"
- Time-based: response chậm >3.5s khi dùng SLEEP/WAITFOR

Xác nhận MEDIUM (confirmed=true, severity=Medium):
- technique="boolean_based": response TRUE khác FALSE rõ rệt (>100 bytes)
- Status 500 liên tục khi inject, baseline là 200

FALSE POSITIVE (confirmed=false):
- Status 500 đơn thuần không có SQL error message
- Response không thay đổi so với baseline

=== CROSS-SITE SCRIPTING (CWE-79) ===
CVSS Base Score: 6.1 (Medium) — Requires user interaction

Xác nhận HIGH (confirmed=true, severity=High):
- playwright_confirmed=true: browser thực sự trigger alert() → đây là bằng chứng tuyệt đối
- Payload <script>alert(1)</script> xuất hiện NGUYÊN XI trong response HTML

Xác nhận MEDIUM (confirmed=true, severity=Medium):
- Payload bị HTML encode (&lt;script&gt;) nhưng vẫn xuất hiện → có thể DOM XSS
- Event handler payload xuất hiện trong attribute HTML

FALSE POSITIVE (confirmed=false):
- Payload không xuất hiện trong response
- Status 500 đơn thuần (server lỗi, không phải reflection)
- Chỉ có probe text reflect nhưng XSS payload không reflect
"""

SQL_ERROR_SIGNATURES = [
    "microsoft ole db", "odbc microsoft access", "unclosed quotation mark",
    "incorrect syntax near", "you have an error in your sql",
    "syntax error converting", "[microsoft][odbc", "warning: mysql",
    "ora-01756", "jdbc", "sqlstate",
]


# ─── Finding model ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    url:         str
    param:       str
    vuln_type:   str   # sqli | xss
    severity:    str   # High | Medium | Low
    technique:   str   # error_based | time_based | boolean_based | playwright_confirmed
    description: str
    remediation: str
    owasp:       str   # A03:2021-Injection
    cwe:         str   # CWE-89 | CWE-79
    cvss_score:  str   # 9.8 | 6.1
    payload:     str   = ""
    evidence:    str   = ""
    endpoint_id: str   = ""
    log_id:      str   = ""
    playwright_confirmed: bool = False
    finding_id:  str   = field(default_factory=lambda: f"f_{uuid.uuid4().hex[:6]}")

    def to_dict(self) -> dict:
        return {
            "finding_id":           self.finding_id,
            "endpoint_id":          self.endpoint_id,
            "log_id":               self.log_id,
            "url":                  self.url,
            "param":                self.param,
            "vuln_type":            self.vuln_type,
            "severity":             self.severity,
            "technique":            self.technique,
            "description":          self.description,
            "remediation":          self.remediation,
            "owasp":                self.owasp,
            "cwe":                  self.cwe,
            "cvss_score":           self.cvss_score,
            "payload":              self.payload,
            "evidence":             self.evidence,
            "playwright_confirmed": self.playwright_confirmed,
        }


# ─── Entry point ──────────────────────────────────────────────────────────────

def analyze(session_dir: str | Path) -> list[Finding]:
    session_dir = Path(session_dir)
    logs        = _load_logs(session_dir)
    if not logs:
        return []

    vuln_logs = [l for l in logs if l.get("is_vulnerable")]
    log.info(f"[analyzer] {len(logs)} logs | {len(vuln_logs)} vulnerable")

    if not vuln_logs:
        log.info("[analyzer] Không có log vulnerable")
        return []

    # Playwright-confirmed XSS → HIGH ngay, không cần hỏi AI
    playwright_logs = [l for l in vuln_logs if l.get("playwright_confirmed")]
    other_logs      = [l for l in vuln_logs if not l.get("playwright_confirmed")]

    findings = []

    # Playwright confirmed → tự động HIGH, chắc chắn 100%
    for l in playwright_logs:
        findings.append(_make_playwright_finding(l))
        log.info(f"[analyzer] ✅ Playwright confirmed XSS: {l['url']}")

    # Các log còn lại → AI phân tích
    if other_logs:
        findings += _ai_analyze_batch(other_logs)

    # Cross-check để giảm false positive
    findings = [_cross_check(f, logs) for f in findings]
    findings = [f for f in findings if f is not None]

    _save(findings, session_dir)
    _print_summary(findings)
    return findings


# ─── Playwright confirmed finding ─────────────────────────────────────────────

def _make_playwright_finding(l: dict) -> Finding:
    """XSS được Playwright xác nhận → HIGH, không cần hỏi AI."""
    return Finding(
        url         = l.get("url", ""),
        param       = l.get("param", ""),
        vuln_type   = "xss",
        severity    = "High",
        technique   = "playwright_confirmed",
        description = (
            f"Reflected XSS được xác nhận bằng Playwright headless browser. "
            f"Payload '{l.get('payload','')}' đã trigger alert() thực sự trong browser, "
            f"chứng minh ứng dụng không encode output trước khi render HTML."
        ),
        remediation = (
            "Encode tất cả output trước khi render ra HTML:\n"
            "Python: import html; html.escape(user_input)\n"
            "Dùng Content-Security-Policy header để giảm thiểu impact.\n"
            "Không dùng innerHTML, dùng textContent thay thế."
        ),
        owasp       = "A03:2021-Injection",
        cwe         = "CWE-79",
        cvss_score  = "6.1",
        payload     = l.get("payload", ""),
        evidence    = f"Browser alert() triggered với payload: {l.get('payload','')}",
        endpoint_id = l.get("endpoint_id", ""),
        log_id      = l.get("log_id", ""),
        playwright_confirmed = True,
    )


# ─── AI Analysis ──────────────────────────────────────────────────────────────

def _ai_analyze_batch(logs: list[dict]) -> list[Finding]:
    findings = []
    for i in range(0, len(logs), BATCH_SIZE):
        findings += _ai_batch(logs[i:i + BATCH_SIZE])
    return findings


def _ai_batch(logs: list[dict]) -> list[Finding]:
    slim = [
        {
            "id":        l["log_id"],
            "ep_id":     l["endpoint_id"],
            "url":       l["url"],
            "param":     l["param"],
            "type":      l["vuln_type"],
            "technique": l.get("technique", ""),
            "payload":   l["payload"],
            "status":    l["response"]["status"],
            "snippet":   l["response"].get("body_snippet", "")[:400],
            "duration":  l.get("duration_ms", 0),
        }
        for l in logs
    ]

    prompt = f"""
{ANALYSIS_KNOWLEDGE}

Phân tích các log kiểm thử bảo mật sau dựa trên tài liệu trên:

{json.dumps(slim, ensure_ascii=False)}

Với mỗi log, xác định lỗ hổng và trả về JSON array:
[{{
  "id": "log_id",
  "ep_id": "endpoint_id",
  "url": "...",
  "param": "...",
  "type": "sqli|xss",
  "confirmed": true/false,
  "severity": "High|Medium|Low",
  "technique": "error_based|time_based|boolean_based|http_reflection",
  "desc": "mô tả ngắn tiếng Việt",
  "fix": "cách fix + code ví dụ",
  "owasp": "A03:2021-Injection",
  "cwe": "CWE-89|CWE-79",
  "cvss": "9.8|6.1",
  "evidence": "đoạn text trong snippet chứng minh"
}}]

Quy tắc:
- Chỉ confirmed=true khi có bằng chứng RÕ RÀNG trong snippet
- Không bịa evidence không có trong snippet
- Trả [] nếu không có finding thực sự
- Chỉ trả JSON array, không có text thừa
"""

    result = call_json(prompt)

    if not result or not isinstance(result, list):
        log.warning("[analyzer] AI thất bại → rule-based")
        return _rule_analyze(logs)

    findings = []
    for item in result:
        if not item.get("confirmed"):
            continue
        try:
            findings.append(Finding(
                url         = item.get("url", ""),
                param       = item.get("param", ""),
                vuln_type   = item.get("type", "unknown"),
                severity    = item.get("severity", "Medium"),
                technique   = item.get("technique", ""),
                description = item.get("desc", ""),
                remediation = item.get("fix", ""),
                owasp       = item.get("owasp", ""),
                cwe         = item.get("cwe", ""),
                cvss_score  = item.get("cvss", ""),
                payload     = item.get("payload", ""),
                evidence    = item.get("evidence", ""),
                endpoint_id = item.get("ep_id", ""),
                log_id      = item.get("id", ""),
            ))
        except Exception as e:
            log.debug(f"[analyzer] Parse lỗi: {e}")

    return findings


# ─── Cross-check (chống hallucination) ───────────────────────────────────────

def _cross_check(finding: Finding, all_logs: list[dict]) -> Finding | None:
    """
    Kiểm tra lại finding của AI bằng rule cứng.
    Nếu AI nói confirmed nhưng không có bằng chứng thực → hạ severity hoặc bỏ.
    """
    # Tìm log gốc
    orig = next((l for l in all_logs if l.get("log_id") == finding.log_id), None)
    if not orig:
        return finding

    snippet = orig["response"].get("body_snippet", "").lower()

    if finding.vuln_type == "sqli" and finding.severity == "High":
        # AI nói High SQLi → phải có SQL error signature trong snippet
        has_error = any(sig in snippet for sig in SQL_ERROR_SIGNATURES)
        if not has_error and orig.get("technique") != "time_based":
            log.warning(f"[cross-check] Hạ SQLi High→Medium (không có error): {finding.url}")
            finding.severity = "Medium"
            finding.description += " [Hạ xuống Medium: không tìm thấy SQL error rõ ràng trong response]"

    if finding.vuln_type == "xss" and finding.severity == "High":
        # AI nói High XSS → payload phải xuất hiện trong snippet
        payload_lower = finding.payload.lower()[:15]
        if payload_lower and payload_lower not in snippet:
            encoded = finding.payload.replace("<","&lt;").replace(">","&gt;")
            if encoded.lower() not in snippet:
                log.warning(f"[cross-check] Hạ XSS High→Medium (không reflect): {finding.url}")
                finding.severity = "Medium"
                finding.description += " [Hạ xuống Medium: payload không tìm thấy trong response]"

    return finding


# ─── Rule-based fallback ──────────────────────────────────────────────────────

_OWASP = {
    "sqli": ("A03:2021-Injection", "CWE-89", "9.8"),
    "xss":  ("A03:2021-Injection", "CWE-79", "6.1"),
}
_DESC = {
    "sqli": "SQL Injection: input người dùng được đưa trực tiếp vào câu SQL, cho phép kẻ tấn công can thiệp vào database.",
    "xss":  "Reflected XSS: input phản chiếu trong HTML không được encode, cho phép chèn mã JavaScript.",
}
_FIX = {
    "sqli": "Dùng Prepared Statements:\ncursor.execute('SELECT * FROM t WHERE id=%s', (id,))",
    "xss":  "Encode output:\nimport html; html.escape(user_input)\nDùng textContent thay innerHTML.",
}


def _rule_analyze(logs: list[dict]) -> list[Finding]:
    findings = []
    for l in logs:
        vt = l.get("vuln_type", "unknown")
        ow, cw, cvss = _OWASP.get(vt, ("", "", ""))
        findings.append(Finding(
            url=l.get("url",""), param=l.get("param",""),
            vuln_type=vt, severity="Medium",
            technique=l.get("technique",""),
            description=_DESC.get(vt,"Lỗ hổng bảo mật."),
            remediation=_FIX.get(vt,"Kiểm tra đầu vào."),
            owasp=ow, cwe=cw, cvss_score=cvss,
            payload=l.get("payload",""),
            evidence=l.get("response",{}).get("body_snippet","")[:200],
            endpoint_id=l.get("endpoint_id",""),
            log_id=l.get("log_id",""),
        ))
    return findings


# ─── I/O ──────────────────────────────────────────────────────────────────────

def _load_logs(session_dir: Path) -> list[dict]:
    path = session_dir / "logs.jsonl"
    if not path.exists():
        log.error(f"[analyzer] Không tìm thấy {path}")
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def _save(findings: list[Finding], session_dir: Path):
    path = session_dir / "findings.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump([fi.to_dict() for fi in findings], f, indent=2, ensure_ascii=False)
    log.info(f"[analyzer] Saved {len(findings)} findings → {path}")


def _print_summary(findings: list[Finding]):
    s  = Counter(f.severity for f in findings)
    pw = sum(1 for f in findings if f.playwright_confirmed)
    print(f"\n{'═'*55}")
    print(f"  FINDINGS — {len(findings)} total")
    print(f"  🔴 High={s.get('High',0)}  🟡 Medium={s.get('Medium',0)}  🟢 Low={s.get('Low',0)}")
    print(f"  ✅ Playwright confirmed XSS: {pw}")
    print(f"{'═'*55}")
    for f in findings:
        icon = {"High":"🔴","Medium":"🟡","Low":"🟢"}.get(f.severity,"⚪")
        pw_tag = " [Playwright ✅]" if f.playwright_confirmed else ""
        print(f"\n  {icon} [{f.severity}] {f.vuln_type.upper()}{pw_tag} — {f.url}")
        print(f"     param={f.param} | {f.technique}")
        print(f"     {f.owasp} | {f.cwe} | CVSS={f.cvss_score}")
        print(f"     {f.description[:80]}...")
    print()