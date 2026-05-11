# =============================================================================
# analyzer/log_analyzer.py — Phân tích log fuzz bằng AI → sinh Finding
#
# Pipeline: đọc logs.jsonl → lọc vulnerable → Ollama phân tích → lưu findings.json
# =============================================================================

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib     import Path
import uuid

from llm.ollama_client import call_json

log        = logging.getLogger(__name__)
BATCH_SIZE = 10


@dataclass
class Finding:
    url:         str
    param:       str
    vuln_type:   str   # sqli | xss | idor
    severity:    str   # High | Medium | Low
    description: str   # mô tả lỗ hổng tiếng Việt
    remediation: str   # hướng dẫn khắc phục + code ví dụ
    owasp:       str   # A03:2021-Injection
    cwe:         str   # CWE-89
    payload:     str   = ""
    evidence:    str   = ""
    endpoint_id: str   = ""
    log_id:      str   = ""
    finding_id:  str   = field(default_factory=lambda: f"f_{uuid.uuid4().hex[:6]}")

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "endpoint_id": self.endpoint_id,
            "log_id": self.log_id, "url": self.url, "param": self.param,
            "vuln_type": self.vuln_type, "severity": self.severity,
            "description": self.description, "remediation": self.remediation,
            "owasp": self.owasp, "cwe": self.cwe,
            "payload": self.payload, "evidence": self.evidence,
        }


def analyze(session_dir: str | Path) -> list[Finding]:
    """
    Đọc logs.jsonl → phân tích → trả về danh sách Finding.
    """
    session_dir = Path(session_dir)
    logs        = _load_logs(session_dir)
    if not logs: return []

    vuln_logs = [l for l in logs if l.get("is_vulnerable")]
    log.info(f"[analyzer] {len(logs)} logs | {len(vuln_logs)} vulnerable")

    if not vuln_logs:
        log.info("[analyzer] Không có log vulnerable")
        return []

    findings = _ai_analyze(vuln_logs)
    _save(findings, session_dir)
    _print_summary(findings)
    return findings


def _ai_analyze(logs: list[dict]) -> list[Finding]:
    findings = []
    for i in range(0, len(logs), BATCH_SIZE):
        findings += _ai_batch(logs[i:i + BATCH_SIZE])
    return findings


def _ai_batch(logs: list[dict]) -> list[Finding]:
    slim = [
        {
            "log_id":     l["log_id"],
            "endpoint_id":l["endpoint_id"],
            "url":        l["url"],
            "param":      l["param"],
            "vuln_type":  l["vuln_type"],
            "payload":    l["payload"],
            "status":     l["response"]["status"],
            "body":       l["response"].get("body_snippet", "")[:300],
            "baseline":   l.get("baseline", {}),
        }
        for l in logs
    ]

    prompt = f"""Bạn là chuyên gia pentest web. Phân tích log và xác nhận lỗ hổng bảo mật.

Log:
{json.dumps(slim, indent=2, ensure_ascii=False)}

Trả về JSON array, không có text thừa:
[{{"log_id":"...","endpoint_id":"...","url":"...","param":"...","vuln_type":"sqli|xss|idor",
"severity":"High|Medium|Low","description":"mô tả tiếng Việt","remediation":"hướng dẫn + code ví dụ",
"owasp":"A03:2021-Injection","cwe":"CWE-89","payload":"...","evidence":"..."}}]

Quy tắc:
- SQLi High: body có SQL error rõ ràng
- XSS High:  payload phản chiếu nguyên xi trong HTML
- IDOR Medium: response length khác baseline >20%
- Trả [] nếu không có finding thực sự"""

    result = call_json(prompt)

    if not result or not isinstance(result, list):
        log.warning("[analyzer] Ollama thất bại → rule-based")
        return _rule_analyze(logs)

    findings = []
    for item in result:
        try:
            findings.append(Finding(
                url=item.get("url",""), param=item.get("param",""),
                vuln_type=item.get("vuln_type","unknown"),
                severity=item.get("severity","Medium"),
                description=item.get("description",""),
                remediation=item.get("remediation",""),
                owasp=item.get("owasp",""), cwe=item.get("cwe",""),
                payload=item.get("payload",""), evidence=item.get("evidence",""),
                endpoint_id=item.get("endpoint_id",""), log_id=item.get("log_id",""),
            ))
        except Exception as e:
            log.debug(f"[analyzer] Parse lỗi: {e}")
    return findings


# Mapping fallback
_OWASP = {"sqli":("A03:2021-Injection","CWE-89"),"xss":("A03:2021-Injection","CWE-79"),"idor":("A01:2021-Broken Access Control","CWE-639")}
_DESC  = {"sqli":"SQL Injection: ứng dụng không lọc input, attacker can thiệp được vào câu SQL.","xss":"XSS: payload phản chiếu không encode, attacker chèn được JS độc hại.","idor":"IDOR: không kiểm tra quyền truy cập tài nguyên theo ID."}
_REMED = {"sqli":"Dùng Prepared Statements:\ncursor.execute('SELECT * FROM t WHERE id=%s',(id,))","xss":"Encode output:\nimport html; html.escape(user_input)","idor":"Kiểm tra quyền:\nif resource.owner != session.user: return 403"}


def _rule_analyze(logs: list[dict]) -> list[Finding]:
    findings = []
    for l in logs:
        vt        = l.get("vuln_type","unknown")
        ow, cw    = _OWASP.get(vt,("",""))
        findings.append(Finding(
            url=l.get("url",""), param=l.get("param",""), vuln_type=vt,
            severity="Medium", description=_DESC.get(vt,"Lỗ hổng bảo mật."),
            remediation=_REMED.get(vt,"Kiểm tra đầu vào."),
            owasp=ow, cwe=cw, payload=l.get("payload",""),
            evidence=l.get("response",{}).get("body_snippet","")[:200],
            endpoint_id=l.get("endpoint_id",""), log_id=l.get("log_id",""),
        ))
    return findings


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
    s = Counter(f.severity for f in findings)
    print(f"\n{'═'*50}")
    print(f"  FINDINGS — {len(findings)} total")
    print(f"  🔴 High={s.get('High',0)}  🟡 Medium={s.get('Medium',0)}  🟢 Low={s.get('Low',0)}")
    print(f"{'═'*50}")
    for f in findings:
        icon = {"High":"🔴","Medium":"🟡","Low":"🟢"}.get(f.severity,"⚪")
        print(f"\n  {icon} [{f.severity}] {f.vuln_type.upper()} — {f.url}")
        print(f"     param={f.param} | payload={f.payload}")
        print(f"     {f.owasp} | {f.cwe}")
    print()