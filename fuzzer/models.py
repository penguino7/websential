# =============================================================================
# fuzzer/models.py — Cấu trúc dữ liệu kết quả fuzz
# =============================================================================

from dataclasses import dataclass, field
from datetime    import datetime
import uuid


@dataclass
class LogEntry:
    endpoint_id:   str
    url:           str
    param:         str
    vuln_type:     str   # sqli | xss | idor
    payload:       str
    request:       dict
    response:      dict
    baseline:      dict
    is_vulnerable: bool = False
    confidence:    str  = "none"  # high | medium | low | none
    duration_ms:   int  = 0
    log_id:        str  = field(default_factory=lambda: f"log_{uuid.uuid4().hex[:6]}")
    timestamp:     str  = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id, "endpoint_id": self.endpoint_id,
            "url": self.url, "param": self.param,
            "vuln_type": self.vuln_type, "payload": self.payload,
            "request": self.request, "response": self.response,
            "baseline": self.baseline, "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence, "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }