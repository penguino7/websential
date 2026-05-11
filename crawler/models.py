# =============================================================================
# crawler/models.py — Cấu trúc dữ liệu Endpoint
#
# Endpoint là đơn vị dữ liệu trung tâm của toàn hệ thống.
# Tất cả module đều dùng chung class này.
# =============================================================================

from dataclasses import dataclass, field
from datetime    import datetime
from typing      import Optional
import uuid


@dataclass
class Endpoint:
    url:           str
    method:        str            # GET | POST
    params:        list[str]      # ["id", "q", ...]
    param_types:   dict[str, str] # {"id": "integer", "q": "string"}
    source:        str            # "static" | "js_intercept" | "both"

    # Được điền bởi classifier
    risk_level:    str       = "unknown"  # high | medium | low | skip
    likely_vulns:  list[str] = field(default_factory=list)  # ["sqli", "xss"]
    risk_reason:   str       = ""

    # Metadata
    requires_auth:    bool          = False
    content_type:     str           = "text/html"
    post_body_sample: Optional[str] = None
    response_sample:  dict          = field(default_factory=dict)
    id:               str           = field(default_factory=lambda: f"ep_{uuid.uuid4().hex[:6]}")
    discovered_at:    str           = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id, "url": self.url, "method": self.method,
            "params": self.params, "param_types": self.param_types,
            "source": self.source, "risk_level": self.risk_level,
            "likely_vulns": self.likely_vulns, "risk_reason": self.risk_reason,
            "requires_auth": self.requires_auth, "content_type": self.content_type,
            "post_body_sample": self.post_body_sample,
            "response_sample": self.response_sample,
            "discovered_at": self.discovered_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "Endpoint":
        ep = Endpoint(
            url=d["url"], method=d["method"],
            params=d.get("params", []),
            param_types=d.get("param_types", {}),
            source=d.get("source", "unknown"),
            risk_level=d.get("risk_level", "unknown"),
            likely_vulns=d.get("likely_vulns", []),
            risk_reason=d.get("risk_reason", ""),
            requires_auth=d.get("requires_auth", False),
            content_type=d.get("content_type", "text/html"),
            post_body_sample=d.get("post_body_sample"),
            response_sample=d.get("response_sample", {}),
        )
        ep.id           = d.get("id", ep.id)
        ep.discovered_at= d.get("discovered_at", ep.discovered_at)
        return ep