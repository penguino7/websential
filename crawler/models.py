# =============================================================================
# crawler/models.py — Định nghĩa cấu trúc dữ liệu Endpoint
# =============================================================================

from dataclasses import dataclass, field
from datetime    import datetime
from typing      import Optional
import uuid


@dataclass
class Endpoint:
    """
    Đại diện cho một endpoint web được phát hiện trong quá trình crawl.
    """
    url:              str
    method:           str
    params:           list[str]
    param_types:      dict[str, str]
    source:           str
    requires_auth:    bool          = False
    content_type:     str           = "text/html"
    post_body_sample: Optional[str] = None
    response_sample:  dict          = field(default_factory=dict)
    risk_level:       str           = "unknown"
    likely_vulns:     list[str]     = field(default_factory=list)
    risk_reason:      str           = ""
    id:               str           = field(default_factory=lambda: f"ep_{uuid.uuid4().hex[:6]}")
    discovered_at:    str           = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id, "url": self.url, "method": self.method,
            "params": self.params, "param_types": self.param_types,
            "source": self.source, "requires_auth": self.requires_auth,
            "content_type": self.content_type,
            "post_body_sample": self.post_body_sample,
            "response_sample": self.response_sample,
            "risk_level": self.risk_level, "likely_vulns": self.likely_vulns,
            "risk_reason": self.risk_reason, "discovered_at": self.discovered_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "Endpoint":
        ep = Endpoint(
            url=d["url"], method=d["method"],
            params=d.get("params", []),
            param_types=d.get("param_types", {}),
            source=d.get("source", "unknown"),
            requires_auth=d.get("requires_auth", False),
            content_type=d.get("content_type", "text/html"),
            post_body_sample=d.get("post_body_sample"),
            response_sample=d.get("response_sample", {}),
            risk_level=d.get("risk_level", "unknown"),
            likely_vulns=d.get("likely_vulns", []),
            risk_reason=d.get("risk_reason", ""),
        )
        ep.id            = d.get("id", ep.id)
        ep.discovered_at = d.get("discovered_at", ep.discovered_at)
        return ep