# =============================================================================
# crawler/crawler.py — Entry point crawl
#
# Pipeline: static_crawl → classify → filter → sort → lưu file
# =============================================================================

import json
import logging
from collections import Counter
from pathlib     import Path

from crawler.static_crawler import static_crawl
from crawler.classifier     import classify
from crawler.models         import Endpoint
from crawler.utils          import dedup_key
import config

log = logging.getLogger(__name__)


def crawl(session_dir: str | Path, use_ai: bool = True) -> list[Endpoint]:
    """
    Chạy toàn bộ pipeline crawl. Đọc config từ config.py.

    Returns:
        Danh sách Endpoint đã phân loại rủi ro
    """
    session_dir = Path(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    # Bước 1: Crawl HTML
    log.info(f"[crawler] Static crawl → {config.TARGET_URL}")
    endpoints = static_crawl(config.TARGET_URL, config.SCOPE, config.MAX_DEPTH, config.CRAWL_DELAY)
    log.info(f"[crawler] Tìm được {len(endpoints)} endpoints")

    # Bước 2: JS crawl (tuỳ chọn)
    if config.USE_JS:
        from crawler.js_crawler import js_crawl
        js_eps    = js_crawl(config.TARGET_URL, config.SCOPE)
        endpoints = _merge(endpoints, js_eps)

    # Bước 3: Phân loại rủi ro bằng AI (hoặc rule-based nếu use_ai=False)
    log.info(f"[crawler] Phân loại rủi ro {'(AI)' if use_ai else '(rule-based)'}...")
    endpoints = classify(endpoints, use_ai=use_ai)

    # Bước 4: Lọc + sắp xếp + giới hạn
    endpoints = [ep for ep in endpoints if ep.risk_level != "skip"]
    endpoints = sorted(endpoints, key=lambda e: {"high":0,"medium":1,"low":2}.get(e.risk_level, 3))
    if len(endpoints) > config.MAX_ENDPOINTS:
        endpoints = endpoints[:config.MAX_ENDPOINTS]

    # Bước 5: Lưu file
    out = session_dir / "endpoints.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump([ep.to_dict() for ep in endpoints], f, indent=2, ensure_ascii=False)

    _print_summary(endpoints)
    return endpoints


def load_endpoints(session_dir: str | Path) -> list[Endpoint]:
    """Load endpoints từ session đã lưu."""
    with open(Path(session_dir) / "endpoints.json", encoding="utf-8") as f:
        return [Endpoint.from_dict(d) for d in json.load(f)]


def _merge(static_eps, js_eps):
    merged = {dedup_key(ep.url, ep.method, ep.params): ep for ep in static_eps}
    for ep in js_eps:
        k = dedup_key(ep.url, ep.method, ep.params)
        if k in merged: merged[k].source = "both"
        else:           merged[k] = ep
    return list(merged.values())


def _print_summary(eps):
    r = Counter(ep.risk_level for ep in eps)
    print(f"\n{'═'*50}")
    print(f"  CRAWL XONG — {len(eps)} endpoints")
    print(f"  🔴 High={r.get('high',0)}  🟡 Medium={r.get('medium',0)}  🟢 Low={r.get('low',0)}")
    print(f"{'═'*50}\n")