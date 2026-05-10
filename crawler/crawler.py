# =============================================================================
# crawler/crawler.py — Entry point của toàn bộ quá trình crawl
#
# Pipeline:
#   static_crawl() → [js_crawl()] → merge → classify → lưu file
#
# Đây là file duy nhất bên ngoài cần gọi khi muốn crawl.
# =============================================================================

import json
import logging
from collections import Counter
from pathlib     import Path

from crawler.static_crawler import static_crawl
from crawler.classifier     import classify
from crawler.models         import Endpoint
from crawler.utils          import dedup_key, is_static_asset

log = logging.getLogger(__name__)


def crawl(
    target_url:   str,
    scope:        str,
    session_dir:  str | Path,
    max_depth:    int  = 2,
    use_js:       bool = False,
    api_key:      str  = "",
    max_endpoints:int  = 100,
    headers:      dict = None,
) -> list[Endpoint]:
    """
    Chạy toàn bộ pipeline crawl.

    Args:
        target_url:    URL mục tiêu
        scope:         Domain giới hạn (vd: 'target.com')
        session_dir:   Thư mục lưu kết quả
        max_depth:     Độ sâu crawl
        use_js:        Bật Playwright để crawl SPA
        api_key:       Gemini API key để classify
        max_endpoints: Giới hạn số endpoint tối đa
        headers:       Header bổ sung (cookie auth...)

    Returns:
        Danh sách Endpoint đã được phân loại rủi ro
    """
    session_dir = Path(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    # ── Bước 1: Static crawl ──────────────────────────────────────────────────
    log.info(f"[crawler] Bắt đầu STATIC crawl → {target_url}")
    all_eps = static_crawl(target_url, scope, max_depth, headers=headers)
    log.info(f"[crawler] Static tìm được: {len(all_eps)} endpoints")

    # ── Bước 2: JS crawl (tuỳ chọn) ──────────────────────────────────────────
    if use_js:
        from crawler.js_crawler import js_crawl
        log.info("[crawler] Bắt đầu JS crawl (Playwright)...")
        js_eps  = js_crawl(target_url, scope, headers=headers)
        all_eps = _merge(all_eps, js_eps)
        log.info(f"[crawler] Sau merge: {len(all_eps)} endpoints")

    # ── Bước 3: Phân loại rủi ro ──────────────────────────────────────────────
    log.info("[crawler] Phân loại rủi ro...")
    all_eps = classify(all_eps, api_key=api_key, use_ai=bool(api_key))

    # ── Bước 4: Lọc và sắp xếp ───────────────────────────────────────────────
    # Bỏ endpoint "skip" (file tĩnh, không có param)
    all_eps = [ep for ep in all_eps if ep.risk_level != "skip"]
    # Sắp xếp: high → medium → low → unknown
    all_eps = _sort_by_risk(all_eps)
    # Giới hạn số lượng
    if len(all_eps) > max_endpoints:
        log.warning(f"[crawler] Giới hạn {len(all_eps)} → {max_endpoints}")
        all_eps = all_eps[:max_endpoints]

    # ── Bước 5: Lưu kết quả ───────────────────────────────────────────────────
    out_path = session_dir / "endpoints.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump([ep.to_dict() for ep in all_eps], f, indent=2, ensure_ascii=False)
    log.info(f"[crawler] Đã lưu → {out_path}")

    _print_summary(all_eps)
    return all_eps


def load_endpoints(session_dir: str | Path) -> list[Endpoint]:
    """Load lại endpoints từ session đã lưu (không cần crawl lại)."""
    path = Path(session_dir) / "endpoints.json"
    with open(path, encoding="utf-8") as f:
        return [Endpoint.from_dict(d) for d in json.load(f)]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _merge(static_eps: list[Endpoint], js_eps: list[Endpoint]) -> list[Endpoint]:
    """Gộp 2 danh sách, loại trùng lặp theo (url, method, params)."""
    merged = {}
    for ep in static_eps:
        merged[dedup_key(ep.url, ep.method, ep.params)] = ep
    for ep in js_eps:
        k = dedup_key(ep.url, ep.method, ep.params)
        if k in merged:
            merged[k].source = "both"
        else:
            merged[k] = ep
    return list(merged.values())


def _sort_by_risk(eps: list[Endpoint]) -> list[Endpoint]:
    order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    return sorted(eps, key=lambda e: order.get(e.risk_level, 3))


def _print_summary(eps: list[Endpoint]):
    risk = Counter(ep.risk_level for ep in eps)
    print("\n" + "═" * 55)
    print(f"  CRAWL XONG — {len(eps)} endpoints")
    print(f"  🔴 High: {risk.get('high',0)}  🟡 Medium: {risk.get('medium',0)}  🟢 Low: {risk.get('low',0)}")
    print("═" * 55 + "\n")