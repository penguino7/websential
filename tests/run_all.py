# =============================================================================
# tests/run_all.py — Chạy toàn bộ pipeline: Crawl → Fuzz → Analyze
#
# Usage: python tests/run_all.py
# =============================================================================

import sys
import json
import logging
from pathlib import Path

# Thêm thư mục gốc vào sys.path để import đúng
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(message)s")

import config
from crawler.crawler       import crawl, load_endpoints
from fuzzer.payload_planner import generate_plan
from fuzzer.fuzzer          import fuzz
from analyzer.log_analyzer  import analyze

# Thư mục lưu session
SESSION_DIR = Path("sessions") / config.SESSION_ID
SESSION_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════
# BƯỚC 1 — CRAWL
# ═══════════════════════════════════════════════════════════
print("\n" + "═" * 55)
print("  BƯỚC 1 — CRAWL")
print("═" * 55)

endpoints = crawl(
    target_url    = config.TARGET_URL,
    scope         = config.SCOPE,
    session_dir   = SESSION_DIR,
    max_depth     = config.MAX_DEPTH,
    use_js        = config.USE_JS_CRAWLER,
    api_key       = config.GEMINI_API_KEY,
    max_endpoints = config.MAX_ENDPOINTS,
)

print(f"\n  Tìm được {len(endpoints)} endpoints để fuzz:\n")
for ep in endpoints:
    icon = {"high":"🔴","medium":"🟡","low":"🟢"}.get(ep.risk_level,"⚪")
    print(f"  {icon} {ep.method:4} {ep.url} | params={ep.params}")


# ═══════════════════════════════════════════════════════════
# BƯỚC 2 — SINH PAYLOAD PLAN
# ═══════════════════════════════════════════════════════════
print("\n" + "═" * 55)
print("  BƯỚC 2 — SINH PAYLOAD PLAN")
print("═" * 55)

plan = generate_plan(endpoints, api_key=config.GEMINI_API_KEY)

print(f"\n  Plan cho {len(plan)} endpoints:\n")
for ep_id, items in plan.items():
    print(f"  [{ep_id}]")
    for item in items:
        print(f"    param={item['param']} | type={item['vuln_type']} | {len(item['payloads'])} payloads")


# ═══════════════════════════════════════════════════════════
# BƯỚC 3 — FUZZ
# ═══════════════════════════════════════════════════════════
print("\n" + "═" * 55)
print("  BƯỚC 3 — FUZZ")
print("═" * 55 + "\n")

logs = fuzz(
    endpoints    = endpoints,
    payload_plan = plan,
    timeout      = config.REQUEST_TIMEOUT,
    delay        = config.FUZZ_DELAY,
    max_per_ep   = config.MAX_REQ_PER_EP,
)

# Lưu logs.jsonl
logs_path = SESSION_DIR / "logs.jsonl"
with open(logs_path, "w", encoding="utf-8") as f:
    for l in logs:
        f.write(json.dumps(l.to_dict(), ensure_ascii=False) + "\n")
print(f"\n  Đã lưu {len(logs)} logs → {logs_path}")


# ═══════════════════════════════════════════════════════════
# BƯỚC 4 — PHÂN TÍCH LOG
# ═══════════════════════════════════════════════════════════
print("\n" + "═" * 55)
print("  BƯỚC 4 — PHÂN TÍCH LOG (AI)")
print("═" * 55)

findings = analyze(session_dir=SESSION_DIR, api_key=config.GEMINI_API_KEY)

print(f"\n  ✅ Hoàn thành! Kết quả lưu tại: {SESSION_DIR}/")
print(f"     endpoints.json → {len(endpoints)} endpoints")
print(f"     logs.jsonl     → {len(logs)} requests")
print(f"     findings.json  → {len(findings)} lỗ hổng\n")