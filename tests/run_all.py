# =============================================================================
# tests/run_all.py — Chạy toàn bộ pipeline một lệnh
# Usage: python tests/run_all.py
# =============================================================================

import sys
import json
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
logging.basicConfig(level=logging.INFO, format="%(message)s")

import config
from llm.ollama_client       import is_alive
from crawler.crawler         import crawl, load_endpoints
from fuzzer.payload_planner  import generate_plan
from fuzzer.fuzzer           import fuzz
from analyzer.log_analyzer   import analyze

SESSION = Path("sessions") / config.SESSION_ID
SESSION.mkdir(parents=True, exist_ok=True)

# Kiểm tra Ollama trước khi chạy
if not is_alive():
    print("❌ Ollama chưa chạy! Mở terminal khác và chạy: ollama serve")
    sys.exit(1)
print(f"✅ Ollama OK — model: {config.OLLAMA_MODEL}\n")


# ── BƯỚC 1: CRAWL ─────────────────────────────────────────────────────────────
print("═"*50)
print("  BƯỚC 1 — CRAWL")
print("═"*50)

endpoints = crawl(SESSION)

print(f"  {len(endpoints)} endpoints cần fuzz:")
for ep in endpoints:
    icon = {"high":"🔴","medium":"🟡","low":"🟢"}.get(ep.risk_level,"⚪")
    print(f"  {icon} {ep.method:4} {ep.url} | {ep.params}")


# ── BƯỚC 2: PAYLOAD PLAN ──────────────────────────────────────────────────────
print("\n" + "═"*50)
print("  BƯỚC 2 — SINH PAYLOAD PLAN")
print("═"*50)

plan = generate_plan(endpoints)
for ep_id, items in plan.items():
    print(f"  [{ep_id}]")
    for item in items:
        print(f"    {item['param']} → {item['vuln_type']} ({len(item['payloads'])} payloads)")


# ── BƯỚC 3: FUZZ ──────────────────────────────────────────────────────────────
print("\n" + "═"*50)
print("  BƯỚC 3 — FUZZ")
print("═"*50 + "\n")

logs = fuzz(endpoints, plan)

logs_path = SESSION / "logs.jsonl"
with open(logs_path, "w", encoding="utf-8") as f:
    for l in logs:
        f.write(json.dumps(l.to_dict(), ensure_ascii=False) + "\n")
print(f"\n  Saved {len(logs)} logs → {logs_path}")


# ── BƯỚC 4: PHÂN TÍCH ─────────────────────────────────────────────────────────
print("\n" + "═"*50)
print("  BƯỚC 4 — PHÂN TÍCH (AI)")
print("═"*50)

findings = analyze(SESSION)

print(f"\n{'═'*50}")
print(f"  ✅ HOÀN THÀNH")
print(f"  📁 Session: {SESSION}")
print(f"  📋 Endpoints : {len(endpoints)}")
print(f"  📋 Requests  : {len(logs)}")
print(f"  📋 Findings  : {len(findings)}")
print(f"{'═'*50}\n")