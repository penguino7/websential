# =============================================================================
# tests/run_all.py — Chạy toàn bộ pipeline
# Usage: python tests/run_all.py
# =============================================================================

import sys
import json
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
logging.basicConfig(level=logging.INFO, format="%(message)s")

import config
from llm.ollama_client      import is_alive
from crawler.crawler        import crawl
from fuzzer.payload_planner import generate_plan
from fuzzer.sqli_fuzzer     import fuzz_sqli
from fuzzer.xss_fuzzer      import fuzz_xss
from analyzer.log_analyzer  import analyze

SESSION = Path("sessions") / config.SESSION_ID
SESSION.mkdir(parents=True, exist_ok=True)

# Kiểm tra Ollama
if not is_alive():
    print("❌ Ollama chưa chạy! Chạy: ollama serve")
    sys.exit(1)
print(f"✅ Ollama OK — model: {config.OLLAMA_MODEL}\n")


# ── BƯỚC 1: CRAWL ─────────────────────────────────────────────────────────────
print("═"*55)
print("  BƯỚC 1 — CRAWL")
print("═"*55)

endpoints = crawl(SESSION)
print(f"\n  {len(endpoints)} endpoints:")
for ep in endpoints:
    icon = {"high":"🔴","medium":"🟡","low":"🟢"}.get(ep.risk_level,"⚪")
    print(f"  {icon} {ep.method:4} {ep.url} | {ep.params} | vulns={ep.likely_vulns}")


# ── BƯỚC 2: PAYLOAD PLAN ──────────────────────────────────────────────────────
print("\n" + "═"*55)
print("  BƯỚC 2 — AI SINH PAYLOAD (RAG: OWASP + CWE)")
print("═"*55)

ai_payloads = generate_plan(endpoints)
for ep_id, payloads in ai_payloads.items():
    print(f"  [{ep_id}] AI sinh {len(payloads)} payloads bổ sung")


# ── BƯỚC 3: FUZZ SQLi ─────────────────────────────────────────────────────────
print("\n" + "═"*55)
print("  BƯỚC 3 — FUZZ SQL INJECTION")
print("  Kỹ thuật: error-based, time-based, boolean-based")
print("═"*55 + "\n")

sqli_logs = fuzz_sqli(endpoints, ai_payloads)


# ── BƯỚC 4: FUZZ XSS ──────────────────────────────────────────────────────────
print("\n" + "═"*55)
print("  BƯỚC 4 — FUZZ XSS")
print("  Kỹ thuật: probe reflection → HTTP fuzz → Playwright alert()")
print("═"*55 + "\n")

xss_logs = fuzz_xss(endpoints, ai_payloads)


# ── Lưu tất cả logs ───────────────────────────────────────────────────────────
all_logs  = sqli_logs + xss_logs
logs_path = SESSION / "logs.jsonl"
with open(logs_path, "w", encoding="utf-8") as f:
    for l in all_logs:
        f.write(json.dumps(l.to_dict(), ensure_ascii=False) + "\n")

sqli_vuln = sum(1 for l in sqli_logs if l.is_vulnerable)
xss_vuln  = sum(1 for l in xss_logs  if l.is_vulnerable)
xss_conf  = sum(1 for l in xss_logs  if getattr(l, "playwright_confirmed", False))

print(f"\n  SQLi: {len(sqli_logs)} requests | {sqli_vuln} vulnerable")
print(f"  XSS:  {len(xss_logs)} requests  | {xss_vuln} suspect | {xss_conf} confirmed by Playwright")
print(f"  Saved {len(all_logs)} logs → {logs_path}")


# ── BƯỚC 5: PHÂN TÍCH AI ──────────────────────────────────────────────────────
print("\n" + "═"*55)
print("  BƯỚC 5 — AI PHÂN TÍCH (RAG + Cross-check)")
print("═"*55)

findings = analyze(SESSION)

print(f"\n{'═'*55}")
print(f"  ✅ HOÀN THÀNH — Session: {SESSION}")
print(f"  📋 Endpoints : {len(endpoints)}")
print(f"  📋 Requests  : {len(all_logs)} (SQLi={len(sqli_logs)}, XSS={len(xss_logs)})")
print(f"  📋 Findings  : {len(findings)}")
print(f"{'═'*55}\n")