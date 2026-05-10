# =============================================================================
# config.py — Cấu hình toàn bộ dự án
# Chỉnh sửa file này trước khi chạy
# =============================================================================

# ── LLM Backend ───────────────────────────────────────────────────────────────
# Chọn 1 trong 2: Gemini hoặc Ollama

# Option 1: Gemini API (cần internet, có rate limit)
GEMINI_API_KEY = ""           # để trống nếu dùng Ollama
GEMINI_MODEL   = "gemini-2.5-pro"

# Option 2: Ollama local (không cần internet, không rate limit)
USE_OLLAMA     = True         # True = dùng Ollama, False = dùng Gemini
OLLAMA_MODEL   = "qwen2.5-coder:14b"    # model đã pull về
OLLAMA_URL     = "http://192.168.62.107:11434/api/chat"

# ── Crawler ───────────────────────────────────────────────────────────────────
MAX_DEPTH        = 2     # Độ sâu crawl (2 = đủ cho hầu hết web)
MAX_ENDPOINTS    = 100   # Giới hạn số endpoint tránh spam
CRAWL_DELAY      = 0.3   # Giây chờ giữa mỗi request (tránh bị block)
USE_JS_CRAWLER   = False # Bật nếu target là SPA (React/Vue) — cần Playwright

# ── Fuzzer ────────────────────────────────────────────────────────────────────
MAX_REQ_PER_EP   = 20    # Số request tối đa mỗi endpoint
FUZZ_DELAY       = 0.5   # Giây chờ giữa mỗi request fuzz
REQUEST_TIMEOUT  = 8     # Timeout cho mỗi request (giây)

# ── Target ────────────────────────────────────────────────────────────────────
TARGET_URL = "http://testasp.vulnweb.com"
SCOPE      = "testasp.vulnweb.com"
SESSION_ID = "testasp_01"