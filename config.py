# =============================================================================
# config.py — Cấu hình toàn bộ dự án
# Chỉnh sửa file này trước khi chạy
# =============================================================================

# ── Ollama ────────────────────────────────────────────────────────────────────
OLLAMA_HOST  = "http://192.168.62.102:11434"   # đổi thành IP LAN nếu cần
OLLAMA_MODEL = "qwen2.5-coder:14b"       # model đã pull về

# ── Target ────────────────────────────────────────────────────────────────────
TARGET_URL = "https://juice-shop.herokuapp.com/#/"
SCOPE      = "juice-shop.herokuapp.com"
SESSION_ID = "testasp_01"

# ── Crawler ───────────────────────────────────────────────────────────────────
MAX_DEPTH     = 3    # độ sâu crawl
MAX_ENDPOINTS = 100    # giới hạn endpoint
CRAWL_DELAY   = 0.3    # giây chờ giữa request
USE_JS        = False  # bật nếu target là SPA React/Vue

# ── Fuzzer ────────────────────────────────────────────────────────────────────
MAX_REQ_PER_EP  = 20   # request tối đa mỗi endpoint
FUZZ_DELAY      = 0.5  # giây chờ giữa request
REQUEST_TIMEOUT = 8    # timeout mỗi request