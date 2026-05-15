# =============================================================================
# llm/ollama_client.py — Giao tiếp với Ollama local
#
# Có 2 trạng thái:
#   - ONLINE : Ollama chạy → gọi API bình thường
#   - OFFLINE: Ollama lỗi/timeout → trả về None → caller tự dùng fallback
#
# Không throw exception ra ngoài — mọi lỗi đều được bắt trong file này.
# =============================================================================

import json
import re
import logging
import requests

import config

log = logging.getLogger(__name__)

CHAT_URL = f"{config.OLLAMA_HOST}/api/chat"
TAGS_URL = f"{config.OLLAMA_HOST}/api/tags"
TIMEOUT  = 300   # 5 phút — model 14B cần thời gian


# =============================================================================
# Kiểm tra kết nối
# =============================================================================

def is_alive() -> bool:
    """Kiểm tra Ollama server có đang chạy không."""
    try:
        r = requests.get(TAGS_URL, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# =============================================================================
# Gọi API — trả về None nếu lỗi (caller tự xử lý fallback)
# =============================================================================

def call(prompt: str) -> str | None:
    """
    Gửi prompt → nhận text response.

    Returns:
        str   nếu thành công
        None  nếu Ollama không chạy hoặc lỗi → caller dùng payload cứng
    """
    if not is_alive():
        log.warning("[ollama] Server không khả dụng → fallback payload cứng")
        return None

    try:
        resp = requests.post(CHAT_URL, json={
            "model":    config.OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream":   False,
        }, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    except requests.Timeout:
        log.warning("[ollama] Timeout → fallback payload cứng")
        return None
    except requests.ConnectionError:
        log.warning("[ollama] Mất kết nối → fallback payload cứng")
        return None
    except Exception as e:
        log.warning(f"[ollama] Lỗi không xác định: {e} → fallback payload cứng")
        return None


def call_json(prompt: str) -> list | dict | None:
    """
    Gửi prompt → parse JSON từ response.

    Returns:
        list | dict  nếu thành công
        None         nếu Ollama lỗi hoặc response không parse được
    """
    raw = call(prompt)
    if raw is None:
        return None   # Ollama lỗi → caller fallback

    # Bỏ ```json ... ``` nếu model bọc output
    clean = re.sub(r"```json|```", "", raw).strip()

    # Tìm JSON array [...] hoặc object {...}
    match = re.search(r"(\[.*\]|\{.*\})", clean, re.DOTALL)
    if not match:
        log.warning(f"[ollama] Không tìm thấy JSON trong response:\n{raw[:200]}")
        return None

    try:
        return json.loads(match.group())
    except json.JSONDecodeError as e:
        log.warning(f"[ollama] JSON parse lỗi: {e}")
        return None