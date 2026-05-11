# =============================================================================
# llm/ollama_client.py — Giao tiếp với Ollama local
#
# Ollama expose API tại localhost:11434
# Dùng endpoint /api/chat (chuẩn mới)
# Không cần API key, không rate limit
# =============================================================================

import json
import re
import logging
import requests
import config

log = logging.getLogger(__name__)

CHAT_URL = f"{config.OLLAMA_HOST}/api/chat"
TAGS_URL = f"{config.OLLAMA_HOST}/api/tags"


def is_alive() -> bool:
    """Kiểm tra Ollama server có đang chạy không."""
    try:
        r = requests.get(TAGS_URL, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def call(prompt: str) -> str:
    """
    Gửi prompt → nhận text response từ Ollama.

    Args:
        prompt: Nội dung câu hỏi gửi cho AI

    Returns:
        Text response, hoặc "" nếu lỗi
    """
    if not is_alive():
        log.error("[ollama] Server chưa chạy! Chạy lệnh: ollama serve")
        return ""

    try:
        resp = requests.post(CHAT_URL, json={
            "model":   config.OLLAMA_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream":  False,
        }, timeout=120)
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    except Exception as e:
        log.error(f"[ollama] Lỗi gọi API: {e}")
        return ""


def call_json(prompt: str) -> list | dict | None:
    """
    Gửi prompt → nhận JSON response từ Ollama.
    Tự động bỏ markdown ```json``` nếu model trả về.

    Returns:
        list hoặc dict nếu parse thành công, None nếu thất bại
    """
    raw = call(prompt)
    if not raw:
        return None

    # Bỏ ```json ... ``` nếu model bọc output
    clean = re.sub(r"```json|```", "", raw).strip()

    # Tìm JSON array [...] hoặc object {...}
    match = re.search(r"(\[.*\]|\{.*\})", clean, re.DOTALL)
    if not match:
        log.warning(f"[ollama] Không tìm thấy JSON trong response:\n{raw[:300]}")
        return None

    try:
        return json.loads(match.group())
    except json.JSONDecodeError as e:
        log.warning(f"[ollama] JSON parse lỗi: {e}")
        return None