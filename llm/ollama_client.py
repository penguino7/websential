# =============================================================================
# llm/ollama_client.py — Giao tiếp với Ollama local
# Không cần API key, không rate limit, chạy hoàn toàn offline
# =============================================================================

import json
import re
import logging
import requests

log = logging.getLogger(__name__)

OLLAMA_URL = "http://192.168.62.107:11434/api/generate"


def is_alive() -> bool:
    """Kiểm tra Ollama server có đang chạy không."""
    try:
        r = requests.get("http://192.168.62.107:11434/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def call_ollama(prompt: str, model: str = "mistral") -> str:
    """
    Gửi prompt tới Ollama, trả về text response.
    Lưu ý: Ollama chậm hơn Gemini, timeout 120s.
    """
    try:
        resp = requests.post(OLLAMA_URL, json={
            "model":  model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "")
    except Exception as e:
        log.error(f"[ollama] Lỗi: {e}")
        return ""


def call_ollama_json(prompt: str, model: str = "mistral") -> list | dict | None:
    """Gọi Ollama và parse JSON từ response."""
    raw = call_ollama(prompt, model)
    if not raw:
        return None

    # Bỏ markdown wrapper nếu có
    clean = re.sub(r"```json|```", "", raw).strip()

    # Tìm JSON array hoặc object
    match = re.search(r"(\[.*\]|\{.*\})", clean, re.DOTALL)
    if not match:
        log.warning(f"[ollama] Không tìm thấy JSON:\n{raw[:200]}")
        return None
    try:
        return json.loads(match.group())
    except json.JSONDecodeError as e:
        log.warning(f"[ollama] JSON parse lỗi: {e}")
        return None