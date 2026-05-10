# =============================================================================
# llm/router.py — Tự động chọn LLM backend
#
# Thứ tự ưu tiên:
#   1. Ollama local (nếu USE_OLLAMA=True và server đang chạy)
#   2. Gemini API   (nếu có GEMINI_API_KEY)
#   3. None         → fallback rule-based trong từng module
# =============================================================================

import logging
import config

from llm.ollama_client import call_ollama_json, is_alive as ollama_alive
from llm.gemini_client import call_gemini_json

log = logging.getLogger(__name__)


def call_llm_json(prompt: str) -> list | dict | None:
    """
    Gọi LLM và trả về JSON.
    Tự động chọn backend dựa theo config.
    """
    # Thử Ollama trước nếu được cấu hình
    if config.USE_OLLAMA:
        if ollama_alive():
            log.info("[llm] Dùng Ollama local")
            return call_ollama_json(prompt, model=config.OLLAMA_MODEL)
        else:
            log.warning("[llm] Ollama chưa chạy! Chạy: ollama serve")

    # Fallback Gemini
    if config.GEMINI_API_KEY:
        log.info("[llm] Dùng Gemini API")
        return call_gemini_json(prompt, config.GEMINI_API_KEY, config.GEMINI_MODEL)

    log.warning("[llm] Không có LLM nào khả dụng → rule-based fallback")
    return None