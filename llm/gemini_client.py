# =============================================================================
# llm/gemini_client.py — Giao tiếp với Gemini API
#
# Chức năng:
#   - Gửi prompt → nhận text response
#   - Tự động parse JSON từ response
#   - Retry tối đa 3 lần khi bị rate limit (429)
# =============================================================================

import json
import re
import time
import logging
import requests

log = logging.getLogger(__name__)

# URL API của Gemini — đổi model tại đây nếu cần
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

MAX_RETRIES  = 3   # Số lần thử lại khi bị 429
RETRY_DELAY  = 15  # Giây chờ mỗi lần retry


def call_gemini(prompt: str, api_key: str, model: str = "gemini-2.5-flash") -> str:
    """
    Gửi prompt đến Gemini, trả về text response.
    Tự động retry nếu bị rate limit.

    Args:
        prompt:  Nội dung prompt gửi đi
        api_key: Gemini API key
        model:   Tên model (mặc định gemini-2.5-pro)

    Returns:
        Text response từ Gemini, hoặc "" nếu lỗi
    """
    url  = GEMINI_API_URL.format(model=model) + f"?key={api_key}"
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1},
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(url, json=body, timeout=30)

            # Rate limit → chờ rồi thử lại
            if resp.status_code == 429:
                wait = RETRY_DELAY * (attempt + 1)
                log.warning(f"[gemini] Rate limit → chờ {wait}s ({attempt+1}/{MAX_RETRIES})")
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

        except requests.HTTPError as e:
            log.error(f"[gemini] HTTP error: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
        except Exception as e:
            log.error(f"[gemini] Lỗi không xác định: {e}")
            break

    return ""


def call_gemini_json(prompt: str, api_key: str, model: str = "gemini-2.5-pro") -> list | dict | None:
    """
    Gửi prompt đến Gemini, parse kết quả thành JSON.
    Tự động bỏ markdown code block (```json ... ```) nếu có.

    Returns:
        list hoặc dict nếu parse thành công, None nếu thất bại
    """
    raw = call_gemini(prompt, api_key, model)
    if not raw:
        return None

    # Bỏ markdown wrapper nếu Gemini bọc JSON trong ```json ... ```
    clean = re.sub(r"```json|```", "", raw).strip()

    # Tìm JSON array [...] hoặc object {...} đầu tiên trong response
    match = re.search(r"(\[.*\]|\{.*\})", clean, re.DOTALL)
    if not match:
        log.warning(f"[gemini] Không tìm thấy JSON trong response:\n{raw[:300]}")
        return None

    try:
        return json.loads(match.group())
    except json.JSONDecodeError as e:
        log.warning(f"[gemini] JSON parse lỗi: {e}")
        return None