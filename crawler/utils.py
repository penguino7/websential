# =============================================================================
# crawler/utils.py — Hàm tiện ích dùng chung
# =============================================================================

import re
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
}


def normalize_url(url: str, base: str = "") -> str:
    """Chuyển URL tương đối → tuyệt đối, bỏ fragment #."""
    full = urljoin(base, url)
    p    = urlparse(full)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))


def in_scope(url: str, scope: str) -> bool:
    """Kiểm tra URL có trong domain scope không."""
    try:
        return re.search(scope, urlparse(url).netloc) is not None
    except Exception:
        return False


def is_static(url: str) -> bool:
    """Nhận biết file tĩnh — bỏ qua khi crawl."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def extract_params(url: str) -> tuple[str, dict[str, str]]:
    """
    Tách query params từ URL, đoán kiểu dữ liệu.
    Trả về (clean_url, {param_name: type}).
    """
    p           = urlparse(url)
    qs          = parse_qs(p.query, keep_blank_values=True)
    param_types = {k: guess_type(v[0] if v else "") for k, v in qs.items()}
    clean       = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    return clean, param_types


def guess_type(value: str) -> str:
    """Đoán kiểu dữ liệu từ giá trị mẫu."""
    if re.fullmatch(r"\d+", value):                   return "integer"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):    return "date"
    if re.fullmatch(r"[a-fA-F0-9\-]{32,36}", value): return "uuid"
    if value.lower() in ("true", "false"):            return "boolean"
    return "string"


def dedup_key(url: str, method: str, params: list[str]) -> tuple:
    """Tạo chữ ký duy nhất cho endpoint — dùng để loại trùng lặp."""
    p     = urlparse(url)
    clean = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    return (clean, method.upper(), frozenset(params))