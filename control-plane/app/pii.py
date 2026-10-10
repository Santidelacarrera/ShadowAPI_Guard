"""PII / secret redaction applied before anything is persisted."""
import re
from collections import Counter
from typing import Any

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
APIKEY_RE = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b")
# key=value / "key": "value" for secret-looking keys
SECRET_KEYS = r"password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|access[_-]?token|refresh[_-]?token|cvv|cvc"
KV_RE = re.compile(
    rf"""(?ix)
    (?P<k>["']?(?:{SECRET_KEYS})["']?\s*[:=]\s*)
    (?P<v>"[^"]*"|'[^']*'|[^\s&,;}}]+)
    """
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CARD_RE = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")
RUT_RE = re.compile(r"(?<![\w.-])\d{1,2}\.?\d{3}\.?\d{3}-[\dkK](?![\w-])")

_KV_CUES = ("password", "passwd", "pwd", "secret", "token", "api_key", "api-key", "apikey", "authorization", "cvv", "cvc")
_DIGITS8 = re.compile(r"\d[^\d]{0,3}\d[^\d]{0,3}\d[^\d]{0,3}\d[^\d]{0,3}\d[^\d]{0,3}\d[^\d]{0,3}\d")  # >= 7 digits
_SENSITIVE_KEY_RE = re.compile(rf"(?i)(?:{SECRET_KEYS})")  # substring: db_password, x-api-key ...


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def rut_ok(rut: str) -> bool:
    """Validate a Chilean RUT check digit (modulo 11)."""
    body, dv = re.sub(r"[.\s]", "", rut).upper().split("-")
    s, mul = 0, 2
    for ch in reversed(body):
        s += int(ch) * mul
        mul = 2 if mul == 7 else mul + 1
    r = 11 - s % 11
    expected = "0" if r == 11 else "K" if r == 10 else str(r)
    return dv == expected


def _kv_repl(m: re.Match) -> str:
    q = m.group("v")[0] if m.group("v")[0] in "\"'" else ""  # keep JSON valid
    return f"{m.group('k')}{q}[REDACTED:SECRET]{q}"


def _redact_cards(text: str, counts: Counter) -> str:
    """Mask Luhn-valid 13-19 digit numbers, also when glued to neighbouring digits ("4111... 0")."""
    def f(m: re.Match) -> str:
        chunk = m.group(0)
        pos = [i for i, ch in enumerate(chunk) if ch.isdigit()]
        digits = "".join(chunk[i] for i in pos)
        out, i, last = [], 0, 0
        while i < len(digits):
            for ln in range(min(19, len(digits) - i), 12, -1):
                if luhn_ok(digits[i:i + ln]):
                    out.append(chunk[last:pos[i]])
                    out.append("[REDACTED:CARD]")
                    last = pos[i + ln - 1] + 1
                    counts["CARD"] += 1
                    i += ln
                    break
            else:
                i += 1
        return "".join(out) + chunk[last:] if out else chunk

    return CARD_RE.sub(f, text)


def redact_text(text: str) -> tuple[str, Counter]:
    """Return (redacted_text, counts_by_kind)."""
    counts: Counter = Counter()

    def sub(kind: str, pattern: re.Pattern, s: str, check=None, repl=None) -> str:
        def f(m: re.Match) -> str:
            if check and not check(m.group(0)):
                return m.group(0)
            counts[kind] += 1
            return repl(m) if repl else f"[REDACTED:{kind}]"

        return pattern.sub(f, s)

    # cheap cue checks avoid running every regex over every body
    low = text.lower()
    if "eyj" in low:
        text = sub("JWT", JWT_RE, text)
    if "bearer" in low or "basic" in low:
        text = sub("BEARER", BEARER_RE, text, repl=lambda m: f"{m.group(1)} [REDACTED:TOKEN]")
    if "_live_" in low or "_test_" in low or "akia" in low or "gh" in low:
        text = sub("APIKEY", APIKEY_RE, text)
    if (":" in text or "=" in text) and any(k in low for k in _KV_CUES):
        text = sub("SECRET", KV_RE, text, check=lambda s: "[REDACTED" not in s, repl=_kv_repl)
    if "@" in text:
        text = sub("EMAIL", EMAIL_RE, text)
    if _DIGITS8.search(text):
        text = _redact_cards(text, counts)
        if "-" in text:
            text = sub("RUT", RUT_RE, text, check=rut_ok)
    return text, counts


def redact_json(obj: Any, counts: Counter | None = None) -> tuple[Any, Counter]:
    """Recursively redact a decoded JSON structure; secret-named keys are dropped wholesale."""
    counts = counts if counts is not None else Counter()
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _SENSITIVE_KEY_RE.search(str(k)) and v not in (None, ""):
                counts["SECRET"] += 1
                out[k] = "[REDACTED:SECRET]"
            else:
                out[k] = redact_json(v, counts)[0]
        return out, counts
    if isinstance(obj, list):
        return [redact_json(v, counts)[0] for v in obj], counts
    if isinstance(obj, str):
        s, c = redact_text(obj)
        counts.update(c)
        return s, counts
    return obj, counts


def redact_body(body: str) -> tuple[str, Counter]:
    """Redact an HTTP body; JSON bodies are handled structurally."""
    import json

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return redact_text(body or "")
    if isinstance(data, (dict, list)):
        red, counts = redact_json(data)
        return json.dumps(red, ensure_ascii=False), counts
    return redact_text(body)


def scan(text: str) -> Counter:
    return redact_text(text)[1]
