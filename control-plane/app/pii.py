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

    text = sub("JWT", JWT_RE, text)
    text = sub("BEARER", BEARER_RE, text, repl=lambda m: f"{m.group(1)} [REDACTED:TOKEN]")
    text = sub("APIKEY", APIKEY_RE, text)
    text = sub("SECRET", KV_RE, text, check=lambda s: "[REDACTED" not in s, repl=_kv_repl)
    text = sub("EMAIL", EMAIL_RE, text)
    text = sub("CARD", CARD_RE, text, check=lambda s: 13 <= len(re.sub(r"\D", "", s)) <= 19 and luhn_ok(re.sub(r"\D", "", s)))
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
