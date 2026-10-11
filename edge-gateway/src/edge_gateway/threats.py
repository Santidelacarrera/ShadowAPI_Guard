"""Lightweight WAF + prompt-injection detector.

Every string (and every object key) of a parsed JSON payload is canonicalised and matched against
a rule set.  Rules carry a severity (1-10); the request score is the highest severity plus one
point per additional distinct rule (max +3).  Requests whose score reaches ``block_threshold`` are
blocked; lower, non-empty findings are *flagged*: forwarded, but marked and audited.

The rules are heuristics: they raise the cost of an attack, they do not make a model immune.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from dataclasses import dataclass

from .normalize import normalize

MAX_STRING_CHARS = 16_384
MAX_BASE64_CANDIDATES = 3
_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4}){16,}(?:==|=)?")
_I = re.IGNORECASE | re.DOTALL


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: int
    pattern: re.Pattern[str]
    leet: bool = False  # also run against the de-leeted text (language rules only)


def _r(rule_id: str, category: str, severity: int, pattern: str, *, leet: bool = False) -> Rule:
    return Rule(rule_id, category, severity, re.compile(pattern, _I), leet)


_FILLER = r"(?:(?:all|any|every|the|your|my|these|those|previous|prior|above|earlier|former|system|developer|safety|todas?|las?|los|tus|mis|estas?|anteriores|previas?|sistema)\W+){0,4}"

RULES: tuple[Rule, ...] = (
    # ---- prompt injection (EN / ES) -------------------------------------------------------------------------------
    _r("pi.override", "prompt_injection", 8,
       rf"\b(?:ignore|disregard|forget|override|bypass|skip|overrule|drop|neglect)\W+(?:all\W+)?{_FILLER}(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|restrictions?|guardrails?|policies)\b",
       leet=True),
    _r("pi.override_es", "prompt_injection", 8,
       rf"\b(?:ignora\w*|olvida\w*|descarta\w*|omite\w*|anula\w*|salta\w*|desatiende\w*)\W+{_FILLER}(?:instrucciones|indicaciones|reglas|directrices|restricciones|prompts?|pautas|politicas|políticas)\b",
       leet=True),
    _r("pi.new_instructions", "prompt_injection", 7,
       r"\b(?:new|updated|real|actual|nuevas?|verdaderas?)\W+(?:system\W+)?(?:instructions?|instrucciones|rules|reglas)\W*(?::|\b(?:are|is|son|es)\b)", leet=True),
    _r("pi.role_override", "prompt_injection", 7,
       r"\b(?:you\W+are\W+now|from\W+now\W+on,?\W+you\W+(?:are|will\W+be|must\W+be)|act\W+as|pretend\W+(?:to\W+be|you\W+are)|roleplay\W+as|simulate\W+being)\W+(?:an?\W+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken|evil|root|admin(?:istrator)?|developer\W+mode|system|the\W+system)\b", leet=True),
    _r("pi.role_override_es", "prompt_injection", 7,
       r"\b(?:ahora\W+eres|a\W+partir\W+de\W+ahora\W+eres|actua\W+como|actúa\W+como|finge\W+ser|hazte\W+pasar\W+por|compórtate\W+como|comportate\W+como)\W+(?:un\W+|una\W+)?(?:dan|sin\W+restricciones|sin\W+filtros|administrador|root|modo\W+desarrollador|el\W+sistema)\b", leet=True),
    _r("pi.exfil_prompt", "prompt_injection", 8,
       r"\b(?:reveal|show|print|output|repeat|leak|display|dump|expose|tell\W+me|what(?:'s|\W+is|\W+are))\W+(?:me\W+)?(?:all\W+)?(?:your\W+|the\W+)?(?:system|initial|hidden|original|secret|internal|full)\W+(?:prompt|instructions?|message|rules|configuration)\b", leet=True),
    _r("pi.exfil_prompt_es", "prompt_injection", 8,
       r"\b(?:revela\w*|muestra\w*|imprime\w*|repite\w*|dime|filtra\w*|expone\w*)\W+(?:me\W+)?(?:todo\W+)?(?:tu\W+|el\W+|las?\W+|tus\W+)?(?:prompt|instrucciones)\W+(?:del\W+|de\W+)?(?:sistema|iniciales|ocultas|originales|secretas|internas)\b", leet=True),
    _r("pi.chat_template", "prompt_injection", 8,
       r"<\|?\s*(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>|\[/?inst\]|<</?sys>>|</?(?:system|assistant|developer)>"),
    _r("pi.role_line", "prompt_injection", 7,
       r"(?:^|\n)\s*(?:system|assistant|developer)\s*:\s*(?:you\b|ignore|disregard|forget|from\W+now|your\b|act\b|new\b|obey|reveal|override|eres\b|ahora\b|tu\b|debes\b|ignora)"),
    _r("pi.jailbreak", "prompt_injection", 7,
       r"\bdo\W+anything\W+now\b|\bdan\W+mode\b|\bdeveloper\W+mode\W+(?:enabled|on|activated)\b|\bjailbreak(?:ed|ing)?\b|\bmodo\W+dios\b", leet=True),
    _r("pi.exfil_data", "prompt_injection", 8,
       r"\b(?:send|post|forward|upload|exfiltrate|email|leak|envia\w*|envía\w*|manda\w*)\W+.{0,40}?(?:conversation|context|history|chat|documents?|data|secrets?|credentials?|prompt|instructions|knowledge|contexto|conversaci[oó]n|datos|documentos|credenciales)\W+.{0,40}?\b(?:to|a)\W+https?://"),
    _r("pi.exfil_channel", "prompt_injection", 6,
       r"\b(?:send|post|forward|upload|exfiltrate|email|envia\w*|envía\w*)\W+.{0,60}?\b(?:to|a)\W+https?://", ),
    _r("pi.markdown_exfil", "prompt_injection", 7, r"!\[[^\]]{0,80}\]\(https?://[^)\s]*\?[^)\s]*="),
    # ---- command injection ----------------------------------------------------------------------------------------
    _r("cmd.chain", "command_injection", 8,
       r"(?:;|\|\||&&|\||\n)\s*(?:sudo\s+)?(?:rm|wget|curl|nc|ncat|netcat|bash|sh|zsh|powershell|pwsh|cmd|chmod|chown|scp|ssh|telnet|nslookup)\b\s+\S"),
    _r("cmd.chain_weak", "command_injection", 8,
       r"(?:;|\|\||&&|\||\n)\s*(?:cat|python\d?|perl|ruby|php|dig|id|ls|echo|whoami|uname|env|printenv)\b\s*(?:-\w|/|\.{1,2}/|~|\$|[|<>]|$)"),
    _r("cmd.shell_exec", "command_injection", 8, r"/bin/(?:ba|z|da|k)?sh\s+-c\b|/usr/bin/env\s+(?:ba)?sh\b"),
    _r("cmd.subst", "command_injection", 8, r"\$\(\s*(?:rm|cat|curl|wget|nc|bash|sh|id|whoami|uname|env|printenv)\b|`\s*(?:rm|cat|curl|wget|nc|bash|sh|id|whoami|uname|env|printenv)\b[^`]{0,100}`"),
    _r("cmd.revshell", "command_injection", 10, r"/dev/tcp/|\bnc\s+-[a-z]*e\b|bash\s+-i\b|mkfifo\s+\S+\s*;|python\d?\s+-c\s+['\"]import\s+(?:socket|os|pty)"),
    _r("cmd.log4shell", "command_injection", 10, r"\$\{\s*(?:jndi|env|sys|lower|upper|date)\s*:"),
    _r("cmd.sensitive_file", "command_injection", 8, r"/etc/(?:passwd|shadow|sudoers)|/proc/self/(?:environ|cmdline)|\.ssh/id_rsa|\bwin\.ini\b|c:\\windows\\system32"),
    _r("cmd.windows", "command_injection", 7, r"\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-(?:enc|e|c|nop|command)\b"),
    # ---- SQL / NoSQL ----------------------------------------------------------------------------------------------
    _r("sqli.union", "sql_injection", 8, r"\bunion\b\s+(?:all\s+)?select\b"),
    _r("sqli.tautology", "sql_injection", 8, r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|$)"),
    _r("sqli.stacked", "sql_injection", 8, r";\s*(?:drop|delete|truncate|alter|insert|update|create|exec(?:ute)?|shutdown)\s+(?:table|from|into|database|user|master|xp_)\b"),
    _r("sqli.timing", "sql_injection", 7, r"\b(?:pg_sleep|sleep|benchmark|waitfor\s+delay|dbms_pipe\.receive_message)\s*\(?\s*['\"]?\d"),
    _r("sqli.xp_cmdshell", "sql_injection", 9, r"\bxp_cmdshell\b|\bsp_oacreate\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b"),
    _r("sqli.meta", "sql_injection", 6, r"\binformation_schema\b|\bsqlite_master\b|\bpg_catalog\b"),
    _r("sqli.login_bypass", "sql_injection", 8, r"(?:^|\s)\w{2,30}['\"]\s*(?:--|#|/\*)\s*$|['\"]\s*\)?\s*(?:or|and)\s*\(?\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*['\"]?\s*\)?\s*(?:--|#)"),
    _r("sqli.comment_tail", "sql_injection", 5, r"['\"]\s*(?:--|#|/\*)"),
    # ---- traversal / SSRF / XXE / XSS / SSTI ---------------------------------------------------------------------
    _r("path.traversal", "path_traversal", 7, r"(?:\.\.[/\\]){2,}|(?:^|[/\\])\.\.[/\\](?:etc|windows|proc|var|root|home)\b"),
    _r("path.dotdot", "path_traversal", 4, r"\.\.[/\\]"),
    _r("path.scheme", "path_traversal", 8, r"\b(?:file|gopher|dict|ldap|ftp|jar|php|expect|data)://"),
    _r("ssrf.internal", "ssrf", 8,
       r"https?://(?:[^/\s@]*@)?(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f[0-9a-f]*|169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[(?:::1?|::ffff:[^\]]*)\]|metadata\.google\.internal|[a-z0-9.-]+\.internal|[a-z0-9.-]+\.local)(?![a-z0-9-])"),
    _r("xxe.entity", "xxe", 7, r"<!(?:entity|doctype)\b"),
    _r("xss.script", "xss", 7, r"<\s*script\b|\bjavascript\s*:|<\s*iframe\b|<\s*(?:svg|img|body)\b[^>]*\bon\w+\s*=|\bon(?:error|load|mouseover|focus)\s*=\s*['\"]?\s*(?:alert|eval|fetch|document)"),
    _r("ssti.dunder", "template_injection", 9, r"\{\{[^}]{0,120}__(?:class|globals|import|builtins|mro|subclasses|init)__|\{%\s*(?:import|include|extends)\b"),
    _r("ssti.expr", "template_injection", 6, r"\{\{[^}]{0,80}(?:__class__|__globals__|__import__|config|self|lipsum|cycler|request|\d+\s*[*+/-]\s*\d+)[^}]{0,80}\}\}|<%[^%]{0,80}%>|#\{[^}]{0,80}\}"),
    _r("http.crlf", "header_injection", 7, r"(?:\r|\n)\s*(?:set-cookie|location|content-(?:type|length)|host|x-forwarded-for)\s*:"),
)

# object keys that have meaning for data stores / runtimes
_KEY_RULES: tuple[tuple[str, str, int, re.Pattern[str]], ...] = (
    ("key.nosql_operator", "nosql_injection", 8, re.compile(r"^\$(?:where|ne|gt|gte|lt|lte|regex|function|expr|accumulator|nin|in|or|and|not|exists)$")),
    ("key.prototype", "prototype_pollution", 8, re.compile(r"^(?:__proto__|constructor|prototype)$")),
    ("key.dotted_path", "prototype_pollution", 6, re.compile(r"(?:^|\.)(?:__proto__|constructor|prototype)(?:\.|$)")),
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: int
    pointer: str  # RFC 6901 JSON pointer of the offending value/key
    excerpt: str  # short, control-stripped, digit-masked snippet: never the full value

    def as_dict(self) -> dict[str, object]:
        return {"rule": self.rule_id, "category": self.category, "severity": self.severity,
                "pointer": self.pointer, "excerpt": self.excerpt}


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    score: int
    blocked: bool

    @property
    def flagged(self) -> bool:
        return bool(self.findings) and not self.blocked


def _excerpt(text: str, start: int, end: int) -> str:
    snippet = text[max(0, start - 8): min(len(text), end + 8)][:60]
    snippet = re.sub(r"[^\x20-\x7e\u00a0-\uffff]", "?", snippet)
    return re.sub(r"\d{5,}", lambda m: "#" * len(m.group(0)), snippet)


def _pointer(parts: tuple[str, ...]) -> str:
    return "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in parts)


def _decode_base64(text: str) -> Iterator[str]:
    for count, m in enumerate(_B64.finditer(text)):
        if count >= MAX_BASE64_CANDIDATES:
            return
        try:
            raw = base64.b64decode(m.group(0), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="ignore")
        if len(decoded) >= 8 and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.9:
            yield decoded


class ThreatScanner:
    def __init__(self, block_threshold: int = 7, rules: tuple[Rule, ...] = RULES) -> None:
        self.block_threshold = block_threshold
        self.rules = rules

    # ------------------------------------------------------------------------------------------------------------
    def scan(self, payload: object) -> ScanResult:
        findings: list[Finding] = []
        stack: list[tuple[tuple[str, ...], object]] = [((), payload)]
        while stack:
            path, value = stack.pop()
            if isinstance(value, dict):
                for k, v in value.items():
                    key = str(k)
                    for rid, cat, sev, pat in _KEY_RULES:
                        if pat.search(key):
                            findings.append(Finding(rid, cat, sev, _pointer((*path, key)), _excerpt(key, 0, len(key))))
                    findings.extend(self._scan_text(key, (*path, key), is_key=True))
                    stack.append(((*path, key), v))
            elif isinstance(value, list):
                stack.extend(((*path, str(i)), v) for i, v in enumerate(value))
            elif isinstance(value, str):
                findings.extend(self._scan_text(value, path))
        return self._result(findings)

    def scan_text(self, text: str) -> ScanResult:
        return self._result(self._scan_text(text, ()))

    # ------------------------------------------------------------------------------------------------------------
    def _result(self, findings: list[Finding]) -> ScanResult:
        unique: dict[tuple[str, str], Finding] = {}
        for f in findings:
            unique.setdefault((f.rule_id, f.pointer), f)
        ordered = tuple(sorted(unique.values(), key=lambda f: (-f.severity, f.rule_id, f.pointer)))
        if not ordered:
            return ScanResult((), 0, False)
        distinct = len({f.rule_id for f in ordered})
        score = min(10, ordered[0].severity + min(3, distinct - 1))
        return ScanResult(ordered, score, score >= self.block_threshold)

    def _scan_text(self, raw: str, path: tuple[str, ...], *, is_key: bool = False, depth: int = 0) -> list[Finding]:
        out: list[Finding] = []
        if len(raw) > MAX_STRING_CHARS:
            out.append(Finding("anomaly.oversized_string", "anomaly", 10, _pointer(path), f"{len(raw)} chars"))
            raw = raw[:MAX_STRING_CHARS]
        n = normalize(raw)
        if "\x00" in raw:
            out.append(Finding("anomaly.null_byte", "anomaly", 7, _pointer(path), "NUL"))
        if n.had_invisible:
            out.append(Finding("obf.invisible_chars", "obfuscation", 4, _pointer(path), "zero-width/bidi characters"))
        if n.had_homoglyphs:
            out.append(Finding("obf.homoglyphs", "obfuscation", 4, _pointer(path), "mixed-script look-alikes"))
        for rule in self.rules:
            m = rule.pattern.search(n.text)
            hay = n.text
            if m is None and rule.leet and n.leet != n.text:
                m = rule.pattern.search(n.leet)
                hay = n.leet
            if m is not None:
                sev = rule.severity
                if n.had_invisible or n.had_homoglyphs:  # evasion attempt around a hit: more suspicious
                    sev = min(10, sev + 1)
                out.append(Finding(rule.rule_id, rule.category, sev, _pointer(path), _excerpt(hay, m.start(), m.end())))
        if depth == 0 and not is_key:
            for decoded in _decode_base64(raw):
                for f in self._scan_text(decoded, path, depth=1):
                    if f.category != "obfuscation":
                        out.append(Finding("enc." + f.rule_id, f.category, min(10, f.severity + 1), f.pointer, f.excerpt))
        return out
