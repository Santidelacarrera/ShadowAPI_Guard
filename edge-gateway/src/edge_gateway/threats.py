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
from collections.abc import Iterator, Mapping
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


_ART = r"(?:the|las?|los)"
_QUAL_EN = r"(?:all|any|every|your|my|these|those|previous|prior|above|earlier|former|system|developer|safety)"
_QUAL_ES = r"(?:todas?|tus|mis|estas?|esas?|anteriores|previas?|sistema)"
_NOUN_EN = r"(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|restrictions?|guardrails?|policies)"
_NOUN_ES = r"(?:instrucciones|indicaciones|reglas|directrices|restricciones|prompts?|pautas|politicas|políticas)"
_PERSONA_EN = r"(?:dan|unrestricted|unfiltered|uncensored|jailbroken|evil|developer\W+mode)"
_PERSONA_ES = r"(?:dan|sin\W+restricciones|sin\W+filtros|sin\W+l[ií]mites|modo\W+desarrollador)"
_ROLE_CLAIM = r"(?:root|admin(?:istrator)?|administrador|system|the\W+system|el\W+sistema)"

RULES: tuple[Rule, ...] = (
    # ---- prompt injection (EN / ES) -------------------------------------------------------------------------------
    # An override needs a qualifier ("previous", "all", "your"...) or a trailing marker ("above", "anteriores"):
    # "disregard the rules of the raffle" or "ignore the instructions" alone are ordinary sentences.
    _r("pi.override", "prompt_injection", 8,
       rf"\b(?:ignore|disregard|forget|override|bypass|skip|overrule|drop|neglect)\W+(?:{_ART}\W+)*(?:{_QUAL_EN}\W+)(?:(?:{_ART}|{_QUAL_EN})\W+){{0,3}}{_NOUN_EN}\b"
       rf"|\b(?:ignore|disregard|forget|override|bypass|skip|overrule|neglect)\W+(?:{_ART}\W+)*{_NOUN_EN}\W+(?:above|before|earlier|so\W+far|given)\b",
       leet=True),
    _r("pi.override_es", "prompt_injection", 8,
       rf"\b(?:ignora\w*|olvida\w*|descarta\w*|omite\w*|anula\w*|salta\w*|desatiende\w*)\W+(?:{_ART}\W+)*(?:{_QUAL_ES}\W+)(?:(?:{_ART}|{_QUAL_ES})\W+){{0,3}}{_NOUN_ES}\b"
       rf"|\b(?:ignora\w*|olvida\w*|descarta\w*|omite\w*|anula\w*|salta\w*|desatiende\w*)\W+(?:{_ART}\W+)*{_NOUN_ES}\W+(?:anteriores|previas?|de\W+arriba|del\W+sistema)\b",
       leet=True),
    _r("pi.new_instructions", "prompt_injection", 7,
       r"\b(?:new|updated|real|actual|nuevas?|verdaderas?)\W+(?:system\W+)?(?:instructions?|instrucciones|rules|reglas)\W*(?::|\b(?:are|is|son|es)\b)", leet=True),
    _r("pi.role_override", "prompt_injection", 7,
       rf"\b(?:you\W+are\W+now|from\W+now\W+on,?\W+you\W+(?:are|will\W+be|must\W+be)|act\W+as|pretend\W+(?:to\W+be|you\W+are)|roleplay\W+as|simulate\W+being)\W+(?:an?\W+)?(?:\w+\W+){{0,2}}?{_PERSONA_EN}\b", leet=True),
    _r("pi.role_override_es", "prompt_injection", 7,
       rf"\b(?:ahora\W+eres|a\W+partir\W+de\W+ahora\W+eres|actua\W+como|actúa\W+como|finge\W+ser|hazte\W+pasar\W+por|compórtate\W+como|comportate\W+como)\W+(?:(?:un|una)\W+)?(?:\w+\W+){{0,2}}?{_PERSONA_ES}\b", leet=True),
    # claiming a privileged role is common in ordinary role-play prompts: flag, do not block
    _r("pi.role_claim", "prompt_injection", 5,
       rf"\b(?:you\W+are\W+now|act\W+as|pretend\W+(?:to\W+be|you\W+are)|roleplay\W+as|ahora\W+eres|actúa\W+como|actua\W+como|finge\W+ser|hazte\W+pasar\W+por)\W+(?:(?:an?|the|un|una|el)\W+)?{_ROLE_CLAIM}\b", leet=True),
    _r("pi.exfil_prompt", "prompt_injection", 8,
       r"\b(?:reveal|show|print|output|repeat|leak|display|dump|expose|tell\W+me|what(?:'s|\W+is|\W+are))\W+(?:me\W+)?(?:all\W+)?(?:(?:your|the)\W+)?"
       r"(?:(?:system|initial|hidden|original|secret|internal)\W+prompt|(?:your\W+(?:(?:system|initial|original|hidden|secret|internal)\W+)?|(?:hidden|secret|internal)\W+(?:system\W+)?)(?:instructions?|rules)|(?:hidden|secret|internal)\W+(?:message|configuration))\b", leet=True),
    _r("pi.exfil_prompt_es", "prompt_injection", 8,
       r"\b(?:revela\w*|muestra\w*|imprime\w*|repite\w*|dime|filtra\w*|expone\w*)\W+(?:me\W+)?(?:todo\W+)?(?:tu\W+|el\W+|las?\W+|tus\W+)?"
       r"(?:prompt\W+(?:del\W+sistema|inicial|oculto|original|secreto|interno)|instrucciones\W+(?:ocultas|secretas|internas|iniciales\W+del\W+sistema))\b", leet=True),
    _r("pi.chat_template", "prompt_injection", 8,
       r"<\|?\s*(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\s*\|?>|\[/?inst\]|<</?sys>>|</?(?:system|assistant|developer)>"),
    _r("pi.role_line", "prompt_injection", 7,
       r"(?:^|\n)\s*(?:system|assistant|developer)\s*:\s*(?:you\b|ignore|disregard|forget|from\W+now|your\b|act\b|new\b|obey|reveal|override|eres\b|ahora\b|tu\b|debes\b|ignora)"),
    _r("pi.jailbreak", "prompt_injection", 7,
       r"\bdo\W+anything\W+now\b|\bdan\W+mode\b|\bdeveloper\W+mode\W+(?:enabled|on|activated)\b|\bmodo\W+dios\b", leet=True),
    _r("pi.jailbreak_word", "prompt_injection", 5, r"\bjailbreak(?:ed|ing)?\b", leet=True),
    _r("pi.exfil_data", "prompt_injection", 8,
       r"\b(?:send|post|forward|upload|exfiltrate|email|leak|envia\w*|envía\w*|manda\w*)\W+.{0,40}?"
       r"(?:conversation|context|history|chat|prompt|instructions|secrets?|credentials?|passwords?|api\W+keys?|contexto|conversaci[oó]n|historial|credenciales|contrase[nñ]as?)"
       r"\W+.{0,40}?\b(?:to|a)\W+https?://"),
    _r("pi.exfil_channel", "prompt_injection", 6,
       r"\b(?:send|post|forward|upload|exfiltrate|email|envia\w*|envía\w*)\W+.{0,60}?\b(?:to|a)\W+https?://"),
    _r("pi.markdown_exfil", "prompt_injection", 7,
       r"!\[[^\]]{0,80}\]\(https?://[^)\s]*\?[^)\s]*\b(?:data|q|query|secret|payload|content|ctx|context|text|msg|message|prompt|history|chat|conversation)="),
    # ---- command injection ----------------------------------------------------------------------------------------
    _r("cmd.chain", "command_injection", 8,
       r"(?:;|\|\||&&|\||\n)\s*(?:sudo\s+)?(?:rm|wget|curl|nc|ncat|netcat|bash|sh|zsh|powershell|pwsh|cmd|chmod|chown|scp|ssh|telnet|nslookup)\b\s+\S"),
    _r("cmd.chain_weak", "command_injection", 8,
       r"(?:;|\|\||&&|\||\n)\s*(?:cat|python\d?|perl|ruby|php|dig|id|ls|echo|whoami|uname|env|printenv)\b\s*(?:-\w|/|\.{1,2}/|~|\$|[|<>]|$)"),
    _r("cmd.shell_exec", "command_injection", 8, r"/bin/(?:ba|z|da|k)?sh\s+-c\b|/usr/bin/env\s+(?:ba)?sh\b"),
    _r("cmd.subst", "command_injection", 8, r"\$\(\s*(?:rm|cat|curl|wget|nc|bash|sh|id|whoami|uname|env|printenv)\b"),
    # `cmd arg` in backticks is how docs write inline code: only worth a flag
    _r("cmd.subst_backtick", "command_injection", 5, r"`\s*(?:rm|cat|curl|wget|nc|bash|sh|id|whoami|uname|env|printenv)\b\s+[^`\s][^`]{0,100}`"),
    # "bash -i" alone is an interactive shell; it is only a reverse-shell shape when its output is redirected
    _r("cmd.revshell", "command_injection", 10, r"/dev/tcp/|\bnc\s+-[a-z]*e\b|bash\s+-i\s*>|mkfifo\s+\S+\s*;|python\d?\s+-c\s+['\"]import\s+(?:socket|os|pty)"),
    _r("cmd.log4shell", "command_injection", 10, r"\$\{\s*jndi\s*:"),
    _r("cmd.lookup_syntax", "command_injection", 5, r"\$\{\s*(?:env|sys|lower|upper|date|ctx|java|k8s|docker|web)\s*:"),
    _r("cmd.sensitive_file", "command_injection", 8, r"/etc/(?:passwd|shadow|sudoers)|/proc/self/(?:environ|cmdline)|\.ssh/id_rsa|\bwin\.ini\b|c:\\windows\\system32"),
    _r("cmd.windows", "command_injection", 7, r"\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-(?:enc|e|c|nop|command)\b"),
    # ---- SQL / NoSQL ----------------------------------------------------------------------------------------------
    _r("sqli.union", "sql_injection", 8, r"\bunion\b\s+(?:all\s+)?select\b"),
    _r("sqli.tautology", "sql_injection", 8, r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|/\*|$)"),
    _r("sqli.stacked", "sql_injection", 8, r";\s*(?:drop|delete|truncate|alter|insert|update|create|exec(?:ute)?|shutdown)\s+(?:table|from|into|database|user|master|xp_)\b"),
    _r("sqli.timing", "sql_injection", 7, r"\b(?:pg_sleep|benchmark|waitfor\s+delay|dbms_pipe\.receive_message)\s*\(?\s*['\"]?\d|\bsleep\s*\(\s*\d"),
    _r("sqli.xp_cmdshell", "sql_injection", 9, r"\bxp_cmdshell\b|\bsp_oacreate\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b"),
    _r("sqli.meta", "sql_injection", 6, r"\binformation_schema\b|\bsqlite_master\b|\bpg_catalog\b"),
    _r("sqli.login_bypass", "sql_injection", 8, r"(?:^|\s)\w{2,30}['\"]\s*(?:--|#|/\*)\s*$|['\"]\s*\)?\s*(?:or|and)\s*\(?\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*['\"]?\s*\)?\s*(?:--|#)"),
    _r("sqli.comment_tail", "sql_injection", 5, r"['\"]\s*(?:--|#|/\*)"),
    # ---- traversal / SSRF / XXE / XSS / SSTI ---------------------------------------------------------------------
    # "../../utils" is a normal import path; three levels up, or a hop into a system root, is not
    _r("path.traversal", "path_traversal", 7, r"(?:\.\.[/\\]){3,}|(?:^|[/\\])\.\.[/\\](?:etc|windows|proc|var|root|home)\b"),
    _r("path.dotdot", "path_traversal", 4, r"\.\.[/\\]"),
    _r("path.scheme", "path_traversal", 8, r"\b(?:gopher|dict|expect|php|jar)://"),
    _r("path.scheme_soft", "path_traversal", 5, r"\b(?:file|ldaps?|ftp)://"),
    # cloud metadata endpoints are never something a user needs to mention; private addresses are common in ordinary questions
    _r("ssrf.metadata", "ssrf", 8,
       r"https?://(?:[^/\s@]*@)?(?:169\.254\.\d+\.\d+|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|\[fd00:ec2::254\])(?![a-z0-9-])"),
    _r("ssrf.private", "ssrf", 5,
       r"https?://(?:[^/\s@]*@)?(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f[0-9a-f]*|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[(?:::1?|::ffff:[^\]]*)\]|[a-z0-9.-]+\.internal|[a-z0-9.-]+\.local)(?![a-z0-9-])"),
    _r("xxe.entity", "xxe", 7, r"<!entity\b|<!doctype\b[^>]*\["),
    _r("xss.script_tag", "xss", 5, r"<\s*script\b|<\s*iframe\b"),
    _r("xss.active", "xss", 7,
       r"<\s*script\b[^>]*>[^<]{0,200}(?:alert|eval|document\.|fetch\(|window\.|location\.)|\bjavascript\s*:\s*(?:alert|eval|document|fetch|window|location)"
       r"|<\s*(?:svg|img|body)\b[^>]*\bon\w+\s*=|\bon(?:error|load|mouseover|focus)\s*=\s*['\"]?\s*(?:alert|eval|fetch|document)"),
    _r("ssti.dunder", "template_injection", 9, r"\{\{[^}]{0,120}__(?:class|globals|import|builtins|mro|subclasses|init)__|\{%\s*(?:import|include|extends)\b"),
    _r("ssti.expr", "template_injection", 6, r"\{\{[^}]{0,80}(?:__class__|__globals__|__import__|config|self|lipsum|cycler|request|\d+\s*[*+/-]\s*\d+)[^}]{0,80}\}\}|<%[^%]{0,80}%>|#\{[^}]{0,80}\}"),
    # pasted HTTP requests/responses legitimately contain these header lines; the gateway never writes body text into headers
    _r("http.crlf", "header_injection", 5, r"(?:\r|\n)\s*(?:set-cookie|location|content-(?:type|length)|host|x-forwarded-for)\s*:"),
)

# Deployment profiles = severity overrides on top of the rule defaults. "business" is the strict default.
# "technical" is for developer/DevOps assistants, where shell, SQL and template snippets are everyday content: those
# rules drop to *flag* (5), so a single hit is forwarded with X-Guard-Verdict: flagged instead of blocked.
PROFILES: dict[str, dict[str, int]] = {
    "business": {},
    "technical": {
        "cmd.chain": 5, "cmd.chain_weak": 5, "cmd.windows": 5, "cmd.subst": 5, "pi.chat_template": 5,
        "sqli.union": 5, "sqli.tautology": 5, "sqli.stacked": 5, "sqli.timing": 5, "sqli.login_bypass": 5, "ssti.dunder": 5, "ssti.expr": 4,
    },
}
KEY_RULE_IDS = ("key.nosql_operator", "key.prototype", "key.dotted_path")
ANOMALY_RULE_IDS = ("anomaly.oversized_string", "anomaly.null_byte", "obf.invisible_chars", "obf.homoglyphs")


def known_rule_ids() -> set[str]:
    return {r.rule_id for r in RULES} | set(KEY_RULE_IDS) | set(ANOMALY_RULE_IDS)


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
    """Deterministic, dependency-free text/JSON scanner. Reusable on its own: it knows nothing about HTTP or tenants."""

    def __init__(self, block_threshold: int = 7, rules: tuple[Rule, ...] = RULES, *, profile: str = "business",
                 overrides: Mapping[str, int] | None = None) -> None:
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}; choose one of {sorted(PROFILES)}")
        merged = {**PROFILES[profile], **(overrides or {})}
        unknown = sorted(set(merged) - known_rule_ids())
        if unknown:
            raise ValueError(f"unknown rule id(s) in overrides: {unknown}")
        bad = {k: v for k, v in merged.items() if not 0 <= v <= 10}
        if bad:
            raise ValueError(f"severity must be 0..10 (0 disables the rule): {bad}")
        self.block_threshold = block_threshold
        self.rules = rules
        self.profile = profile
        self._sev = merged

    def severity(self, rule_id: str, default: int) -> int:
        """Effective severity after the profile and overrides (0 = rule disabled)."""
        return self._sev.get(rule_id, default)

    def effective_rules(self) -> list[dict[str, object]]:
        base = [(r.rule_id, r.category, r.severity) for r in self.rules]
        base += [(rid, cat, sev) for rid, cat, sev, _ in _KEY_RULES]
        return [{"rule": rid, "category": cat, "default_severity": sev, "severity": self.severity(rid, sev),
                 "blocks": self.severity(rid, sev) >= self.block_threshold} for rid, cat, sev in base]

    # ------------------------------------------------------------------------------------------------------------
    def scan(self, payload: object) -> ScanResult:
        findings: list[Finding] = []
        stack: list[tuple[tuple[str, ...], object]] = [((), payload)]
        while stack:
            path, value = stack.pop()
            if isinstance(value, dict):
                for k, v in value.items():
                    key = str(k)
                    for rid, cat, base_sev, pat in _KEY_RULES:
                        sev = self.severity(rid, base_sev)
                        if sev > 0 and pat.search(key):
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
            if (sev := self.severity("anomaly.oversized_string", 10)) > 0:
                out.append(Finding("anomaly.oversized_string", "anomaly", sev, _pointer(path), f"{len(raw)} chars"))
            raw = raw[:MAX_STRING_CHARS]
        n = normalize(raw)
        if "\x00" in raw and (sev := self.severity("anomaly.null_byte", 7)) > 0:
            out.append(Finding("anomaly.null_byte", "anomaly", sev, _pointer(path), "NUL"))
        if n.had_invisible and (sev := self.severity("obf.invisible_chars", 4)) > 0:
            out.append(Finding("obf.invisible_chars", "obfuscation", sev, _pointer(path), "zero-width/bidi characters"))
        if n.had_homoglyphs and (sev := self.severity("obf.homoglyphs", 4)) > 0:
            out.append(Finding("obf.homoglyphs", "obfuscation", sev, _pointer(path), "mixed-script look-alikes"))
        for rule in self.rules:
            base_sev = self.severity(rule.rule_id, rule.severity)
            if base_sev <= 0:
                continue  # disabled by the profile / an override
            m = rule.pattern.search(n.text)
            hay = n.text
            if m is None and rule.leet and n.leet != n.text:
                m = rule.pattern.search(n.leet)
                hay = n.leet
            if m is not None:
                sev = base_sev
                if n.had_invisible or n.had_homoglyphs:  # evasion attempt around a hit: more suspicious
                    sev = min(10, sev + 1)
                out.append(Finding(rule.rule_id, rule.category, sev, _pointer(path), _excerpt(hay, m.start(), m.end())))
        if depth == 0 and not is_key:
            for decoded in _decode_base64(raw):
                for f in self._scan_text(decoded, path, depth=1):
                    if f.category != "obfuscation":
                        out.append(Finding("enc." + f.rule_id, f.category, min(10, f.severity + 1), f.pointer, f.excerpt))
        return out
