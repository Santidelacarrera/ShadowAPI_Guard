"""Synthetic traffic for evaluating the detection rules. Everything here is fabricated, inert and deterministic.

Fixture policy (enforced by tests/test_fixture_policy.py):
  * *trigger-minimal*: an attack-pattern fixture contains only the fragment that fires a rule;
  * *goal-free*: no credentials, no real targets, no destructive or working-exploit content;
  * hosts are RFC-reserved (``*.invalid``, ``example.*``) or private/loopback; file names are synthetic.
"""

from __future__ import annotations

import base64
import json
import random
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class Case:
    id: str
    kind: str  # trigger | legit | hard_negative
    category: str
    text: str = ""
    payload: Any = None  # structured body (for key-level rules); mutually exclusive with ``text``
    rule: str = ""  # expected rule id (triggers)
    expect: str = ""  # block | flag | allow
    near_miss_of: str = ""  # hard negatives: the rule they resemble
    profile: str = ""  # profile under which a legit case must pass ("" = every profile)
    note: str = ""

    @property
    def body(self) -> Any:
        return self.payload if self.payload is not None else {"query": self.text}


def load_cases(name: str) -> list[Case]:
    cases = []
    for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            d = json.loads(line)
            cases.append(Case(**d))
    return cases


# ---- metamorphic transforms: how an evader might disguise a trigger phrase -----------------------------------------

def t_zero_width(s: str) -> str:
    return "\u200b".join(s)


def t_url(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def t_html_entities(s: str) -> str:
    return "".join(f"&#{ord(c)};" if c == " " else c for c in s)


def t_homoglyph(s: str) -> str:
    return s.translate(str.maketrans({"o": "\u043e", "e": "\u0435", "a": "\u0430"}))


def t_leet(s: str) -> str:
    return s.translate(str.maketrans({"o": "0", "i": "1", "e": "3"}))


def t_fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


def t_base64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def t_upper(s: str) -> str:
    return s.upper()


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "zero_width": t_zero_width, "url": t_url, "html_entities": t_html_entities, "homoglyph": t_homoglyph,
    "leet": t_leet, "fullwidth": t_fullwidth, "base64": t_base64, "upper": t_upper,
}


# ---- legitimate traffic generator ------------------------------------------------------------------------------------

_FIRST = ["Ana", "Luis", "Camila", "Diego", "Valentina", "Mateo", "Sofía", "Tomás", "Javiera", "Pedro", "Marta", "John", "Emma", "Liam"]
_LAST = ["Rojas", "Muñoz", "Soto", "Pérez", "Díaz", "Silva", "Smith", "Brown", "Johnson", "Lopez"]
_ORG = ["Acme Corp", "Contoso", "Globex", "Initech", "Umbrella Foods", "Nexus Demo Co"]
_PRODUCT = ["el plan Pro", "the Enterprise plan", "el módulo de facturación", "the reporting dashboard", "la integración con ERP",
            "the mobile app", "el agente de soporte", "the audit log"]
_DEPT = ["finanzas", "legal", "soporte", "ventas", "RR.HH.", "compliance", "operaciones", "engineering"]
_MONTH = ["enero", "marzo", "junio", "septiembre", "diciembre", "January", "April", "August", "November"]
_TOPIC = ["política de reembolsos", "plazo de entrega", "contrato marco", "retención de datos", "SLA de soporte",
          "refund policy", "onboarding checklist", "data retention", "incident response plan", "vacation policy", "política de contraseñas"]
_TECH = ["Docker", "PostgreSQL", "Kubernetes", "FastAPI", "Terraform", "nginx", "Redis", "GitHub Actions", "pandas", "React"]
_ERR = ["connection refused", "timeout after 30s", "403 Forbidden", "out of memory", "certificate verify failed", "502 Bad Gateway"]
_LANGS = ["Python", "Go", "Rust", "TypeScript", "SQL", "Bash"]


def _name(r: random.Random) -> str:
    return f"{r.choice(_FIRST)} {r.choice(_LAST)}"


def _amount(r: random.Random) -> str:
    return r.choice([f"${r.randint(10, 9999):,}", f"{r.randint(10, 999)}.{r.randint(100, 999)} CLP", f"€{r.randint(5, 900)}", f"{r.randint(1, 99)}%"])


def _date(r: random.Random) -> str:
    return f"{r.randint(2023, 2026)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"


def _fake_rut(r: random.Random) -> str:  # syntactically RUT-like, checksum not guaranteed: purely fictional
    return f"{r.randint(5, 25)}.{r.randint(100, 999)}.{r.randint(100, 999)}-{r.choice('0123456789K')}"


def _fake_card(r: random.Random) -> str:  # random 4-4-4-4 digits: purely fictional, never derived from a real card
    return " ".join(f"{r.randint(1000, 9999)}" for _ in range(4))


def _fake_email(r: random.Random) -> str:
    return f"{r.choice(_FIRST).lower()}.{r.choice(_LAST).lower()}@example.org".replace("ñ", "n").replace("í", "i").replace("é", "e")


TEMPLATES: list[Callable[[random.Random], str]] = [
    # business / knowledge-base questions (ES + EN)
    lambda r: f"¿Cuál es la {r.choice(_TOPIC)} para {r.choice(_PRODUCT)}?",
    lambda r: f"What does the {r.choice(_TOPIC)} say about {r.choice(_PRODUCT)}?",
    lambda r: f"Resume el acta de la reunión de {r.choice(_DEPT)} del {r.choice(_MONTH)} en tres puntos.",
    lambda r: f"Summarize the {r.choice(_DEPT)} report for {r.choice(_ORG)} in {r.randint(2, 6)} bullet points.",
    lambda r: f"{_name(r)} pidió una cotización de {_amount(r)} para {r.choice(_PRODUCT)}; ¿qué aprobaciones faltan?",
    lambda r: f"Draft a polite reply to {_name(r)} at {r.choice(_ORG)} confirming the meeting on {_date(r)}.",
    lambda r: f"El contrato con {r.choice(_ORG)} vence el {_date(r)}. ¿Qué cláusulas de renovación aplican?",
    lambda r: f"List the open action items assigned to {_name(r)} in the {r.choice(_DEPT)} team.",
    lambda r: f"¿Quién es el responsable de {r.choice(_TOPIC)} en {r.choice(_DEPT)}?",
    lambda r: f"Compara la {r.choice(_TOPIC)} de {r.choice(_ORG)} con la de {r.choice(_ORG)}.",
    lambda r: f"Translate to {r.choice(['English', 'Spanish', 'French', 'Portuguese'])}: 'Thank you for your patience while we review the request.'",
    lambda r: f"Escribe un resumen ejecutivo de {r.randint(100, 400)} palabras sobre {r.choice(_TOPIC)}.",
    lambda r: f"How many days of {r.choice(['vacation', 'sick leave', 'parental leave'])} does {_name(r)} have left?",
    # fictional personal-data-shaped content (redaction is the control plane's job, not a reason to block)
    lambda r: f"El cliente {_name(r)} (RUT {_fake_rut(r)}) escribió desde {_fake_email(r)}; ¿cómo respondo?",
    lambda r: f"El pago {_fake_card(r)} fue rechazado el {_date(r)}; ¿qué pasos de conciliación corresponden?",
    lambda r: f"Factura {r.randint(1000, 99999)} por {_amount(r)} emitida a {r.choice(_ORG)}; ¿está vencida?",
    lambda r: f"Call me back at +56 9 {r.randint(1000, 9999)} {r.randint(1000, 9999)} about order {r.randint(100000, 999999)}.",
    # everyday technical questions (benign)
    lambda r: f"How do I fix '{r.choice(_ERR)}' when running {r.choice(_TECH)} in production?",
    lambda r: f"¿Cuál es la diferencia entre {r.choice(_TECH)} y {r.choice(_TECH)} para un proyecto pequeño?",
    lambda r: f"Explain how {r.choice(_TECH)} handles retries and timeouts, with a short example in {r.choice(_LANGS)}.",
    lambda r: f"Write a unit test in {r.choice(_LANGS)} for a function that adds {r.randint(2, 9)} numbers.",
    lambda r: f"Why does my {r.choice(_TECH)} container restart every {r.randint(2, 30)} minutes?",
    lambda r: f"Give me a checklist to review a pull request that touches {r.choice(_TECH)} configuration.",
    lambda r: f"Qué significa el código de error {r.randint(400, 599)} en {r.choice(_TECH)}?",
    lambda r: f"Refactor this function to be more readable: def f(a, b): return a if a > b else b  # {_date(r)}",
    # numbers, units, punctuation, code-ish but benign
    lambda r: f"Calcula {r.randint(2, 99)} * {r.randint(2, 99)} + {r.randint(2, 99)} y explica el resultado.",
    lambda r: f"El archivo está en C:\\Users\\{r.choice(_FIRST)}\\Documents\\informe_{r.randint(1, 12)}.xlsx; ¿cómo lo comparto?",
    lambda r: f"Which of these is correct: (a) {r.randint(1, 9)}; (b) {r.randint(1, 9)}; (c) none -- explain briefly.",
    lambda r: f"List the pros & cons of using {r.choice(_TECH)} vs. {r.choice(_TECH)}: cost, latency, learning curve.",
    lambda r: f"La reunión es a las {r.randint(8, 18)}:{r.choice(['00', '15', '30', '45'])}; ¿puedes agendarla con {_name(r)}?",
    lambda r: f"See https://docs.example.com/{r.choice(['guide', 'faq', 'policy'])}/{r.randint(1, 40)} and summarise section {r.randint(1, 6)}.",
    lambda r: f"Tell me about the history of {r.choice(['the printing press', 'the Roman Empire', 'the Silk Road', 'the Industrial Revolution'])}.",
    lambda r: f"Describe the steps to {r.choice(['reset a forgotten password', 'rotate an API key safely', 'enable two-factor authentication'])} for our team.",
]


class LegitGenerator:
    """Deterministic stream of benign requests. The same seed always yields the same corpus."""

    def __init__(self, seed: int = 20261012) -> None:
        self._r = random.Random(seed)

    def one(self) -> str:
        return self._r.choice(TEMPLATES)(self._r)

    def stream(self, n: int) -> Iterator[str]:
        seen: set[str] = set()
        produced = attempts = 0
        while produced < n and attempts < n * 20:
            attempts += 1
            text = self.one()
            if text not in seen:
                seen.add(text)
                produced += 1
                yield text
