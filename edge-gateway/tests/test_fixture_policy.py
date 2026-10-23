"""Enforces the fixture policy: synthetic, trigger-minimal, goal-free, inert. A violation fails the build."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from synthetic_traffic import FIXTURES, load_cases

TRIGGERS = load_cases("detection_triggers.jsonl")
ROOT = Path(__file__).resolve().parents[1]

# working-exploit / destructive / sensitive-target markers: forbidden in fixtures AND anywhere else in tests/ and scripts/
PAYLOAD = re.compile(
    r"rm\s+-rf|drop\s+table|xp_cmdshell\s*\(|/etc/(?:passwd|shadow)|169\.254\.169\.254|jndi:(?:ldap|rmi|dns)://|bash\s+-i\s*>&|"
    r"\bnc\s+-e\b|id_rsa|/proc/self|union\s+select\s+.*\bfrom\b|into\s+outfile|<script>\s*(?:document|fetch)|\bwget\s+http|"
    r"\bcurl\s+[^\s]*\|\s*(?:ba)?sh",
    re.IGNORECASE,
)
# sensitive nouns: a *trigger* fixture must not name what an attack would go after (auth tests legitimately use these words)
SENSITIVE = re.compile(r"password|passwd|credential|api[_\s-]?key|\btoken\b|\bsecret\b", re.IGNORECASE)
URL_RE = re.compile(r"\b(?:https?|ftp|ftps|gopher|ldaps?|php|file|dict)://([^/\s:?#'\")\]]+)", re.IGNORECASE)
# reserved or generic names only; metadata.google.internal is a public, reserved-suffix name used purely as an SSRF *signature*
ALLOWED_HOST = re.compile(r"(?:^|\.)(?:invalid|example|example\.com|example\.org|example\.net)$|^localhost$|^metadata\.google\.internal$", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")


def _host_ok(host: str) -> bool:
    if ALLOWED_HOST.search(host):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


@pytest.mark.parametrize("case", TRIGGERS, ids=[c.id for c in TRIGGERS])
def test_trigger_fixture_is_minimal_and_goal_free(case) -> None:  # type: ignore[no-untyped-def]
    text = case.text if case.text else str(case.payload)
    assert len(text) <= 90, "trigger fixtures must be minimal fragments, not full payloads"
    hit = PAYLOAD.search(text) or SENSITIVE.search(text)
    assert hit is None, f"{case.id} contains a weaponised/sensitive marker: {hit and hit.group(0)!r}"


@pytest.mark.parametrize("case", load_cases("detection_triggers.jsonl") + load_cases("legit_corpus.jsonl"), ids=lambda c: c.id)
def test_every_fixture_uses_reserved_hosts_and_fictional_data(case) -> None:  # type: ignore[no-untyped-def]
    text = case.text if case.text else str(case.payload)
    for host in URL_RE.findall(text):
        assert _host_ok(host), f"{case.id}: host {host!r} is not reserved/private (use *.invalid or example.*)"
    for domain in EMAIL_RE.findall(text):
        assert domain.lower() in {"example.org", "example.com", "example.net"}, f"{case.id}: real-looking e-mail domain {domain!r}"
    for run in re.findall(r"\b\d(?:[ -]?\d){12,18}\b", text):
        digits = re.sub(r"\D", "", run)
        assert not _luhn(digits), f"{case.id}: a Luhn-valid number could be a real card: {run!r}"


def test_fixture_files_declare_the_policy() -> None:
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    for must in ("Mínimos", "Sin objetivo", "Hosts reservados", "Nexus Security & AI Lab"):
        assert must in readme


def test_no_weaponised_strings_anywhere_else_in_tests_or_scripts() -> None:
    """The policy applies to the whole component, not just the fixtures."""
    offenders = []
    for path in [*(ROOT / "tests").glob("*.py"), *(ROOT / "scripts").glob("*.py")]:
        if path.name == "test_fixture_policy.py":
            continue  # defines the deny-list itself
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if PAYLOAD.search(line):
                offenders.append(f"{path.name}:{n}: {line.strip()[:80]}")
    assert not offenders, offenders
