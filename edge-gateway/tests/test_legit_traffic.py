"""Legitimate traffic must not be blocked: curated corpus, hard negatives, a seeded synthetic stream, and the full gateway."""

from __future__ import annotations

import collections
from typing import Any

import pytest

from edge_gateway.threats import ThreatScanner

from conftest import Gateway, bearer
from detection_eval import decision
from synthetic_traffic import Case, LegitGenerator, load_cases

URL = "/v1/rag/query"
LEGIT = load_cases("legit_corpus.jsonl")
PROFILES = {"business": ThreatScanner(), "technical": ThreatScanner(profile="technical")}
CASES = [(c, p) for c in LEGIT for p in PROFILES if c.profile in ("", p)]


@pytest.mark.parametrize("case,profile", CASES, ids=[f"{c.id}-{p}" for c, p in CASES])
def test_curated_legitimate_and_hard_negative_cases_are_not_blocked(case: Case, profile: str) -> None:
    got, rules, score = decision(PROFILES[profile], case.body)
    assert got != "block", f"false positive under {profile}: {case.text!r} -> {rules} (score {score})"


def test_known_technical_false_positives_are_documented_not_hidden() -> None:
    """Hard negatives marked profile=technical ARE blocked by the strict default. That is intentional and measured,
    so a change that silently fixes or worsens it must be noticed."""
    strict_blocked = [c for c in LEGIT if c.profile == "technical" and decision(PROFILES["business"], c.body)[0] == "block"]
    technical_cases = [c for c in LEGIT if c.profile == "technical"]
    assert len(strict_blocked) >= len(technical_cases) * 0.6, "technical fixtures no longer stress the strict profile"


def test_generator_is_deterministic_and_unique() -> None:
    a, b = list(LegitGenerator(7).stream(200)), list(LegitGenerator(7).stream(200))
    assert a == b and len(set(a)) == 200
    assert a != list(LegitGenerator(8).stream(200))


def test_generator_covers_both_languages_and_all_template_families() -> None:
    texts = list(LegitGenerator().stream(1500))
    assert any("¿" in t for t in texts) and any(t.startswith(("What", "Summarize", "How", "Draft", "List")) for t in texts)
    assert any("example.org" in t for t in texts) and any("+56 9" in t for t in texts)  # fictional PII-shaped content
    assert any("```" not in t and "docs.example.com" in t for t in texts)


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_synthetic_stream_is_never_blocked_and_rarely_flagged(profile: str) -> None:
    scanner = PROFILES[profile]
    blocked, flagged, n = [], 0, 3000
    for text in LegitGenerator().stream(n):
        d, rules, _ = decision(scanner, {"query": text})
        flagged += d == "flag"
        if d == "block":
            blocked.append((rules, text[:80]))
    assert not blocked, f"{len(blocked)} false positives, e.g. {blocked[:3]}"
    assert flagged / n <= 0.01, f"flag rate {flagged / n:.2%} is noisy"


def test_different_seeds_do_not_reveal_new_false_positives() -> None:
    for seed in (1, 2, 3, 4, 5):
        for text in LegitGenerator(seed).stream(600):
            assert decision(PROFILES["business"], {"query": text})[0] != "block", (seed, text)


def test_fictional_personal_data_is_not_a_reason_to_block() -> None:
    body = {"query": "El cliente Ana Soto (RUT 12.345.678-5) escribió desde ana.soto@example.org; tarjeta 4111 1111 1111 1111; +56 9 8765 4321."}
    assert decision(PROFILES["business"], body)[0] != "block"  # redaction is the control plane's job


def test_long_legitimate_documents_are_not_blocked() -> None:
    para = "El comité revisó el presupuesto trimestral y acordó priorizar la migración de sistemas. "
    assert decision(PROFILES["business"], {"query": para * 40})[0] != "block"  # ~3.4k chars, below the string cap


# ---- end to end: the whole gateway, real requests ------------------------------------------------------------------

def test_gateway_forwards_a_large_synthetic_legitimate_stream(gw: Gateway) -> None:
    statuses: collections.Counter[int] = collections.Counter()
    for text in LegitGenerator(99).stream(600):
        statuses[gw.client.post(URL, json={"query": text}, headers=bearer()).status_code] += 1
    assert statuses == {200: 600}, statuses
    assert not gw.events("threat_blocked") and not gw.events("schema_anomaly")
    assert len(gw.upstream.seen("rag.internal")) == 600


def test_gateway_forwards_legitimate_consensus_tasks(gw: Gateway) -> None:
    for text in LegitGenerator(5).stream(120):
        body: dict[str, Any] = {"task": text, "agents": ["legal", "finance"], "max_rounds": 2, "context": {"area": "ventas"}}
        assert gw.client.post("/v1/consensus/run", json=body, headers=bearer()).status_code == 200
    assert not gw.events("threat_blocked")


def test_hard_negatives_flow_through_the_gateway_with_a_clean_or_flagged_verdict(gw: Gateway) -> None:
    for c in (c for c in LEGIT if c.kind == "hard_negative" and c.profile == "" and len(c.text) <= 4000):
        r = gw.client.post(URL, json={"query": c.text}, headers=bearer())
        assert r.status_code == 200, f"{c.id} [{c.near_miss_of}] was rejected: {r.status_code}"
        assert gw.upstream.seen("rag.internal")[-1]["headers"]["x-guard-verdict"] in {"clean", "flagged"}


def test_technical_profile_gateway_accepts_technical_questions(make_gw: Any) -> None:
    gw = make_gw(profile="technical")
    for c in (c for c in LEGIT if c.profile == "technical"):
        assert gw.client.post(URL, json={"query": c.text}, headers=bearer()).status_code == 200, c.id


def test_strict_profile_blocks_what_the_technical_profile_allows(gw: Gateway) -> None:
    """Same input, two deployments: shows the profile is what changes the outcome, and that it is audited."""
    technical_case = next(c for c in LEGIT if c.profile == "technical" and decision(PROFILES["business"], c.body)[0] == "block")
    assert gw.client.post(URL, json={"query": technical_case.text}, headers=bearer()).status_code == 403
