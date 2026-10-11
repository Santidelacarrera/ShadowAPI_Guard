"""Tiny Prometheus-compatible metrics registry (no dependency)."""
import threading
from collections import defaultdict

_lock = threading.Lock()
_counters: dict[tuple[str, tuple], float] = defaultdict(float)

HELP = {
    "shadowapi_events_ingested_total": "Events accepted and stored",
    "shadowapi_redactions_total": "Sensitive values redacted, by kind",
    "shadowapi_bola_alerts_total": "BOLA violations reported by the detector",
    "shadowapi_ingest_failures_total": "Ingest batches rejected because ClickHouse was unavailable",
    "shadowapi_graphql_introspection_total": "GraphQL introspection queries observed",
    "shadowapi_findings_total": "New red team findings, by severity",
}


def inc(name: str, value: float = 1, **labels: str) -> None:
    with _lock:
        _counters[(name, tuple(sorted(labels.items())))] += value


def reset() -> None:
    with _lock:
        _counters.clear()


def render(gauges: dict[str, float] | None = None) -> str:
    lines = []
    with _lock:
        items = sorted(_counters.items())
    seen = set()
    for (name, labels), v in items:
        if name not in seen:
            lines += [f"# HELP {name} {HELP.get(name, name)}", f"# TYPE {name} counter"]
            seen.add(name)
        lab = "{" + ",".join(f'{k}="{val}"' for k, val in labels) + "}" if labels else ""
        lines.append(f"{name}{lab} {v:g}")
    for g, v in (gauges or {}).items():
        lines += [f"# TYPE {g} gauge", f"{g} {v:g}"]
    return "\n".join(lines) + "\n"
