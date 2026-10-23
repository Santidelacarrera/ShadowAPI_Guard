"""Evaluate the detection rules against the synthetic fixtures and write docs/DETECTION_REPORT.md.

    python scripts/evaluate_detection.py            # print a summary per profile, rewrite the report
    python scripts/evaluate_detection.py --check    # exit 1 if the committed report is stale (used by CI/tests)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from edge_gateway.threats import ThreatScanner  # noqa: E402

from detection_eval import evaluate, render_report, summary  # noqa: E402

REPORT = ROOT / "docs" / "DETECTION_REPORT.md"


def main() -> int:
    if "--check" in sys.argv:
        ok = REPORT.exists() and REPORT.read_text(encoding="utf-8") == render_report()
        print("DETECTION_REPORT.md is up to date" if ok else "DETECTION_REPORT.md is stale: run scripts/evaluate_detection.py")
        return 0 if ok else 1
    for profile in ("business", "technical"):
        print(f"=== profile {profile} ===")
        print(summary(evaluate(ThreatScanner(profile=profile), profile=profile)))
        print()
    REPORT.write_text(render_report(), encoding="utf-8")
    print(f"wrote {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
