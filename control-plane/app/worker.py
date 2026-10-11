"""Continuous fuzzing worker: periodically scans newly discovered shadow endpoints."""
import logging
import os
import time

from . import db
from .redteam import ScopeError, run_scan

log = logging.getLogger("redteam-worker")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    target = os.environ["REDTEAM_TARGET"]
    interval = int(os.environ.get("REDTEAM_INTERVAL", "30"))
    token = os.environ.get("REDTEAM_TOKEN", "")
    db.init_db()
    while True:
        try:
            res = run_scan(target, token=token, only_new=True)
            if res["endpoints_probed"]:
                log.info("probed %d new endpoints, %d findings", res["endpoints_probed"], len(res["findings"]))
        except ScopeError as e:
            log.error("scope violation: %s", e)
            raise SystemExit(2)
        except Exception:
            log.exception("scan failed")
        time.sleep(interval)


if __name__ == "__main__":
    main()
