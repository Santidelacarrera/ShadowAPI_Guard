"""``python -m edge_gateway``: run the gateway with configuration from the environment.

The listener binds to loopback unless ``GUARD_BIND_HOST`` says otherwise: exposing the gateway is an explicit decision
(the container image sets it to 0.0.0.0 inside its own network namespace; compose publishes the port on 127.0.0.1).
"""

import os

import uvicorn

from .app import create_app
from .settings import Settings


def main() -> None:
    settings = Settings.from_env()
    host = os.environ.get("GUARD_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("GUARD_PORT", "8080"))
    uvicorn.run(create_app(settings), host=host, port=port, proxy_headers=False, server_header=False)


if __name__ == "__main__":
    main()
