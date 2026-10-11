"""``python -m edge_gateway``: run the gateway with configuration from the environment."""

import uvicorn

from .app import create_app
from .settings import Settings


def main() -> None:
    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host="0.0.0.0", port=8080, proxy_headers=False, server_header=False)


if __name__ == "__main__":
    main()
