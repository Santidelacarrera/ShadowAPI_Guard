"""The documented API surface. Everything else is, by definition, a Shadow API probe."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pydantic import BaseModel

from .schemas import ConsensusRun, RagQuery

_PARAM = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class Route:
    name: str
    method: str
    pattern: str
    upstream: str  # key into Settings.upstreams
    scope: str
    body_model: type[BaseModel] | None = None
    max_body_bytes: int = 64 * 1024
    segments: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        object.__setattr__(self, "segments", tuple(self.pattern.strip("/").split("/")))

    def match(self, path_segments: tuple[str, ...]) -> bool:
        if len(path_segments) != len(self.segments):
            return False
        for want, got in zip(self.segments, path_segments, strict=True):
            if want.startswith("{") and want.endswith("}"):
                if not _PARAM.match(got):
                    return False
            elif want != got:
                return False
        return True

    @property
    def template(self) -> str:
        return "/" + "/".join(self.segments)


@dataclass(frozen=True)
class Resolution:
    route: Route | None
    path_known: bool  # some route exists for this path, with another method
    allowed_methods: tuple[str, ...]


class RouteTable:
    def __init__(self, routes: list[Route]) -> None:
        self._routes = routes

    @property
    def routes(self) -> tuple[Route, ...]:
        return tuple(self._routes)

    def resolve(self, method: str, path: str) -> Resolution:
        segs = tuple(path.split("/")[1:]) if path.startswith("/") else ("",)  # strict: a trailing slash is a different path
        by_path = [r for r in self._routes if r.match(segs)]
        for r in by_path:
            if r.method == method.upper():
                return Resolution(r, True, ())
        return Resolution(None, bool(by_path), tuple(sorted({r.method for r in by_path})))


def default_routes() -> RouteTable:
    return RouteTable(
        [
            Route("rag.query", "POST", "/v1/rag/query", "rag", "rag:query", RagQuery, 16 * 1024),
            Route("consensus.run", "POST", "/v1/consensus/run", "consensus", "consensus:run", ConsensusRun, 32 * 1024),
            Route("consensus.get", "GET", "/v1/consensus/runs/{run_id}", "consensus", "consensus:read"),
        ]
    )
