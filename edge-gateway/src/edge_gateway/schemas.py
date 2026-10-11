"""Request schemas of the documented API surface. Unknown fields are anomalies, not ignored."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,64}$")]
UUIDStr = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
Scalar = str | int | float | bool


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RagQuery(_Strict):
    query: Annotated[str, StringConstraints(min_length=1, max_length=4000)]
    top_k: Annotated[int, Field(ge=1, le=50)] = 5
    filters: dict[Identifier, Annotated[str, StringConstraints(max_length=256)] | int | bool] = {}
    conversation_id: UUIDStr | None = None

    @field_validator("filters")
    @classmethod
    def _few_filters(cls, v: dict[str, object]) -> dict[str, object]:
        if len(v) > 20:
            raise ValueError("too many filters")
        return v


class ConsensusRun(_Strict):
    task: Annotated[str, StringConstraints(min_length=1, max_length=8000)]
    agents: Annotated[list[Identifier], Field(max_length=10)] = []
    max_rounds: Annotated[int, Field(ge=1, le=10)] = 3
    context: dict[Identifier, Annotated[str, StringConstraints(max_length=2000)] | int | float | bool] = {}

    @field_validator("agents")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("duplicate agents")
        return v

    @field_validator("context")
    @classmethod
    def _small(cls, v: dict[str, object]) -> dict[str, object]:
        if len(v) > 50:
            raise ValueError("too many context entries")
        return v
