"""Control plane: orchestrates security rules and exposes API drift."""
from fastapi import FastAPI

app = FastAPI(title="ShadowAPI Guard Control Plane")

OFFICIAL = {"/users/{id}", "/users/{id}/orders"}  # TODO: load from PostgreSQL catalog


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/drift")
def drift(observed: list[str]) -> dict:
    """Return observed templated paths missing from the official spec (Shadow APIs)."""
    return {"shadow": sorted(set(observed) - OFFICIAL)}
