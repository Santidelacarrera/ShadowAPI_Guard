"""Intentionally vulnerable demo API used as the local test target. NEVER deploy this."""
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Demo API (vulnerable by design)")

USERS = {
    1: {"id": 1, "name": "Ana", "email": "ana@example.cl", "rut": "12.345.678-5", "card": "4111 1111 1111 1111"},
    2: {"id": 2, "name": "Beto", "email": "beto@example.cl", "rut": "11.111.111-1", "card": "5500 0000 0000 0004"},
}
USERS[3] = {"id": 3, "name": "Cata", "email": "cata@example.cl", "rut": "9.999.999-3", "card": "4000 0000 0000 0002"}
ACCOUNTS = {1: {"id": 1, "iban": "CL-1", "owner": "Ana"}, 2: {"id": 2, "iban": "CL-2", "owner": "Beto"}}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/users/{uid}")  # documented, but no ownership check -> BOLA
def get_user(uid: int):
    if uid not in USERS:
        raise HTTPException(404)
    return USERS[uid]


@app.get("/users/{uid}/orders")  # documented
def orders(uid: int):
    return [{"order": 1, "user": uid}]


@app.get("/accounts/{aid}/statements")  # documented, no ownership check either (BOLA, found by learning)
def statements(aid: int):
    return [{"account": aid, "month": "2024-01", "balance": 100 * aid}]


@app.get("/admin/debug")  # NOT documented: leaks config and PII
def debug():
    # bandit B105 accepted: deliberately vulnerable demo data
    return {"env": "prod", "db_password": "hunter2", "support": "ops@example.cl", "sample_card": "4111111111111111"}  # nosec B105


@app.get("/legacy/accounts/{aid}")  # NOT documented: leaks other users' data, fragile
def account(aid: str):
    if "'" in aid or "%27" in aid:
        raise HTTPException(500, "psycopg error: syntax error at or near \"'\"")
    if not aid.isdigit() or int(aid) not in ACCOUNTS:
        raise HTTPException(404)
    return ACCOUNTS[int(aid)]
