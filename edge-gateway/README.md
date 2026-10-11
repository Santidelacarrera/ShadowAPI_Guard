# ShadowAPI Guard · Edge Gateway

Firewall perimetral y API gateway de entrada del ecosistema "Segundo Cerebro". Todo el tráfico de `Nexus-Client-Portal` pasa por aquí **antes** de llegar a `ContextRAG_Engine` o `MultiAgent_Consensus`.

```
Nexus-Client-Portal ──▶ PerimeterMiddleware (filtro) ──▶ forwarder FastAPI ──▶ ContextRAG_Engine
                          auth · tenant · shadow API        contexto firmado     MultiAgent_Consensus
                          schema · WAF · anti-injection
                                  │
                                  └──▶ auditoría (JSON log + buffer) ──▶ control plane de ShadowAPI (POST /events)
```

* **Filtro** (`perimeter.py`): middleware ASGI. Decide todo; nada llega al forwarder sin pasar por él. Si el filtro falla por un bug, responde 500 (falla cerrado). El forwarder se niega a reenviar una petición que no lleve el contexto del filtro.
* **Forwarder** (`app.py`, `proxy.py`): elimina todo lo que controla el cliente e inyecta contexto limpio y firmado.

## Orden de decisión

| # | Comprobación | Resultado |
|---|---|---|
| 1 | IP/tenant baneado, ruta con evasión (`%2e`, `//`, `..`, NUL, no ASCII), query string, preflight CORS | 429 / 400 / 204·405 |
| 2 | Límite de tasa pre-auth por IP | 429 |
| 3 | **Autenticación** (JWT HS256/RS256 o `X-API-Key`) **+ cabecera `X-Tenant` obligatoria** | **401** credenciales ausentes/inválidas · **403** tenant ausente, malformado, desconocido o ≠ al del token |
| 4 | Límite de tasa por tenant | 429 |
| 5 | **Shadow API / método no permitido** frente a la superficie documentada | 404 · 405 (+ `Allow`) |
| 6 | Scope requerido por la ruta (token ∩ política del tenant) | 403 |
| 7 | Cuerpo: tamaño (también chunked), `Content-Type`, JSON estricto (sin claves duplicadas, NaN, enteros enormes, profundidad), esquema Pydantic `extra=forbid` | 413 · 415 · 400 · 422 |
| 8 | **WAF + anti prompt-injection** sobre todas las cadenas y claves | 403 `request_blocked` |
| 9 | Reenvío con contexto firmado | respuesta del upstream |

Las respuestas de error son genéricas (`{"error", "request_id"}`): nunca dicen qué regla saltó ni por qué falló la credencial. Credenciales inválidas para un tenant real o inexistente son indistinguibles. Un anónimo que sondea una ruta inexistente recibe 401, no 404.

## Detección de amenazas (`threats.py`, `normalize.py`)
Cada cadena se normaliza (URL/HTML decoding, NFKC, caracteres invisibles, homóglifos cirílicos/griegos, leetspeak, saltos de línea) y se compara con reglas con severidad 1-10; también se analizan claves de objeto y bases64 decodificados. Puntuación = severidad máxima + 1 por cada regla distinta adicional (máx. +3); **bloquea a partir de `GUARD_BLOCK_THRESHOLD` (7)**; por debajo se reenvía marcado `X-Guard-Verdict: flagged` y se audita.

Cubre prompt injection (EN/ES: anulación de instrucciones, cambio de rol, exfiltración del prompt, plantillas de chat, jailbreaks, exfiltración por URL/markdown), inyección de comandos, SQL/NoSQL, path traversal, SSRF, XXE, XSS, SSTI, CRLF, contaminación de prototipos, cadenas sobredimensionadas y NUL.

**Anomalías:** línea base de tamaño por (tenant, ruta) (marca, no bloquea), y baneo temporal de escáneres: el comportamiento hostil autenticado se acota a (tenant, IP) para que un cliente defectuoso no bloquee a otros tras la misma NAT; el no autenticado se acota a la IP.

## Propagación segura
El upstream recibe solo `accept`, `accept-language`, `content-type`, `user-agent` del cliente más:
`X-Tenant-Id`, `X-Auth-Subject`, `X-Auth-Scopes`, `X-Auth-Method`, `X-Request-Id`, `traceparent`, `X-Audit-Trace`, `X-Guard-Verdict`, `X-Guard-Timestamp`, `X-Guard-Body-Sha256`, `X-Guard-Signature` (HMAC-SHA256 sobre tenant, request id, timestamp, método, ruta y hash del cuerpo). `Authorization`, cookies, `X-Forwarded-*` y cualquier `X-Tenant*`/`X-Guard-*` del cliente se descartan. Los upstreams **deben verificar la firma** antes de confiar en el tenant:

```python
from edge_gateway.signing import verify_guard_request
tenant = verify_guard_request(request.headers, request.method, request.url.path, body, key=GUARD_SIGNING_KEY)
if tenant is None:
    raise HTTPException(401)   # no pasó por el guard, fue manipulada o es un replay (> 60 s)
```
Incluye circuit breaker por upstream (503 inmediato tras 5 fallos), timeouts (504), 502 sin detalles internos y tope de tamaño de respuesta.

## Auditoría
Un evento JSON por decisión (`allowed`, `flagged`, `auth_failed`, `forbidden`, `shadow_api`, `method_not_allowed`, `schema_anomaly`, `threat_blocked`, `rate_limited`, `banned`, `malformed`, `upstream_error`) con `request_id`, tenant, sujeto, ruta, hallazgos (regla, severidad, JSON pointer, extracto corto) y SHA-256 del cuerpo. **Nunca se guarda el payload**; las rutas se registran sin query y con ids colapsados. Se reenvían (sin cuerpos) al control plane de ShadowAPI (`GUARD_EVENTS_URL`), y `GET /__guard/audit|metrics|routes` (cabecera `X-Admin-Key`; 404 si no coincide) los expone.

## Configuración (variables de entorno)
`GUARD_TENANTS_JSON` (o `GUARD_TENANTS_FILE`): `{"acme": {"api_keys_sha256": ["…"], "scopes": ["rag:query","consensus:run","consensus:read"], "rate_limit_per_minute": 300}}` · `GUARD_UPSTREAM_RAG`, `GUARD_UPSTREAM_CONSENSUS` · `GUARD_SIGNING_KEY` (≥ 32 B) · `GUARD_JWT_SECRET` (HS256, ≥ 32 B) o `GUARD_JWT_ALGORITHM=RS256` + `GUARD_JWT_PUBLIC_KEY` · `GUARD_JWT_ISSUER`, `GUARD_JWT_AUDIENCE` · `GUARD_ADMIN_API_KEY` · `GUARD_BLOCK_THRESHOLD`, `GUARD_MAX_BODY_BYTES`, `GUARD_PROBE_THRESHOLD`, `GUARD_BAN_SECONDS`, `GUARD_PREAUTH_RATE_PER_MINUTE`, `GUARD_UPSTREAM_TIMEOUT_SECONDS` · `GUARD_CORS_ORIGINS` · `GUARD_TRUSTED_PROXIES` · `GUARD_EVENTS_URL`, `GUARD_EVENTS_API_KEY`.
**Falla cerrado**: sin firma/clave suficientes, sin método de autenticación, sin tenants o con upstreams inválidos, el servicio no arranca. El JWT debe llevar `exp`, `sub` y `tenant_id` (+ `scope`/`scopes`).

## Superficie documentada
`POST /v1/rag/query` → ContextRAG_Engine · `POST /v1/consensus/run` y `GET /v1/consensus/runs/{run_id}` → MultiAgent_Consensus (`routes.py`, `schemas.py`). Todo lo demás es, por definición, una Shadow API.

## Ejecutar y probar
```bash
pip install -e '.[dev]'
pytest                          # 332 pruebas: bloqueo no autorizado, suplantación de tenant, Shadow APIs, corpus de ataques y legítimo, firma, circuit breaker…
mypy --strict src/edge_gateway
python -m edge_gateway          # con las variables anteriores; escucha en :8080
python scripts/smoke.py         # prueba black-box por HTTP contra un gateway en marcha
cd ../deploy && docker compose --profile edge up -d --build   # gateway + mocks de upstream + control plane
```

## Límites conocidos
* Las reglas son **heurísticas**: encarecen el ataque, no vuelven inmune al modelo. Hay falsos positivos posibles en preguntas técnicas legítimas (p. ej. `; curl …` en una consulta sobre instalación); el umbral y las reglas son ajustables. Un atacante determinado puede evadirlas con paráfrasis (otros idiomas, instrucciones repartidas en varios campos o mensajes).
* El estado (límites de tasa, baneos, línea base) es **en memoria y por proceso**: con varias réplicas no se comparte (haría falta Redis).
* No termina TLS (colóquese tras un balanceador/ingress) y confía en `X-Forwarded-For` solo desde `GUARD_TRUSTED_PROXIES`.
* JWT: HS256 o RS256 con clave estática; no hay descubrimiento/rotación JWKS. Sin revocación de tokens.
* El cuerpo se bufferiza (hasta el límite) para poder inspeccionarlo; no hay streaming de peticiones ni WebSockets.
* Las rutas documentadas están definidas en código, no en un OpenAPI externo.
