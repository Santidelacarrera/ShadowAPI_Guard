# ShadowAPI Guard

Motor defensivo que descubre endpoints indocumentados (Shadow APIs), reconstruye su especificación, detecta BOLA/IDOR, redacta PII antes de almacenar, verifica los endpoints con deriva y sincroniza reglas con un WAF/gateway.

```
 Sonda L7: eBPF (Rust/aya) ─┐
 o middleware de simulación ┴─▶ Detector (Go) ──▶ Control plane (FastAPI) ──▶ ClickHouse (eventos redactados)
        (gateway/capture.py)    BOLA: JWT vs URI      │  ▲   │              └─▶ PostgreSQL (catálogo, observados,
                                reglas aprendidas     │  │   └▶ Dashboard         esquemas inferidos, hallazgos, alertas)
                         Red Team Agent ◀─ drift ─────┤  │      Webhooks · /metrics
                         (fuzzing seguro)  hallazgos ─┘  │
                                                      ▼  │
                          WAF sync ──▶ Gateway/WAF (JSON) · nginx · Envoy · Kong
```

## Componentes

| Dir | Qué hace | Tecnología |
|---|---|---|
| `probe/ebpf` | Programa eBPF: tracepoints `sys_enter_write/sendto` + uprobe `SSL_write` (TLS con OpenSSL dinámico); copia los primeros 512 B de lo que parezca una petición HTTP/1.x a un ring buffer | Rust, aya-ebpf (nightly + bpf-linker) |
| `probe/userspace` | Carga el objeto eBPF, lee el ring buffer, reconstruye peticiones y las envía al detector. Modo `simulate` (sin kernel): reproduce capturas | Rust, aya |
| `reconstructor` | Parser HTTP/1.x y *templating* de rutas (`/users/42` → `/users/{id}`) | Rust |
| `detector` | Servicio HTTP: BOLA con reglas estáticas **y aprendidas**, verificación de firma JWT (HS256 / RS256 vía JWKS), descarta `Authorization` | Go |
| `control-plane` | Catálogo OpenAPI, ingesta, redacción, inferencia de esquemas, drift de rutas y de esquema, borrador OpenAPI, Red Team, reglas WAF, dashboard, métricas | FastAPI, SQLAlchemy |
| `gateway` | API demo (vulnerable a propósito) + middleware de captura (sonda simulada) + WAF que aplica reglas | ASGI |
| `deploy` | `docker-compose.yml` (stack completo) y `k8s/shadowapi.yaml` (ejemplo) | |

## Funcionalidades

1. **Catálogo y drift** — `PUT /catalog/{spec}` (OpenAPI 3.x JSON/YAML, con esquemas de request/response y `$ref`). `GET /drift` devuelve:
   - `shadow`: endpoints observados que no casan con el catálogo;
   - `unused`: documentados pero nunca vistos;
   - `schema_drift`: **campos presentes en el tráfico y ausentes del esquema documentado**, marcando los que son PII.
   No cuentan: respuestas 404/405/501, rutas con caracteres de ataque y el tráfico del propio Red Team.
2. **Reconstrucción de OpenAPI** — se infieren esquemas JSON (tipos, formatos, `required` como intersección, marcas `x-pii`) a partir de los bodies **ya redactados** (nunca se guardan valores). `GET /openapi/draft?scope=shadow|all` exporta un OpenAPI 3.1. `GET /schemas` los lista.
3. **Ingesta y redacción** — `POST /events`. Redacta tarjetas (Luhn, también pegadas a otros dígitos), RUT (dígito verificador), emails, JWT/Bearer, API keys y claves `password`/`token`/`api-key`… (en rutas, query strings y bodies, JSON de forma estructural). ClickHouse primero y PostgreSQL después: si ClickHouse falla → 502 sin registrar nada (reintento seguro). Límite de tasa (`EVENTS_RATE_LIMIT`), retención (`CLICKHOUSE_TTL_DAYS`, 90 por defecto).
4. **BOLA** — reglas estáticas (`BOLA_RULES_FILE`) y **aprendidas**: una tupla (ruta, parámetro, claim) se promueve a regla cuando, con ≥20 peticiones 2xx y ≥3 identidades distintas, el parámetro coincide con el claim ≥90 % de las veces. Las violaciones no diluyen una regla ya aprendida y los recursos compartidos (`/products/{id}`) no se aprenden. Firma JWT verificada con `JWT_HS256_SECRET` o `JWKS_URL` (tokens sin firma válida se tratan como no autenticados). `LEARN_STATE_FILE` persiste las reglas; `GET /rules` en el detector las lista.
5. **GraphQL / gRPC** — se detecta el protocolo y la operación (`mutation:CreateUser`, `Charge`) y se guardan en ClickHouse; las consultas de introspección GraphQL generan alerta.
6. **Red Team** — `POST /redteam/scan` y worker continuo (`python -m app.worker`, re-escanea cuando cambia el esquema del endpoint; estado en PostgreSQL). Comprueba: acceso sin credenciales, PII expuesta, métodos peligrosos anunciados, enumeración de IDs, errores por inyección y, con ≥2 `identities` (`token` + `owned_ids`), **BOLA confirmado entre identidades**. Solo contra `REDTEAM_ALLOWED_HOSTS`, solo lectura salvo `allow_unsafe`. Los hallazgos se deduplican.
7. **WAF** — `GET /waf/rules?format=json|nginx|envoy|kong`; `POST /waf/sync` empuja al gateway demo. Reglas: `block` (shadow con hallazgos high/critical, o todos con `WAF_SHADOW_POLICY=block`), `monitor`, `rate_limit` (rutas con alertas BOLA), `mask_pii` (solo gateway demo).
8. **Operación** — `/dashboard` (página estática; pide la API key en el navegador), `/metrics` (Prometheus), logs JSON, `ALERT_WEBHOOK_URL` (Slack-compatible) para shadow nuevo / BOLA / introspección / hallazgo grave, paginación en `/alerts` y `/findings`, migraciones aditivas de columnas al arrancar. Con `API_KEY` toda la API exige `X-API-Key`.

## Ejecutar

```bash
cd deploy && docker compose up -d --build --wait
docker compose --profile e2e run --rm e2e        # verifica todo el pipeline (26 comprobaciones)
docker compose --profile sim run --rm probe-sim  # sonda Rust en modo simulación
# dashboard: http://localhost:8000/dashboard  (API_KEY por defecto de desarrollo: dev-key)

(cd control-plane && pip install -r requirements.txt && python -m pytest)   # TEST_DATABASE_URL=postgresql+psycopg://... para PostgreSQL
(cd detector && go test ./...)
cargo test --workspace
python scripts/bench.py
```

El e2e espera un stack recién levantado (una segunda ejecución falla porque el WAF ya bloquea los endpoints de la primera).

En compose el detector **verifica firmas** (`JWT_SECRET`, por defecto de desarrollo); las capturas de `probe/sample-traffic.ndjson` llevan tokens sin firma y se tratan como no autenticadas.

Sonda eBPF real (Linux, root): `cd probe/ebpf && cargo +nightly build --release` (requiere `bpf-linker`), después
`sudo shadowapi-probe attach --object <objeto> [--libssl /usr/lib/x86_64-linux-gnu/libssl.so.3]`.

## Estado de verificación

**Verificado en este entorno**
- `pytest`: 36 tests (incluye propiedades con Hypothesis sobre el redactor) contra SQLite **y PostgreSQL 16 real**; `go test`/`go vet` (aprendizaje BOLA, JWT HS256/RS256, servidor); `cargo test --workspace`.
- `scripts/e2e.py` (26 comprobaciones) con procesos reales: PostgreSQL 16 + detector Go (firmas HS256 verificadas) + control plane + gateway + sonda Rust en `simulate`.
- Las reglas **nginx exportadas** se cargaron en un nginx 1.24 real: `nginx -t` correcto, los endpoints bloqueados devuelven 403, el rate limit 429 tras la ráfaga y el resto sigue igual.
- Los tests de propiedades encontraron y corrigieron una fuga real (tarjeta seguida de otros dígitos).

**No verificado**
- `docker compose up`, los Dockerfiles, healthchecks y el workflow de CI: no había daemon de Docker. El job `e2e` de CI es el primer test real; el job `ebpf` está en `continue-on-error`.
- **ClickHouse real**: el e2e local usa `scripts/fake_clickhouse.py`. El DDL, el TTL y las migraciones de columnas de ClickHouse no se ejecutaron contra el servidor.
- **eBPF**: `probe/ebpf` (tracepoints + uprobe TLS) pasa `cargo +nightly check`, pero `bpf-linker` no se pudo instalar: no se enlazó, no pasó el verificador del kernel y no se adjuntó nunca. `probe/userspace` en modo `attach` tampoco se ejecutó.
- Las exportaciones **Envoy y Kong** solo se comprueban en estructura (JSON/YAML); no se cargaron en esos gateways. `deploy/k8s` solo se validó como YAML.
- `mask_pii`, `rate_limit` y `block` por API solo se aplican de extremo a extremo en el gateway demo.

**Rendimiento medido** (`scripts/bench.py`, 4 vCPU compartidas; son microbenchmarks de user-space, **no** miden la sobrecarga del kernel ni de la aplicación)
- Redacción de un JSON de 1,4 KB con 5 tipos de PII: ≈170 µs.
- `ingest.process` (SQLite, ClickHouse simulado): ≈360 µs/evento ≈ 2.700 eventos/s por núcleo. Es el cuello de botella del pipeline; escala horizontalmente (réplicas del control plane).
- `Detector.Check` en Go: ≈4 µs/petición.
La promesa de "sin latencia" se refiere a que el análisis es pasivo y fuera de la ruta de la aplicación; no hay una medición de ello en este repositorio.

## Límites conocidos

- La sonda ve HTTP/1.x en claro y, con `--libssl`, TLS cuando la aplicación usa OpenSSL **dinámico** (no Go/BoringSSL/rustls estáticos). Solo captura la petición: en eventos eBPF `status` es 0, por lo que el detector no aprende de ellos (el middleware sí rellena el estado). Trunca a 512 B.
- Un número de 13–19 dígitos válido por Luhn en cualquier ventana se enmascara aunque no sea una tarjeta: se prefiere sobre-redactar a filtrar.
- La redacción es por patrones: nombres, direcciones y texto libre no se detectan.
- Los esquemas protobuf/GraphQL no se infieren (solo protocolo y operación); la inferencia JSON es de cuerpos HTTP+JSON.
- El aprendizaje BOLA asume que la mayor parte del tráfico inicial es legítimo; un atacante que domine el tráfico durante el aprendizaje podría impedir la promoción de una regla (no puede revertir una ya aprendida).
- El rate limiter del WAF demo es en memoria y por proceso.
