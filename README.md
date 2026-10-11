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
8. **Allow-list** — `PUT /allowlist` (`{method, path, reason}`) marca un endpoint no documentado como aceptado (health checks, herramientas internas): deja de ser *shadow*, no genera avisos y no entra en las reglas de bloqueo. `GET`/`DELETE /allowlist` para listar y retirar.
9. **Operación** — `/dashboard` (página estática; pide la API key en el navegador), `/metrics` (Prometheus), logs JSON, `ALERT_WEBHOOK_URL` (Slack-compatible) para shadow nuevo / BOLA / introspección / hallazgo grave, paginación en `/alerts` y `/findings`, migraciones aditivas de columnas al arrancar. Con `API_KEY` toda la API exige `X-API-Key`. El dashboard se sirve con CSP estricta (scripts/estilos por hash), y la API limita tamaños (spec ≤ 4 MiB, rutas ≤ 4 KiB, lotes ≤ 5000 eventos).

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

Sonda eBPF real (Linux, root, `tracefs` montado): `cd probe/ebpf && cargo +nightly build --release`, después
`sudo shadowapi-probe attach --object <objeto> [--libssl /usr/lib/x86_64-linux-gnu/libssl.so.3]`. `scripts/ebpf_smoke.sh` lo comprueba de extremo a extremo.

`bpf-linker` debe coincidir con el LLVM de rustc nightly. La receta que funcionó aquí (nightly con LLVM 23, sin LLVM del sistema):
```bash
SYS=$(rustc +nightly --print sysroot); DRV=$(ls $SYS/lib | grep -o 'rustc_driver-[0-9a-f]*' | head -1)
LLVM=$(ls $SYS/lib | grep -o 'libLLVM-[0-9]*-rust-[^ ]*\.so' | head -1 | sed 's/^lib//; s/\.so$//')
RUSTFLAGS="-C link-arg=-L$SYS/lib -C link-arg=-l$DRV -C link-arg=-l$LLVM -C link-arg=-Wl,-rpath,$SYS/lib" \
  cargo +nightly install bpf-linker --no-default-features --features llvm-23,no-llvm-linking
```

## Estado de verificación

**Verificado en este entorno**
- **Docker Compose real** (`docker compose up --build --wait`): PostgreSQL 16, **ClickHouse 24.8 real**, control plane, detector, gateway y worker Red Team arrancan sanos, y `docker compose --profile e2e run --rm e2e` pasa las 26 comprobaciones. Se comprobó contra el servidor real el DDL de ClickHouse, el TTL, las columnas nuevas y `/stats`. El perfil `sim` (sonda Rust reconstruida en Docker) alimenta el pipeline.
  - En el sandbox el proxy TLS intercepta los builds; se resolvió con un override local de compose que inyecta el CA (`pip`/`cargo`), sin tocar los Dockerfiles. Fuera de un proxy así no hace falta.
- `pytest`: 42 tests (incluye propiedades con Hypothesis sobre el redactor) contra SQLite **y PostgreSQL 16 real**; `go test`/`go vet` (aprendizaje BOLA, JWT HS256/RS256, servidor); `cargo test --workspace`.
- **Dashboard** abierto en Chromium real con la CSP activa: renderiza todas las tablas sin errores de consola.
- Las reglas **Kong** (3.7, modo declarativo) y **Envoy** (1.31, bootstrap mínimo + filtro RBAC exportado) se cargaron en los gateways reales: bloquean con 403 solo lo esperado, pasan el resto al upstream y Kong limita con 429. La prueba destapó un bug (las rutas regex de Kong deben empezar por `~/`), ya corregido y con test. La exportación Envoy no incluye `rate_limit` (necesita configuración de local_ratelimit/RLS).
- Las reglas **nginx exportadas** se cargaron en un nginx 1.24 real: `nginx -t` correcto, 403 en endpoints bloqueados, 429 tras la ráfaga y el resto intacto.
- Los tests de propiedades encontraron y corrigieron una fuga real (tarjeta seguida de otros dígitos); correr contra ClickHouse real destapó que `/stats` devolvía enteros como strings (corregido).

- **Sonda eBPF real** (`scripts/ebpf_smoke.sh`, kernel 6.18 del contenedor, root): el objeto se enlaza con `bpf-linker`, **pasa el verificador del kernel**, se adjunta (tracepoints `sys_enter_write/sendto` + uprobe `SSL_write`) y reporta peticiones HTTP reales de `curl`, **incluido HTTPS en claro antes de cifrar**. El smoke test también detectó y corrigió un bucle: la sonda capturaba sus propios envíos al detector (ahora ignora su PID).

**No verificado**
- La sonda eBPF solo se probó en este kernel y con tráfico local de `curl`/Python; no hay pruebas en otros kernels, bajo carga ni con otros clientes TLS. No hay medición de su sobrecarga.
- El workflow de GitHub Actions (nunca corrió en GitHub; el job `ebpf` está en `continue-on-error`).
- `deploy/k8s` solo se validó como YAML.
- `mask_pii`, `rate_limit` y `block` por API solo se aplican de extremo a extremo en el gateway demo (nginx se verificó con su propia config exportada).

**Rendimiento medido** (`scripts/bench.py`, 4 vCPU compartidas; son microbenchmarks de user-space, **no** miden la sobrecarga del kernel ni de la aplicación)
- Redacción de un JSON de 1,4 KB con 5 tipos de PII: ≈170 µs.
- `ingest.process` (SQLite, ClickHouse simulado): ≈360 µs/evento ≈ 2.700 eventos/s por núcleo. Es el cuello de botella del pipeline; escala horizontalmente (réplicas del control plane).
- `Detector.Check` en Go: ≈4 µs/petición.
La promesa de "sin latencia" se refiere a que el análisis es pasivo y fuera de la ruta de la aplicación; no hay una medición de ello en este repositorio.

## Límites conocidos

- La sonda ve HTTP/1.x en claro y, con `--libssl`, TLS cuando la aplicación usa OpenSSL **dinámico**. Lee siempre una ventana fija de 512 B del buffer de usuario: si el buffer es más corto y acaba justo antes de una página no mapeada, esa captura se pierde (no Go/BoringSSL/rustls estáticos). Solo captura la petición: en eventos eBPF `status` es 0, por lo que el detector no aprende de ellos (el middleware sí rellena el estado). Trunca a 512 B.
- Un número de 13–19 dígitos válido por Luhn en cualquier ventana se enmascara aunque no sea una tarjeta: se prefiere sobre-redactar a filtrar.
- La redacción es por patrones: nombres, direcciones y texto libre no se detectan.
- Los esquemas protobuf/GraphQL no se infieren (solo protocolo y operación); la inferencia JSON es de cuerpos HTTP+JSON.
- El aprendizaje BOLA asume que la mayor parte del tráfico inicial es legítimo; un atacante que domine el tráfico durante el aprendizaje podría impedir la promoción de una regla (no puede revertir una ya aprendida).
- El rate limiter del WAF demo es en memoria y por proceso.
