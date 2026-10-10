# ShadowAPI Guard

Motor defensivo que descubre endpoints indocumentados (Shadow APIs), mapea tráfico HTTP en tiempo real, detecta BOLA/IDOR, redacta PII antes de almacenar y sincroniza reglas con un WAF/gateway.

```
 Sonda L7: eBPF (Rust/aya) ─┐
 o middleware de simulación ┴─▶ Detector (Go) ──▶ Control plane (FastAPI) ──▶ ClickHouse (eventos redactados)
        (gateway/capture.py)    BOLA: JWT vs URI      │  ▲                └─▶ PostgreSQL (catálogo, endpoints
                                                      │  │                     observados, hallazgos, alertas)
                         Red Team Agent ◀─ drift ─────┤  │
                         (fuzzing seguro)  hallazgos ─┘  │
                                                      ▼  │
                                      WAF sync ──▶ Gateway/WAF (block · rate_limit · mask_pii)
```

## Componentes

| Dir | Qué hace | Tecnología |
|---|---|---|
| `probe/ebpf` | Programa eBPF: tracepoints `sys_enter_write/sendto`, copia los primeros 512 B de cada escritura que parezca una petición HTTP/1.x a un ring buffer | Rust, aya-ebpf (nightly + bpf-linker) |
| `probe/userspace` | Carga el objeto eBPF, lee el ring buffer, reconstruye peticiones y las envía al detector. Modo `simulate` (fallback sin kernel): reproduce capturas desde un fichero | Rust, aya |
| `reconstructor` | Parser HTTP/1.x y *templating* de rutas (`/users/42` → `/users/{id}`) | Rust |
| `detector` | Servicio HTTP: correlaciona claims JWT con variables de la URI (BOLA), **descarta el header Authorization** y reenvía eventos saneados | Go |
| `control-plane` | Catálogo OpenAPI, ingesta, redacción PII, *drift*, alertas, Red Team, reglas WAF | FastAPI, SQLAlchemy |
| `gateway` | API demo (vulnerable a propósito) + middleware de captura (sonda simulada) + WAF que aplica reglas | ASGI |
| `scripts/e2e.py` | Prueba de flujo completo contra un stack levantado | Python |

### Flujo y garantías

1. **Catálogo** — `PUT /catalog/{spec}` guarda en PostgreSQL las operaciones de un OpenAPI 3.x (JSON/YAML). Los parámetros se normalizan a `{id}`.
2. **Ingesta** — `POST /events` (lotes). Cada evento se templatiza, se **redacta** (tarjetas con Luhn, RUT con dígito verificador, emails, JWT/Bearer, API keys, claves tipo `password`/`token`…, también en query string y bodies JSON), y se inserta en ClickHouse (`api_events`). Primero ClickHouse y después PostgreSQL: si ClickHouse falla se responde 502 y no queda nada registrado, así que el reintento es seguro.
3. **Drift** — `GET /drift`: `shadow` = endpoints observados que no casan con el catálogo; `unused` = documentados pero nunca vistos. No cuentan para el drift: respuestas 404/405/501, rutas con caracteres de ataque (`'`, `<`…) y tráfico del propio Red Team.
4. **BOLA** — el detector compara el claim (`sub`) con el parámetro de la ruta (reglas por defecto para `/users/{id}…`; personalizables con `BOLA_RULES_FILE`, JSON `[{"Template","Param","Claim"}]`). Las peticiones rechazadas (≥400) no son violación. El sujeto se almacena solo como hash.
5. **Red Team** — `POST /redteam/scan` (y el worker continuo `python -m app.worker`) prueba cada endpoint con deriva: acceso sin credenciales, exposición de PII, métodos peligrosos anunciados, enumeración de IDs (IDOR) e inyecciones/errores filtrados. **Solo contra hosts listados en `REDTEAM_ALLOWED_HOSTS`**, y solo métodos de lectura salvo `allow_unsafe=true`.
6. **WAF** — `GET /waf/rules` genera reglas (`block` para shadow con hallazgos high/critical —o todos con `WAF_SHADOW_POLICY=block`—, `monitor` para el resto, `rate_limit` para rutas con alertas BOLA, `mask_pii` global); `POST /waf/sync` las empuja a `WAF_URL/__waf/rules`.
7. **Auth** — si `API_KEY` está definida, toda la API (control plane y `PUT /__waf/rules`) exige `X-API-Key`.

## Ejecutar

```bash
# stack completo (PostgreSQL, ClickHouse, control plane, detector, gateway demo, worker Red Team)
cd deploy && docker compose up -d --build --wait
docker compose --profile e2e run --rm e2e        # verifica todo el pipeline
docker compose --profile sim run --rm probe-sim  # sonda Rust en modo simulación

# tests unitarios
(cd control-plane && pip install -r requirements.txt && python -m pytest)   # TEST_DATABASE_URL=postgresql+psycopg://... para usar PostgreSQL
(cd detector && go test ./...)
cargo test --workspace
```

Credenciales por defecto de compose son solo de desarrollo (`API_KEY`, `POSTGRES_PASSWORD`, `CLICKHOUSE_PASSWORD` se pueden sobrescribir).

### Sonda eBPF real

```bash
cd probe/ebpf && cargo +nightly build --release          # requiere bpf-linker (cargo install bpf-linker)
sudo cargo run -p shadowapi-probe -- --detector http://localhost:8081 attach --object probe/ebpf/target/bpfel-unknown-none/release/probe-ebpf
```

## Estado de verificación (honesto)

Verificado en este entorno:
- `pytest` (17 tests) contra SQLite **y contra PostgreSQL 16 real**; `go test`/`go vet`; `cargo test --workspace`.
- Flujo completo (`scripts/e2e.py`, 18 comprobaciones) con procesos reales: PostgreSQL 16 + detector Go + control plane + gateway + sonda Rust en modo `simulate`.
- `docker compose config` valida el compose y sus perfiles.

**No verificado:**
- `docker compose up`: el entorno de desarrollo no tenía daemon de Docker, así que las imágenes y healthchecks no se han construido ni ejecutado. El job `e2e` de `.github/workflows/ci.yml` está pensado para hacerlo.
- **ClickHouse real**: en el e2e local se usó `scripts/fake_clickhouse.py` (emulación de la interfaz HTTP). El DDL y las consultas no se han ejecutado contra ClickHouse.
- **Sonda eBPF**: `probe/ebpf` pasa `cargo +nightly check` (tipos/API de aya-ebpf), pero no se pudo instalar `bpf-linker`, así que no se enlazó, ni pasó el verificador del kernel, ni se adjuntó. Es la pieza con más riesgo.

## Límites conocidos

- La sonda ve solo HTTP/1.x **en claro**; TLS exigiría uprobes sobre `SSL_write` (pendiente). Tampoco captura la respuesta, así que `status` es 0 en eventos eBPF (el middleware sí lo rellena), y trunca a 512 B.
- El detector **no verifica la firma del JWT**: asume autenticación previa en el gateway.
- gRPC/GraphQL: se tratan como POST sobre su ruta; no hay inferencia de esquemas Protobuf/JSON (la inferencia de OpenAPI se limita a rutas+métodos).
- Rutas con literales distintos de los ids numéricos/UUID/ObjectId (p. ej. `/users/alice`) se comparan como literales con el catálogo (casan si el catálogo tiene un parámetro en esa posición).
- El rate limiter del WAF demo es en memoria y por proceso.
