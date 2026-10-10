# ShadowAPI Guard

Motor defensivo eBPF que descubre endpoints indocumentados (Shadow APIs), mapea tráfico HTTP/gRPC/GraphQL en tiempo real y previene fugas de PII y vulnerabilidades de autorización lógica (BOLA/IDOR) sin añadir latencia a la aplicación.

## Arquitectura

```
 Fuentes L7 (eBPF, Envoy, Kong)
        │
        ▼
 Reconstrucción (Rust)  ── Zero-Copy L7 / inferencia OpenAPI        → reconstructor/
        │
        ▼
 Detección BOLA/IDOR (Go) ── JWT vs. URI del recurso                → detector/
        │
        ▼
 Control plane (FastAPI) ── drift, reglas, dashboard                → control-plane/
        │                         ▲
        ▼                         └── Red Team Agent (fuzzing)
 Gateway Rate Limiter / WAF Sync ── enmascarado PII, bloqueo activo
```

## Funcionalidades

1. **Reconstrucción OpenAPI 3.1** e inferencia de esquemas en caliente; cálculo de *drift* vs. la especificación oficial.
2. **Detección BOLA** correlacionando claims JWT con variables dinámicas de la URI.
3. **Redacción de PII** en el flujo de red (tarjetas, credenciales, identificadores).
4. **Fuzzing continuo** de endpoints recién descubiertos vía `Red Team Agent`.

## Stack

| Capa | Tecnología |
|---|---|
| Kernel probe | Rust + eBPF (aya-rs) |
| Análisis de lógica | Go |
| Control plane | FastAPI (Python) |
| Series temporales | ClickHouse |
| Catálogo oficial | PostgreSQL |

## Estado

Esqueleto inicial. Implementado y probado:

- `reconstructor/` — normalización de rutas (`/users/42` → `/users/{id}`). `cargo test`
- `detector/` — regla BOLA JWT↔URI (la firma JWT **no** se verifica; se asume autenticación previa en el gateway). `go test ./...`
- `control-plane/` — `/healthz` y `/drift` (catálogo oficial aún en memoria). `uvicorn app.main:app`
- `deploy/docker-compose.yml` — ClickHouse y PostgreSQL para desarrollo.

Pendiente: sonda eBPF (aya-rs), ingesta a ClickHouse, catálogo en PostgreSQL, redacción PII, integración con Red Team Agent y sync con WAF.
