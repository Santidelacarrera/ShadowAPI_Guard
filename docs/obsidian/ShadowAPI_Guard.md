---
tipo: componente
nombre: ShadowAPI_Guard
rol: firewall-perimetral / api-gateway-de-entrada
repo: Santidelacarrera/ShadowAPI_Guard
lenguaje: python (FastAPI) · go · rust
estado: implementado-en-rama
organizacion: "[[empresa]]"
tags: [seguridad, gateway, waf, prompt-injection, multi-tenant, segundo-cerebro]
---

# ShadowAPI_Guard

Guardián de borde: ninguna petición llega a [[ContextRAG_Engine]] ni a [[MultiAgent_Consensus]] sin pasar por aquí.

## Conexiones
- Pertenece a: [[empresa]] (política de seguridad y datos de la organización que este perímetro aplica).
- Entrada: [[Nexus-Client-Portal]] (JWT o API key + cabecera obligatoria `X-Tenant`).
- Salida (reenvío firmado, HMAC-SHA256): [[ContextRAG_Engine]] · [[MultiAgent_Consensus]].
- Telemetría: eventos del perímetro → control plane de ShadowAPI (drift, Shadow APIs, alertas BOLA).

## Contrato de seguridad con los servicios internos
Los servicios internos **solo deben confiar en `X-Tenant-Id` si la firma `X-Guard-Signature` verifica** (`edge_gateway.signing.verify_guard_request`, tolerancia 60 s). Compartir `GUARD_SIGNING_KEY` solo con ellos.

## Decisiones perimetrales (en orden)
bans/higiene de ruta → rate limit → **401/403** (auth + tenant) → rate limit tenant → **404/405** (Shadow API) → scope → cuerpo/esquema (**413/415/400/422**) → **403** WAF/anti prompt-injection → reenvío.

## Notas
- Reglas heurísticas (EN/ES); ver límites en `edge-gateway/README.md`.
- Estado en memoria por proceso: con réplicas, mover límites/baneos a Redis.
- Auditoría sin payload: solo hash, tamaño y extractos cortos.

---

# Ejecución autónoma 2026-10-12 · Nexus Security & AI Lab

Alcance (solo defensivo): reglas de detección con tráfico sintético y pruebas de que no se bloquea tráfico legítimo. Cero payloads ofensivos. Rama: `feat/shadowapi-guard-autonomo-2026-10-12` → PR contra `main`.

## Tareas (con evidencia)
- [x] Reglas de detección ajustadas y probadas con corpus sintético inerte: 80/80 disparos mínimos detectados (`tests/fixtures/detection_triggers.jsonl`).
- [x] No bloquea tráfico legítimo: 0/41 curado, 0/54 negativos difíciles, 0/3000 generado (perfil `business`); informe determinista `edge-gateway/docs/DETECTION_REPORT.md` verificado en CI.
- [x] Perfiles `business`/`technical` y sobrescritura de reglas (`GUARD_PROFILE`, `GUARD_RULE_OVERRIDES`, `GET /__guard/rules`).
- [x] Política de fixtures (sin objetivos ni cadenas ofensivas completas) aplicada por `test_fixture_policy.py`.

## Definición de terminado
1. Tareas cumplidas con evidencia: ver arriba y `DETECTION_REPORT.md`.
2. Pruebas: `cd edge-gateway && python3 -m pytest tests` → `945 passed`; `cd control-plane && python3 -m pytest` → `43 passed`; `cd detector && go vet ./... && go test ./...` → ok; `cargo test --workspace` → ok (3 passed).
3. Seguridad/lint: `python3 -m mypy --strict src/edge_gateway` → `Success: no issues found in 20 source files`; `ruff check src tests scripts` → `All checks passed!`; `bandit -c .bandit -r edge-gateway/src control-plane/app gateway scripts` → 0 issues (alta/media/baja = 0). `python3 scripts/evaluate_detection.py --check` → `DETECTION_REPORT.md is up to date`. Humo por HTTP real 17/17 y contenedor Docker verificados en la sesión.
4. README: raíz y `edge-gateway/README.md` con instalación, pruebas, uso y límites.
5. Bitácora: abajo.
6. Pendientes para Santiago: abajo.

## Bitácora de decisiones
- 2026-10-13 · Reemplazar el corpus de pruebas con cargas de aspecto ofensivo por fixtures mínimos "trigger-minimal", sin objetivo ni utilidad, y hacerlo cumplir con un test. Motivo: regla "cero payloads ofensivos". El corpus antiguo no se movió a `_to_delete/` para no conservar esas cadenas; sigue en el historial git (commits f1c13c1/8540d0a).
- 2026-10-13 · Dos perfiles (`business` por defecto, `technical`). Motivo: 27/54 negativos difíciles se bloqueaban; un asistente técnico legítimo habla de SQL/shell.
- 2026-10-13 · SSRF a direcciones privadas pasa a "marcar" por defecto (override `{"ssrf.private": 8}` para bloquear). Motivo: falsos positivos; el backend debe aplicar su lista de salida permitida.
- 2026-10-13 · Reglas divididas (`pi.override` exige calificador/marcador) para reducir falsos positivos manteniendo recall medido.
- 2026-10-13 · Bind por defecto a 127.0.0.1 (`GUARD_BIND_HOST`); el Dockerfile usa 0.0.0.0. Motivo: no exponer servicios por defecto.
- 2026-10-13 · CI: ruff + comprobación del informe + job `security` con bandit. Motivo: lint/seguridad como puerta.
- 2026-10-13 · Paráfrasis de prompt injection no cubiertas se documentan como límite en lugar de añadir reglas. Motivo: preservar 0 falsos positivos y acotar el alcance de esta vuelta.
- 2026-10-13 · Nombre de rama con 2026-10-12 según la instrucción (fecha real 2026-10-13).

## Pendientes para Santiago
- Corpus ofensivos reales o Red Team activo requieren archivo de autorización escrita del dueño del sistema (no se usaron). El módulo Red Team del control plane (`control-plane/app/redteam.py`) solo exige `REDTEAM_ALLOWED_HOSTS`; considerar exigir autorización escrita.
- `govulncheck` bloqueado por la red (403); `cargo-audit` no completó; `semgrep`/`gosec` no instalados. Ejecutarlos donde haya red.
- Cambiar la rama por defecto de GitHub a `main`.
- Elegir `GUARD_PROFILE`/overrides por despliegue; medir FP/FN con tráfico real.
- Decidir si se añaden reglas para las paráfrasis listadas en `edge-gateway/README.md`.
- El CI nuevo (`security`, `edge-gateway`) no ha corrido en GitHub hasta este PR.
- Alinear rutas/esquemas reales de ContextRAG_Engine y MultiAgent_Consensus; la nota `[[empresa]]` debe existir en el vault.

## Riesgos conocidos
- Detección heurística: evasión por paráfrasis, otros idiomas o fragmentación; menciones educativas de frases de ataque se bloquean.
- SSRF privado solo se marca por defecto.
- Estado en memoria por proceso (límites/baneos) con réplicas.
