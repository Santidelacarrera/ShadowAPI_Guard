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
