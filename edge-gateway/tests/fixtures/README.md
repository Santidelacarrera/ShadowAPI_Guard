# Fixtures de detección (sintéticos)

Todo el material de esta carpeta es **fabricado, inerte y determinista**. Es parte del producto de
**Nexus Security & AI Lab** y existe solo para medir las reglas defensivas del gateway.

| Archivo | Contenido |
|---|---|
| `detection_triggers.jsonl` | Fragmentos *mínimos y sin objetivo* que deben disparar una regla concreta (`rule`) con un resultado esperado (`block`/`flag`). |
| `legit_corpus.jsonl` | Tráfico legítimo (`legit`) y *negativos difíciles* (`hard_negative`: se parecen a una regla pero son legítimos, con `near_miss_of`). `profile: "technical"` = debe pasar con el perfil técnico (es un falso positivo conocido del perfil estricto por defecto). |

## Política de fixtures (la hace cumplir `tests/test_fixture_policy.py`)
1. **Mínimos**: solo el fragmento que activa la regla; sin payloads completos ni cadenas de explotación funcionales.
2. **Sin objetivo**: sin credenciales, secretos, datos reales, rutas sensibles reales ni acciones destructivas; los archivos y tablas son sintéticos.
3. **Hosts reservados**: `*.invalid`, `example.*`, loopback/privados/link-local genéricos; nunca dominios reales.
4. **Sin derivación de datos reales**: nombres, RUT, tarjetas y correos son ficticios.

Los corpus ofensivos reales (p. ej. conjuntos públicos de payloads) **no** se incluyen: requieren autorización escrita del dueño del sistema (ver «Pendientes para Santiago» en la nota del proyecto).
