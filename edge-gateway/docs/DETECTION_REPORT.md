# Informe de detección con tráfico sintético

Producto de **Nexus Security & AI Lab**. Generado por `python scripts/evaluate_detection.py` (semilla `20261012`, 3000 solicitudes legítimas generadas por perfil). Todo el material es sintético, inerte y determinista; la política de fixtures está en `tests/fixtures/README.md` y se hace cumplir en CI.

Los tiempos de escaneo no se incluyen aquí (varían según la máquina); el script los imprime por consola.

## Perfil `business`

| Medida | Resultado |
|---|---|
| Disparos que activan su regla con el resultado esperado | 80/80 |
| Tráfico legítimo curado bloqueado | 0/41 (marcado: 3) |
| Negativos difíciles bloqueados | 0/54 (marcado: 15) |
| Tráfico legítimo generado bloqueado | 0/3000 (marcado: 0) |
| Evasión (4 frases × 8 transformaciones) aún bloqueada | 32/32 |

| Categoría | Detectados | Total |
|---|---:|---:|
| anomaly | 1 | 1 |
| command_injection | 13 | 13 |
| header_injection | 1 | 1 |
| obfuscation | 2 | 2 |
| path_traversal | 6 | 6 |
| prompt_injection | 31 | 31 |
| sql_injection | 10 | 10 |
| ssrf | 4 | 4 |
| structured | 5 | 5 |
| template_injection | 2 | 2 |
| xss | 3 | 3 |
| xxe | 2 | 2 |

## Perfil `technical`

| Medida | Resultado |
|---|---|
| Disparos que activan su regla con el resultado esperado | 80/80 |
| Tráfico legítimo curado bloqueado | 0/41 (marcado: 3) |
| Negativos difíciles bloqueados | 0/67 (marcado: 26) |
| Tráfico legítimo generado bloqueado | 0/3000 (marcado: 0) |
| Evasión (4 frases × 8 transformaciones) aún bloqueada | 32/32 |

| Categoría | Detectados | Total |
|---|---:|---:|
| anomaly | 1 | 1 |
| command_injection | 13 | 13 |
| header_injection | 1 | 1 |
| obfuscation | 2 | 2 |
| path_traversal | 6 | 6 |
| prompt_injection | 31 | 31 |
| sql_injection | 10 | 10 |
| ssrf | 4 | 4 |
| structured | 5 | 5 |
| template_injection | 2 | 2 |
| xss | 3 | 3 |
| xxe | 2 | 2 |

## Falsos positivos conocidos del perfil estricto (`business`)

Texto legítimo de un asistente **técnico** que el perfil estricto bloquea a propósito; el perfil `technical` los deja pasar (marcados). No se ocultan: son el precio de bloquear fragmentos de shell/SQL en un asistente de negocio.

| Regla parecida | Ejemplo sintético |
|---|---|
| `cmd.chain` | cd app && curl -I https://example.com to check the response headers. |
| `cmd.chain` | I ran ssh-keygen; ssh deploy@host failed with permission denied. |
| `cmd.chain_weak` | Run `echo start; ls -la /var/log` and paste the output. |
| `cmd.windows` | Open a terminal and run cmd /c dir to list the files. |
| `sqli.union` | What is the difference between SELECT a FROM t1 UNION SELECT a FROM t2 and UNION ALL? |
| `sqli.tautology` | Fix: WHERE name = 'x' OR name = 'y' returns duplicates, how do I dedupe? |
| `sqli.stacked` | In my migration script I run: BEGIN; insert into audit_log values (1); COMMIT; |
| `sqli.timing` | How do I use sleep(5) in PHP to throttle requests? |
| `sqli.timing` | How do I simulate latency with pg_sleep(1) in a test query? |
| `pi.chat_template` | What does the [INST] marker mean in Llama prompt templates? |
| `ssti.dunder` | In Jinja, {{ obj.__class__.__name__ }} prints the class name; is there a cleaner way? |

## Reglas relajadas por el perfil `technical`

`cmd.chain`, `cmd.chain_weak`, `cmd.subst`, `cmd.windows`, `pi.chat_template`, `sqli.login_bypass`, `sqli.stacked`, `sqli.tautology`, `sqli.timing`, `sqli.union`, `ssti.dunder`, `ssti.expr`.

Nunca se relajan: inyección de prompt (salvo `pi.chat_template`), exfiltración, metadatos cloud (`ssrf.metadata`), `cmd.revshell`, `cmd.log4shell`, `cmd.sensitive_file`.

Reglas totales: 52; con al menos un disparo de prueba: 51.
