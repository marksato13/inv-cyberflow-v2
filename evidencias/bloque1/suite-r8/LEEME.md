# suite-r8: evidencia de la 8.ª revisión (`docs/BLOQUE1-REVISION-8-2026-11-27.md`)

| Carpeta / fichero | Qué es | Código |
|---|---|---|
| `r7-pasada-175s.txt` | Lo único que se conservó de la pasada de r7 con «1 failed» sin identificar | f0f10e8 + lo de 8328032 |
| `sondeo-antes/` | 8 pasadas de `test_sondeo_span.py` con 14 procesos de carga (1 fallida: `antes-06`) | r7 |
| `sondeo-antes-x3/` | 8 pasadas con 42 procesos (3 fallidas: x3-02, x3-03, x3-04; x3-08 cortada al cerrarse la sesión, sin XML) | r7 |
| `mutacion-reconexion/` | Pruebas de reconexión con el sondeo sin reconexión a propósito: deben fallar | r8 + mutación |
| `sondeo-despues/`, `sondeo-despues-x3/` | 8 + 8 pasadas con 14 y 42 procesos, con `resumen.json` | r8 |
| `registros-carga/` | Registro de `tests/conftest.py` de cada pasada de `sondeo-despues*` | r8 |
| `suite-completa/`, `suite-completa-x3/` | Suite completa sin carga y con 42 procesos | r8 + bloque 3 local (91b9798) |
| `registros-suite/` | Registro de `tests/conftest.py` de esas dos pasadas | ídem |
| `r7-arbol-8328032-x3/` | Suite completa del árbol de r7 (8328032) con 42 procesos, 3 pasadas | 8328032 |
| `suite-completa-codex/`, `registros-suite-codex/` | Dos intentos con errores de acceso del sandbox y una suite completa correcta fuera de él; salida, junit y registro por prueba, sin sustituir los fallos | r8 + bloque 3 local |
| `anillo/` | Preflight completo en solo lectura (ventana ficticia) y comprobación de parada | r8 |
| `eve-lectura-viejo-nuevo.txt` | `suricata_stats.py ventana` vieja frente a nueva sobre la EVE real: tiempo, memoria y sha | 91b9798 / r8 |

Las pasadas «antes» las hizo una sesión anterior el 27-nov entre las 06:38 y las 06:48 UTC. Las demás son
de las 07:3x a las 08:1x UTC. Los `.txt` son la salida completa de pytest (`-v -rA`), y los `.xml` el junit
de la misma pasada.
Las pasadas `suite-completa-codex/` son posteriores (21:41–22:05 UTC). El segundo intento abortó
durante `pytest_sessionfinish`; su registro del `conftest` sí contiene los 46 fallos y errores. Los
originales sin sanear de esos tres intentos están en `CYBERFLOW/privado-r8/suite-r8-original/`.

**Saneado para publicar.** En todos los ficheros de texto de esta carpeta se sustituyó:

- la ruta del repositorio por `<REPO>`;
- la carpeta del usuario de Windows por `<HOME>`;
- el usuario por `<usuario>`;
- el nombre del equipo por `<equipo>`.

En los junit XML se usan `[REPO]`, `[HOME]`, `[usuario]` y `[equipo]` para mantener válido el XML. Se
incluyen las barras escapadas de las trazas de Windows. Se normalizaron los saltos de línea a LF y
se convirtieron a UTF-8 siete salidas con caracteres de Windows para que se puedan leer en GitHub.
No se cambió el contenido de las pruebas ni sus resultados. Los originales sin sanear están fuera
del repositorio, en el equipo del autor.
