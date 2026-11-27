# Bloque 1, revisión 8: suite, sondeo, anillo y cierre (27-nov-2026)

Las tres correcciones de la 7.ª revisión (continuidad sin `uptime`, precedencia de la pérdida demostrada y
prueba controlada del paso de cierre) están verificadas funcionalmente y no se tocan. Sus evidencias
(`evidencias/bloque1/suricata-r7/`) y los originales se conservan sin cambios.

Esta revisión cierra lo que la 7.ª dejó sin diagnóstico. **No se inició el piloto final, ni las 49 h, ni
ataques ni campañas.** El laboratorio queda parado (§7).

Una sesión anterior empezó esta revisión (06:33–06:48 UTC). Sus pasadas «antes», con salida completa, son
`evidencias/bloque1/suite-r8/sondeo-antes*/` y se conservan tal cual. Su reproductor de carga se perdió
con su carpeta temporal: `tests/carga_sondeo.py` lo rehace, con 14 o 42 procesos de carga según el
factor, y queda en el repositorio.

## 1. El fallo de la suite que quedó sin diagnóstico

**El registro no se conservó: no se puede saber qué prueba falló.** Se recuperó todo lo que existe
(`evidencias/bloque1/suite-r8/r7-pasada-175s.txt`):

- comando: `cmd /c "python -m pytest -q -p no:cacheprovider tests ..." | Select -Last 1`;
- resultado: `1 failed, 334 passed, 38 subtests passed in 175.48s`, del 26-nov a las 21:28 UTC;
- árbol: f0f10e8 más lo que se comitió en 8328032.

Hay tres razones por las que no se puede identificar:

- `Select -Last 1` tiró la línea `FAILED ...` y la traza;
- `-p no:cacheprovider` no deja `lastfailed`;
- la suite no escribía ningún registro propio.

La pasada tardó 175 s, frente a 61 s la siguiente. Eso es compatible con las pruebas del sondeo que fallan
con carga (§2), pero **no lo demuestra**, y no se atribuye. Repetir 8328032 con carga (§3) solo muestra
qué pruebas de ese árbol fallan con carga.

**Desde esta revisión cada pasada guarda su registro completo**, se vea lo que se vea en la consola.
`tests/conftest.py` escribe `tests/_registros_pytest/<UTC>-<pid>/` (o `$CYBERFLOW_REGISTRO_PRUEBAS`) con:

- `informes.jsonl`: id, fase, duración, traza completa y salida capturada de cada prueba no superada;
- `resultados.tsv`: id, fase, resultado y duración de todas;
- `resumen.json`: totales, fallidas, duración, Python/pytest, plataforma, CPU, commit y si el árbol
  tenía cambios.

La consola termina con la línea `registro completo de esta pasada: <ruta>`. Ninguna carpeta se
sobrescribe; la carpeta raíz está en `.gitignore` y las pasadas que importan se copian a `evidencias/`.

Comprobación: una prueba que falla a propósito, en un fichero temporal ya borrado, quedó en
`informes.jsonl` con su traza (`AssertionError: mensaje de fallo`) y su salida, y en `resumen.json` con
`fallidas` y `cuentas`.

## 2. Pruebas intermitentes del sondeo y su reconexión

### 2.1 Reproducción (antes, código de r7)

Son `tests/test_sondeo_span.py`, con `-v -rA` y junit, en `suite-r8/sondeo-antes*/`:

| Carga | Pasadas | Fallidas | Pruebas que fallan |
|---|---|---|---|
| 14 procesos (1 por CPU) | 8 | 1 | `test_timeout_reconecta_y_registra_hueco` (antes-06) |
| 42 procesos (3 por CPU) | 7 completas | 3 | timeout (x3-03, x3-04); `descartes_usan_intervalo` y `margen_inicial` (x3-02) |

`antes-x3-08` quedó cortada al cerrarse aquella sesión. No es un fallo y no se cuenta.

### 2.2 Causa (de las trazas, no de porcentajes)

Cada prueba lanza el sondeo real con una ventana de reloj fija (`--hasta-epoch = ahora + 3 s`, o 4,6 s
en las de reconexión). Además exige que, dentro de esa ventana, el switch falso (otro proceso Python)
recorra su guion. Hay dos mecanismos:

1. **Plazo de conexión (timeout).** La prueba de timeout usa `--tiempo-max-respuesta-s 0.35`, para
   provocar el timeout en el segundo paso. El sondeo aplicaba ese mismo plazo al prompt inicial de cada
   sesión nueva.
   - En `antes-06`, la reconexión registra `conexion ok=False "sin prompt dentro del plazo"` porque el
     Python del switch falso nuevo tardó más de 0,35 s en arrancar. El retroceso pasa a 4 s y la ventana
     se acaba con 1 muestra (`assert 1 >= 2`).
   - En `x3-03` es la primera conexión la que falla.
   - Es un fallo del entorno de la prueba, no del sondeo. El defecto real es que el sondeo no distinguía
     abrir la sesión de responder a un comando.
2. **Ventana agotada.** Con 42 procesos no llega ninguna muestra a tiempo. Se ve en
   `muestras(eventos)[0]` → `IndexError` (x3-02, `margen_inicial`) y en `subprocess` → `TimeoutExpired`
   (x3-02, `descartes`).

### 2.3 Corrección (sin eliminar ni debilitar aserciones)

- **`operacion/sondeo_span.py` 1.1:**
  - `--tiempo-max-conexion-s` nuevo, para el prompt inicial y `terminal length 0` de cada sesión.
  - **Por omisión vale lo mismo que `--tiempo-max-respuesta-s`**, así que el lanzador y el laboratorio no
    cambian de comportamiento.
  - El valor queda registrado en el evento `arranque`.
- **`tests/test_sondeo_span.py`:**
  - `ejecutar()` exige una condición previa explícita: el guion del switch falso se recorrió entero, es
    decir, `peticiones_servidas ≥ pasos + 1` (el sondeo pidió la muestra siguiente al último paso, así
    que recibió la respuesta de este).
  - Si no se cumple, repite el escenario con ventanas de ×1, ×3 y ×9.
  - Si ni la mayor basta, la prueba **falla** con `el guion del switch falso no se completó…`, los
    intentos y los últimos eventos.
  - Las aserciones de cada prueba son las mismas y se aplican a una pasada que recorrió el escenario.
  - Las pruebas pasan `--tiempo-max-conexion-s 10`.

**Mutación:** con la reconexión rota a propósito (`dormir(1e9)` en lugar de reconectar), las dos pruebas
de reconexión **fallan** en las tres ventanas con el mensaje explícito. La condición previa no tapa una
reconexión rota. Salida en `suite-r8/mutacion-reconexion/sin-reconexion.txt`; el sondeo se restauró y se
comprobó con `diff`.

### 2.4 Resultado (después)

| Carga | Pasadas | Fallidas | Ventanas usadas |
|---|---|---|---|
| 14 procesos | 8 | **0** | ×1 en los 64 escenarios |
| 42 procesos | 8 | **0** | ×1 en los 64 escenarios |

Están en `suite-r8/sondeo-despues*/`, con `resumen.json` y salida completa, y los registros del
`conftest` en `suite-r8/registros-carga/`. Lo que cura es el plazo de conexión: en las 128 ejecuciones
del escenario bastó la primera ventana. La repetición con ventana mayor queda como garantía de que una
pasada incompleta no se confunde con un fallo del sondeo.

## 3. Suite completa con el código corregido

Se ejecutó con `tests/carga_sondeo.py --pruebas tests`, con la salida completa y junit en `suite-r8/suite-completa*/`
y el registro del `conftest` en `suite-r8/registros-suite/`:

| Árbol | Carga | Resultado | Duración |
|---|---|---|---|
| r8 sobre el bloque 3 local (91b9798 + cambios) | sin carga | **348 passed, 38 subtests passed** | 51 s |
| ídem | 42 procesos | **348 passed, 38 subtests passed** | 168 s (la condición de la pasada de 175 s de r7) |
| r7 (8328032), 3 pasadas | 42 procesos | 335 passed las 3 | 155, 101 y 146 s |

El árbol de r7 **no repite el fallo** con carga en 3 pasadas (`suite-r8/r7-arbol-8328032-x3/`). Las
pruebas del sondeo de ese árbol sí fallan con carga cuando se aíslan (§2.1, 4 de 15 pasadas), así que el
fallo es intermitente y depende de la carga, pero **sigue sin poder atribuirse a una prueba concreta**.
Desde r8 la próxima pasada que falle queda identificada (§1).

Al retomar la revisión se hizo una pasada adicional de la suite completa sobre el árbol que se va a
comitear (r8 sobre 91b9798): **348 passed, 38 subtests passed, 50,66 s**; registro
`suite-r8/suite-completa-codex/intento-03-verificado/` y
`suite-r8/registros-suite-codex/20261127T220446Z-35656/`. El `resumen.json` registra rc 0 y cero
fallos. Esta pasada verifica el árbol local combinado; no se atribuye al árbol antiguo de r7.

Se conservan también dos intentos de verificación en el sandbox de Windows:

1. `intento-01-sandbox`: se lanzó solo `test_sondeo_span.py` (11 pruebas) y las 11 dieron error de
   preparación por `PermissionError` al reabrir el directorio temporal de pytest. No llegaron a
   ejercitar el sondeo.
2. `intento-02-sandbox`: se lanzó la suite completa con otro `--basetemp`; 340 reportes dieron
   `passed` (incluidas subpruebas), 39 dieron
   `PermissionError` por la ACL de ese directorio y 7 fallaron porque Git Bash no pudo crear su
   `signal pipe` (Win32 error 5). Pytest terminó además con `PermissionError` al limpiar el temporal.
   Las 46 pruebas afectadas están identificadas en `registros-suite-codex/.../informes.jsonl`.

Son restricciones de acceso de los procesos del sandbox, no evidencia de un defecto funcional del
código. La misma suite, fuera del sandbox, dio rc 0. Los intentos fallidos, su salida íntegra y sus
registros quedan publicados junto a la pasada correcta. `tests/carga_sondeo.py` ahora recoge también
los `ERROR` de setup y los IDs impresos durante una sesión que aborte antes del resumen, y devuelve
rc 1 si alguna pasada falla.

Antes del commit se corrigió además el saneado de las 92 copias públicas previas: los `\\` escapados
de las trazas de Windows habían dejado el nombre de usuario y la ruta local en 60 ficheros. Los
originales privados no se tocaron. El barrido posterior da 0 nombres de usuario/rutas personales,
0 claves privadas y 0 campos de contraseña; los 39 junit XML y los JSON/JSONL se abren correctamente.

Se conservan todos los intentos fallidos (`sondeo-antes*/`, `mutacion-reconexion/` y
`r7-pasada-175s.txt`). Las pasadas correctas posteriores no los sustituyen.

## 4. «tcpdump-ring»: qué unidad estaba inactiva

**Ninguna real.** La frase «`tcpdump-ring` inactivo» de la 7.ª revisión salió de un guion improvisado de
comprobación de parada, que no está en el repositorio y ejecutaba
`systemctl is-active tcpdump-ring suricata`. En Sensor1 **no existe ninguna unidad `tcpdump-ring`**
(`LoadState=not-found`), y `systemctl is-active` responde `inactive` para una unidad inexistente. Así que
la frase no decía nada del anillo. Fue un error de mi comprobación, no un estado del laboratorio.

Comprobado en solo lectura el 27-nov a las 07:38 UTC, sin cambiar ningún servicio:

- **`ppi-motor-capture.service`** (V1, permanente):
  - `active (running)` desde el 23-nov a las 23:14 UTC, `NRestarts=0`, `enabled`, PID 1391.
  - `tcpdump -i ens37 -n -s 0 -U -B 65536 -Z tcpdump -w /var/lib/ppi-motor-capture/live-%Y%m%d%H%M%S.pcap -G 5`.
  - El fichero principal dice `-G 15`; el drop-in `etapa4.conf` lo cambia a `-G 5`. El drop-in
    `etapa4-primer-pcap.conf` arregla el grupo del primer fichero.
  - El anillo tiene 222 ficheros, 27 MB y el último PCAP tenía 0 s. La limpieza la hace
    `cyberflow-limpieza.timer` (más de 15 min).
  - `0 packets dropped by kernel`. Lo informa tcpdump con el SIGUSR1 que envía cada 30 s
    `cf-tcpdump-estadisticas.timer` (V1).
- **Relación con V2:**
  - `captura/archivar_v2.py` copia los PCAP cerrados de ese anillo (`ANILLO = /var/lib/ppi-motor-capture`).
  - Guarda en el manifiesto las 40 últimas líneas del journal de `ppi-motor-capture`.
  - Declara huecos (`salto_nombres`, `salto_paquetes`, `borrado_antes_de_copiar`) si el anillo se
    interrumpe. V2 no tiene tcpdump propio en Sensor1.
- **Preflight:**
  - Ya comprobaba la unidad correcta: `sensor1_servicios` exige
    `systemctl is-active ppi-motor-capture suricata cyberflow-limpieza.timer`.
  - La sesión anterior añadió `sensor1_anillo`, porque «active» no basta: el PCAP más reciente debe
    tener menos de 15 s (3 rotaciones). Va con su prueba `tests/test_preflight_anillo.py`, que ejecuta
    el fragmento real con un `ssh` falso (3 casos).
  - Lo revisé y lo ejecuté entero desde el bastión, en solo lectura, con una ventana ficticia
    (`suite-r8/anillo/preflight-solo-lectura.jsonl`): todo `ok`, `sensor1_anillo` «último PCAP hace
    1 s».
  - Solo falla `exclusion_v1`, como debe: para una ventana ficticia no hay regla `*@` (la crea el
    lanzador).
- **Comprobación de parada versionada:**
  - `operacion/comprobar_parado.sh` sustituye al guion improvisado.
  - Exige que no haya procesos V2 en ningún equipo y que la infraestructura de V1 siga en pie
    (`ppi-motor-capture`, Suricata, limpieza, anillo fresco).
  - Muestra `tcpdump-ring` solo como dato informativo (`not-found`).

## 5. Lectura de la EVE en el paso de cierre: defecto de memoria corregido

Al medir el paso para el punto 4 apareció un defecto. `suricata_stats.py ventana` guardaba en memoria
**todos** los eventos stats de la EVE dedicada desde el 25-nov y filtraba la ventana después. Con
449 MB de EVE, el proceso llegaba a **1,04 GB** de memoria residente. Sensor1 tiene 7,9 GB, y esa
memoria crece con la edad de la EVE.

La EVE dedicada **no rota**. `/etc/logrotate.d/suricata` cubre `/var/log/suricata/*.json`, pero no la
subcarpeta `v2/`. Al final de las 49 h el proceso habría pasado de 2 GB.

**Corrección:** `eventos_stats(rutas, desde, hasta)` guarda solo los eventos del intervalo mientras lee,
y `ventana()` le pasa `[desde − margen, hasta + margen]`. Sigue leyendo línea a línea. `extraer` no
cambia. Se probó en Sensor1 con una copia temporal en `/tmp/r8`, borrada después; el código desplegado
no se tocó. Se ejecutó sobre la EVE real y las cuatro ejecuciones
(`suite-r8/eve-lectura-viejo-nuevo.txt`):

| Ejecución | Versión vieja | Versión nueva | Salida |
|---|---|---|---|
| VD2 | 9,28 s, 1 043 MB | 6,86 s, 33 MB | idéntica (`cmp`), sha 33628441… = r7 |
| VD3 | 9,03 s, 1 043 MB | 6,54 s, 33 MB | idéntica, d56c5480… = r7 |
| VD4 | 9,02 s, 1 043 MB | 6,41 s, 33 MB | idéntica, 57345950… = r7 |
| VD6 | 8,92 s, 1 044 MB | 6,38 s, 32 MB | idéntica, 19c7d4a6… = r7 |

Los cuatro dictámenes de Suricata quedan igual (`presente`). Las 44 pruebas de Suricata y del cierre
pasan.

## 6. Pendientes explícitos del bloque 4

Siguen **pendientes**, y no los cierra esta revisión:

### 6.1 V4-a. Integración del paso de stats en un cierre completo

- **Dónde:** en la primera ejecución real `lanzar_v2.sh` → `cerrar_v2.sh` con el código vigente,
  dentro del bloque 4. Es el piloto integrado final de 30 min, que **necesita tu autorización**. Ninguna
  prueba dirigida la sustituye, porque lo que falta es el paso dentro del cierre real, con el
  archivador recién parado.
- **Criterio de aceptación (todos):**
  1. `cerrar_v2.sh` termina y su registro tiene `suricata_stats_ventana rc=0`.
  2. Existe `registros/suricata-stats-ventana-<ID>.jsonl` y su sha256 coincide con el que da
     `suricata-stats-ventana.json`.
  3. Hay una muestra en o antes del inicio, y otra en o después del fin a ≤ 16 s
     (`muestra_despues_s` entre 0 y 16).
  4. Hay como mucho 5 intentos, y solo se repite por «sin muestra en o después del fin».
  5. C9 se decide con ese fichero y no queda None por falta de la muestra posterior.
  6. `reproducir_dictamen.py`, aplicado a la ventana publicada, da el mismo C9 y el mismo dictamen
     global.
- Si sale `rc 3` o `rc 4` es **falta de evidencia, no aprobación**. El piloto queda `indeterminado` y
  se diagnostica antes de las 49 h.

### 6.2 V4-b. Rendimiento del cierre con el volumen previsto de EVE

- **Volumen previsto.** La EVE dedicada no rota (§5), así que al cerrar las 49 h medirá:
  - el tamaño al empezar (449 MB el 27-nov a las 07:39 UTC);
  - más 6,8 MB/h hasta el inicio (sin tráfico V2: 2,4 de flow y 3,7 de stats);
  - más 49 h × 12,3 MB/h (el ritmo medido en VD2–VD6, con tráfico).
  - Si se empieza dentro de 2 días, son unos 0,78 + 0,60 ≈ **1,4 GB**. La prueba se dimensiona con
    margen ×2: **2,8 GB**.
- **Dónde:** en el bloque 4, antes del piloto integrado. Es una prueba dirigida en Sensor1, sin
  captura V2: `suricata_stats.py ventana` sobre una EVE de prueba de 2,8 GB, construida concatenando la
  EVE real en `/tmp` (no en `/var/log`), con el manifiesto de VD6. Mientras dura, el anillo y Suricata
  siguen en marcha, como en un cierre real.
- **Criterio de aceptación:**
  1. Cada lectura tarda ≤ 60 s. Hoy son 14 ms/MB, unos 40 s para 2,8 GB.
  2. El paso completo, con `--reintentos 4 --espera 6`, tarda ≤ 5 min en el peor caso.
  3. Memoria residente máxima ≤ 256 MB, que no dependa del tamaño (hoy 33 MB).
  4. La salida es igual byte a byte que leyendo solo la EVE original.
  5. Durante la lectura, `ppi-motor-capture` sigue con `0 packets dropped by kernel` y el Δ de
     `kernel_drops` de Suricata es 0.
- Si no se cumple el criterio 1 o el 2, hay dos salidas:
  - leer desde el final o buscar por desplazamiento (bisección sobre los timestamps de `stats`, que van
    en orden);
  - o rotar `v2/`, con decisión tuya (§8).

## 7. Despliegue y estado del laboratorio

- **No desplegué el código de esta revisión.** Sensor1, el bastión y Clientes tienen **91b9798**: es el
  bloque 3 que desplegó la otra sesión, cuyo reanálisis ya terminó («barrido hecho»).
  - Desplegar ahora sustituiría ese código por un árbol sin sus cambios, o lo mezclaría.
  - Los cambios de esta revisión no cambian el comportamiento del laboratorio: el plazo de conexión
    vale igual por omisión y `ventana` da la misma salida.
  - Se despliegan junto con el bloque 3 al empezar el bloque 4, y se verifican por hash.
- `operacion/comprobar_parado.sh`, el 27-nov a las 07:5x UTC (`suite-r8/anillo/comprobar-parado-*.jsonl`):
  - sin candado ni procesos V2 en el bastión, Sensor1, Clientes y srv-dmz;
  - DC1 sin unidades `cf-v2-dns-*`;
  - V1 en pie y anillo fresco;
  - `parado: si`.
- Repetí el comprobador **en solo lectura** a las 21:40 UTC, sin tocar servicios: `parado: si`, sin
  procesos V2 ni candado; `ppi-motor-capture`, Suricata y la limpieza activos, PCAP más reciente de
  0 s y `tcpdump-ring` con `LoadState=not-found`.
  Registro: `suite-r8/anillo/comprobar-parado-20261127T214051Z.jsonl`.

## 8. Lo que necesita una decisión tuya

- **Rotación de `/var/log/suricata/v2/eve.json`.** Hoy no rota.
  - Para las 49 h no es un problema de espacio: crece unos 0,6 GB, y Sensor1 tiene 16 GB libres.
  - Sí afecta al tiempo de lectura del cierre (§6.2).
  - Añadirla exige sudo, y obliga a que `ventana` lea también el fichero rotado (`rutas` admite varios).
  - **Recomiendo no rotarla durante las 49 h**: menos `copytruncate` para el archivador. Si el criterio
    de §6.2 falla, se resuelve leyendo desde el final.
- El piloto final y las 49 h **siguen sin autorización de inicio**.

## 9. Ficheros

- Código:
  - `operacion/sondeo_span.py` (1.1);
  - `operacion/suricata_stats.py`;
  - `operacion/preflight_lab.sh` (`sensor1_anillo`);
  - `operacion/comprobar_parado.sh` (nuevo).
- Pruebas:
  - `tests/test_sondeo_span.py`;
  - `tests/conftest.py` (registro);
  - `tests/test_preflight_anillo.py` (nuevo);
  - `tests/carga_sondeo.py` (reproductor, no es una prueba).
- Evidencia: `evidencias/bloque1/suite-r8/` (pasadas antes y después, mutación, suite completa,
  registros del `conftest`, anillo, preflight, parada, lectura de la EVE y `r7-pasada-175s.txt`).
- `docs/PENDIENTES.md`: filas 73–78.
