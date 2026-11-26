# Bloque 1 — 6.ª revisión (26-nov-2026): suficiencia temporal de Suricata, C9 frente a C7 y alcance de lo publicado

Atiende la revisión de la publicación de Suricata R5. **No se inició** el piloto final ni las 49 h, no
se capturó nada nuevo y no se tocaron SPAN ni búferes. Los originales y los complementos r4 y r5 se
conservan sin cambios. El reanálisis se hizo sobre copias nuevas (Sensor1
`~/cyberflow-v2/reanalisis/2a3478b/`). El laboratorio queda parado.

Código: **2a3478b** (desplegado y verificado por hash: bastión, Sensor1 y clientes con 0 diferencias;
`registro_dns_v2.py` de DC1 sin cambios, sha256 `f4d17e4d…`).

## 1. Suficiencia temporal de las estadísticas de Suricata

**Defecto.** `capture.kernel_drops` es un contador acumulado, así que el Δ entre dos muestras solo
cuenta lo descartado entre ellas. En r5, C9 tomaba el Δ entre la primera y la última muestra del recorte
del archivador, y todas esas muestras son interiores al periodo. Los bordes quedaban sin observar: entre
0,06 y 6,6 s al principio y al final de cada ejecución. Con una sola muestra, el Δ salía 0 y se aceptaba.
Es decir, una evidencia insuficiente se daba por «0 descartes».

**Regla nueva** (`operacion/suricata_stats.py`, `evaluar(eventos, desde, hasta)`). El periodo
`[inicio, fin]` sale del `manifiesto.json` del archivador. Solo queda certificado si se cumplen las
tres condiciones:

| Condición | Valor | Por qué |
|---|---|---|
| Cobertura | una muestra en o antes de `inicio` y otra en o después de `fin` | El Δ entre dos muestras que acotan el periodo incluye todo lo que pasó dentro. Puede sumar hasta un intervalo de fuera en cada extremo, lo que solo atribuye de más y nunca oculta un descarte |
| Huecos | ≤ 16 s entre muestras consecutivas (2 × `stats.interval` de 8 s) | Tolera una escritura retrasada. En las 41 h de la EVE dedicada (25–26-nov, 19 742 muestras) el intervalo máximo fue 8,0 s. Un hueco mayor significa que la salida de stats se detuvo y que no se puede afirmar continuidad |
| Continuidad | \|Δuptime − Δt\| ≤ 2 s (el uptime va en segundos enteros) | Un salto indica que el proceso se reinició, aunque el uptime nuevo no sea menor |

Cada caso da un resultado distinto:

- Sin cobertura, con un hueco o con una sola muestra, el estado es `insuficiente`. Su `delta_kernel_drops` es None (el Δ observado se guarda aparte, como información) y C9 queda en None: **falta evidencia, nunca 0**.
- Un reinicio da `reinicio`, que hace fallar C9.
- `ausente` y `sin_eventos` se mantienen como en r5.

**De dónde salen las muestras que acotan el periodo.** El recorte del archivador no las lleva. Están en
la EVE dedicada completa de Sensor1 (`/var/log/suricata/v2/eve.json`, sin rotar desde el 25-nov
00:18:46). El subcomando nuevo `suricata_stats.py ventana --manifiesto …` extrae los eventos `stats`
de `[inicio − 30 s, fin + 30 s]` en `pruebas/<ID>/registros/suricata-stats-ventana-<ID>.jsonl`:

- `cerrar_v2.sh` lo ejecuta antes de `revisar_criterios` y lo reintenta si la muestra posterior al fin aún no se ha escrito (rc 3);
- es una lectura local en Sensor1, así que no cruza la red durante una captura;
- los eventos `stats` no llevan direcciones ni metadatos de terceros (barrido de IP y MAC hecho).

**Para las cuatro ejecuciones no hizo falta capturar nada nuevo.** La EVE dedicada conserva las
muestras que las acotan, y se leyeron sin modificarla:

| Ejecución | Muestra anterior al inicio | Posterior al fin | Muestras usadas | Hueco máximo | Δ kernel_drops |
|---|---|---|---|---|---|
| VD2 | 6,272 s antes | 3,384 s después | 230 | 8,003 s | 0 |
| VD3 | 2,012 s antes | 7,075 s después | 230 | 8,005 s | 0 |
| VD4 | 2,894 s antes | 6,464 s después | 230 | 8,004 s | 0 |
| VD6 | 1,366 s antes | 7,938 s después | 230 | 8,003 s | 0 |

**Vigía: antigüedad admisible de la lectura** (`operacion/vigia_v2.py`):

- La última muestra `stats` leída puede tener como mucho 20 s (`ANTIGUEDAD_MAXIMA_S`): 2 intervalos de 8 s más 4 s de latencia de `ssh` + `tail`.
- Si es más vieja, la lectura es `obsoleta`. El valor se conserva en `kernel_drops_leido`, pero `kernel_drops` queda en None. Así la supervisión no cuenta como completa y el dictamen no la toma como «sin descartes».
- Se registra `stats_antiguedad_s`.
- El vigía de VD2–VD6 no registraba la marca de tiempo de la muestra. Reconstruida desde la EVE, la muestra más vieja que leyó tenía 7,66 s (VD3), así que ninguna de las 24 lecturas habría sido obsoleta.

## 2. Descartes de Suricata: protocolo, C9, vigía y dictamen, conciliados

**Defecto.** En r5, un Δ > 0 de Suricata en C9 tomaba el valor de C7 («se cuantifica y C7 decide»).
Pero C7 mide la cobertura de las transacciones del generador en el **PCAP del anillo** (tcpdump, con
bytes ≥ 95 %). No dice nada de los paquetes que Suricata dejó de procesar, y son esos los que forman
el EVE del que salen las ventanas (C11). C7 verdadero sustituía, sin justificación, a la evidencia del
procesamiento de Suricata.

**Ahora:**

| Pieza | Descartes de Suricata | Evidencia ausente, insuficiente u obsoleta |
|---|---|---|
| PROTOCOLO §10, C9 | Δ > 0 o reinicio = **fallo**; C7 no lo decide. Para el switch, la NIC y tcpdump se mantiene «se cuantifica y C7 decide», porque C7 mide en ese mismo PCAP si la pérdida tocó al tráfico experimental | Falta evidencia (None) |
| `revisar_criterios.suricata` | `ok False`, con la nota «no lo decide C7» y el valor de C7 solo informativo | `ok None` |
| Vigía (supervisión periódica, cada 300 s) | Un aumento invalida la supervisión (`kernel_drops` → `perdida_en_sensor`) y un reinicio también (`reinicio_suricata`) | `sin_datos`: no completa la supervisión |
| `estado_global` | `criterio:C9` o `supervision:con_invalidaciones` → **`no_aprobada`** | `falta:criterio:C9` → `indeterminada` |

**Un incremento posterior a la última supervisión periódica** no lo ve el vigía, pero sí C9. C9 cubre
hasta la muestra posterior al fin, así que un descarte en los últimos segundos aparece en su Δ y el
dictamen sale `no_aprobada`. Lo comprueba una prueba: todas las supervisiones en 0 y un descarte en la
muestra posterior al fin.

## 3. `dictamen_casos.py`: salida dentro del origen

**Defecto.** En el reanálisis r5 di `--salida` dentro de `--pruebas`. `copiar()` recorre el origen con
`rglob` y encontraba lo que iba copiando, así que la copia se anidó. Borré solo esa copia mía, nueva.

**Corrección.** `comprobar_salida(origen, salida)` resuelve las dos rutas con `Path.resolve()` y, antes
de copiar nada, rechaza tres casos:

- `salida == origen`;
- `origen in salida.parents`;
- una salida que ya existe.

`main` y `copiar` la llaman. Las pruebas (`tests/test_dictamen_casos_salida.py`) cubren:

- salida dentro, igual al origen o escrita con rodeos `..`: comprueban el rechazo y que **no se creó ningún fichero**;
- `copiar` directo hacia dentro;
- una salida fuera: se acepta y no se anida.

Las pruebas no reproducen la copia recursiva: la salida se rechaza antes de crear nada.

## 4. Qué valores publicados deciden el dictamen y qué trazas son privadas

La 5.ª revisión (§5) y `entradas-r4/LEEME.md` decían «ninguno decide el dictamen» y «no intervienen en
el dictamen». **Era inexacto.** Lo que no decide el dictamen son los campos que cuentan el anillo
completo, listados en `DEPENDEN_DEL_TRAFICO_AJENO`: denominadores totales, bytes por VLAN, picos,
reordenaciones, `inventario_ips` y `sensor/paquetes`. Pero varios valores que **sí** lo deciden se
publican como valores del laboratorio, y su traza original es privada o irrepetible.
`reproducir_dictamen.py` (comprobación A) recalcula el dictamen desde esos valores; no los verifica de
forma independiente.

| Valor publicado que decide | Dónde decide | Traza original | Comprobación independiente |
|---|---|---|---|
| Lecturas del switch: `output drops` de Gi2/0/19 (`sondeo-span.jsonl`, supervisión) y estado del enlace | `espejo`, C9, supervisión | Consola del switch en el momento; no se conserva otra traza | No |
| Contadores de Sensor1 (`rx_missed_errors`, softnet) y de tcpdump (`contadores-lab-*.txt`) | C9 | Lecturas puntuales de la NIC y del proceso | No |
| `descartados_nucleo` de tcpdump en srv-dmz (`extremo-captura.json`) | `calidad_extremo` | Salida de tcpdump al pararse | No |
| Relojes y NTP (`preflight-lab.jsonl`, `relojes-*.txt`), desfases de la supervisión | C10, supervisión | Lecturas puntuales de `chrony`/`date` | No |
| Volumen (`volumen.jsonl`, tamaños en `manifiesto.json`) | C12 | Tamaño del PCAP y del EVE **completos**, privados (tráfico y metadatos de terceros) | No; el sha256 de los ficheros privados está en `SHA256SUMS-privados` |
| Recuentos de `nft` de la exclusión de V1 (`exclusion-v1.json`) | C13, `exclusion_v1` | Contadores del cortafuegos en el momento | No |
| Manifiestos del generador y del archivador (inicio, fin, huecos EVE/PCAP) | `generador`, `archivador`, periodo de C9 | Ficheros originales en Sensor1 y clientes | Coherencia interna; los huecos se cuentan sobre el anillo completo |
| Eventos `stats` de Suricata (`suricata-stats-*.jsonl`, `suricata-stats-ventana-*.jsonl`) | C9 (Suricata), supervisión | EVE dedicada completa, privada | Parcial: se publican los eventos `stats` originales sin cambios, y la supervisión se contrasta con ellos (24/24). Que no falte ningún evento solo se ve en la EVE completa |
| Copias del espejo, extremo, DNS, cobertura y extracción **de la población experimental** | `calidad_*`, C7, C11 | Extractos publicados (release `bloque1-r4-2026-11-26`) | **Sí** (comprobación B, `recalcular_desde_capturas.py`) |

Siguen siendo privados:

- el anillo y el EVE completos;
- la clave HMAC de las MAC (Sensor1 `~/cyberflow-v2/privado/clave-mac`);
- la correspondencia de las IP sustituidas;
- los JSON con IP ajenas (gestión de B1).

## 5. Dependencias y pruebas

- **Programas** (`operacion/`, `captura/`, `extraccion/`): Python 3.12 o posterior, solo biblioteca estándar. Las VM del laboratorio no tienen dependencias instaladas.
- **Pruebas** (`tests/`): además, **pytest**. `test_contraste_dns_recortadas.py` lo importa, y la suite usa subtests.
  - Usado aquí: Python 3.14.3 y pytest 9.0.3 en Windows 11.
  - `python -m unittest discover -s tests` **no** ejecuta la suite completa (261 de 310: no recoge las pruebas escritas para pytest).
  - Comando completo, desde la raíz del repositorio:

```
python -m pip install pytest
python -m pytest -q -p no:cacheprovider tests
```

Resultado con 2a3478b: **310 passed, 38 subtests passed**. Pruebas nuevas de esta revisión:

- `tests/test_suricata_stats.py`, que se rehízo con 19 pruebas:
  - suficiencia: una sola muestra, solo interiores, huecos, sin periodo, uptime discontinuo;
  - ventana;
  - C9: Δ > 0 con C7 verdadero da fallo; un incremento tras la última supervisión da `no_aprobada`; sin duplicados;
  - vigía: lectura obsoleta y supervisión sin datos;
- `tests/test_dictamen_casos_salida.py` (5 pruebas).

`test_sondeo_span::test_normal_mide_intervalo_real` depende del reloj y puede fallar por carga de la
máquina. No falló en esta revisión.

## 6. Reproducción de los cuatro dictámenes con el código corregido

El reanálisis se hizo en Sensor1, sobre copias nuevas de las fuentes originales: `pruebas/<ID>` se
copió a `reanalisis/2a3478b/`, y la ventana se extrajo de la EVE dedicada con una lectura local. Dio:

| Ejecución | r5 | r6 | C9 (Suricata) |
|---|---|---|---|
| VD2 | indeterminada (`falta:espejo`, C9 y C10 None) | **igual** | Suricata `presente`, Δ 0; C9 sigue en None por el sondeo del switch |
| VD3 | no_aprobada (`espejo:con_descartes`) | **igual** | `presente`, Δ 0 |
| VD4 | aprobada | **igual** | `presente`, Δ 0 |
| VD6 | aprobada (verificación dirigida) | **igual** | `presente`, Δ 0 |

**No cambia ninguno**, y el motivo es concreto: con las muestras de la EVE completa, las cuatro quedan
acotadas, sin huecos y con Δ 0. Como contraprueba, el mismo código con solo el complemento r5 da
`insuficiente` («sin muestra en o antes del inicio») en las cuatro. VD4 y VD6 pasarían entonces a
`indeterminada`, y `reproducir_dictamen` lo marca como NO SATISFACTORIO. La regla nueva sí cambiaría el
dictamen si faltara la evidencia; no se forzó que se conservara.

Paquete `evidencias/bloque1/suricata-r6/`, por ejecución:

- `pruebas/<ID>/registros/suricata-stats-ventana-<ID>.jsonl`;
- `extraccion-ventana.json`, con el sha256 y la evaluación;
- `referencia/`, recalculada con 2a3478b, con su `ORIGEN.json`.

Hashes en `SHA256SUMS` (24 ficheros, verificados en el bastión y en el portátil). `reproducir_dictamen.py`
superpone ahora los complementos en orden (r5 y después r6) y toma la referencia del último. El registro
del clon limpio (`C:\r6`) está en `suricata-r6/REPRODUCCION-CLON-LIMPIO-intento4.txt`.

## 7. Lo que no cambia

- No se inició el piloto final ni las 49 h.
- No se repitió ninguna captura: la única evidencia nueva es la lectura de la ventana de stats en la EVE dedicada, ya existente.
- Siguen abiertos:
  - la causa interna de la pérdida en el switch;
  - del bloque 3, la deduplicación del extractor (fila 37);
  - del bloque 4, el reloj de DC1 (fila 38), la rotación del EVE y la supervisión prolongada.
