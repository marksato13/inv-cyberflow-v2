> **Nota (6.ª revisión, docs/BLOQUE1-REVISION-6-2026-11-26.md):** tres correcciones a esta revisión. (1) El Δ de Suricata se medía solo entre muestras interiores al periodo; ahora el periodo debe quedar acotado (§1 de la 6.ª). (2) Con Δ > 0, C9 de Suricata dependía de C7; ahora es fallo (§2). (3) «Ninguno decide el dictamen» (§5) era inexacto (§4). Los dictámenes de VD2–VD6 no cambian.

# Bloque 1, revisión 5: reproducción limpia, Suricata `kernel_drops` y matriz final (26-nov-2026)

Esta revisión es **preparación**. No se repitió ninguna captura: el reanálisis se hizo sobre copias.
El piloto final y las 49 h **no se han iniciado**. Se conservan las ejecuciones originales, los
reanálisis anteriores y la release r4 con sus referencias. El laboratorio queda detenido.

## 1. Reproducción desde una carpeta vacía y corta (Windows)

| Intento | Carpeta | Código | Resultado | Registro |
|---|---|---|---|---|
| 1 | ruta de 120+ caracteres en el scratchpad | 57b2293 | **Fallido**: checkout incompleto por rutas > 260 caracteres (sin `core.longpaths`) y los tres guiones con rc 2 | `evidencias/bloque1/entradas-r4/REPRODUCCION-CLON-LIMPIO-intento1-fallido.txt` |
| 2 | `C:\r4`, vacía | 3755089 (r4) | **Satisfactorio**: clon con `-c core.longpaths=true`, 972 ficheros, `git status` vacío; descarga, `verificar_paquetes`, `reproducir_dictamen` y `recalcular_desde_capturas` con rc 0 | `evidencias/bloque1/entradas-r4/REPRODUCCION-CLON-LIMPIO-intento2.txt` |
| 3 | `C:\r5`, vacía | código final de r5 | **Satisfactorio**: ver §6 | `evidencias/bloque1/suricata-r5/REPRODUCCION-CLON-LIMPIO-intento3.txt` |

**Cómo se ejecutan.** En primer plano y paso a paso: cada paso solo se lanza si el anterior dio
rc 0, y el clon se da por bueno solo si `git status --porcelain` sale vacío. Si no, se detiene y
no se continúa sobre una copia incompleta.

**Qué se registra.** Sistema, PowerShell, Python, git y gh; el commit, la fecha de cada paso, el
comando, la salida completa, el rc y la duración.

**Entorno del intento 2:**

- Windows NT 10.0.26300 y PowerShell 7.7.0;
- Python 3.14.3, git 2.56.0.windows.3 y gh 2.103.2.

**Duración de los pasos del intento 2:**

| Paso | Duración |
|---|---|
| Clon | 8,5 s |
| Descarga | 12,6 s |
| Verificación | 11,5 s (0 ficheros distintos en 490/491/483/479) |
| Dictamen | 13,9 s |
| Recálculo | 261,7 s |

## 2. Suricata `kernel_drops`: la contradicción

**Lo que se afirmaba.** Los informes (REVISION-3 §C9, REVISION-4 §6 y §8) y `revisar_criterios.py`
decían «Suricata no publica `kernel_drops` en `stats.log`: no medible». Mientras tanto, `vigia_v2.py`
lo leía de la EVE y las supervisiones publicadas valían 0.

**Lo que se comprobó** en Sensor1, en solo lectura. Está en `evidencias/bloque1/suricata-r5/PROCEDENCIA-SURICATA.txt`:

| Aspecto | Valor |
|---|---|
| Versión | Suricata 7.0.3 RELEASE (`/usr/bin/suricata`) |
| Proceso | Un único proceso, pid 339658, root: `suricata -D --af-packet -c /etc/suricata/suricata.yaml` |
| Arranque y reinicios | `ExecMainStartTimestamp` 2026-11-25 00:18:38 UTC, `NRestarts=0`. `uptime` monótono en las cuatro capturas |
| Modo de captura | AF_PACKET sobre `ens37` (`ring-size 16384`, `cluster-id 99`) |
| Configuración efectiva | `/etc/suricata/suricata.yaml`, sha256 `931845bf…22456`. `stats.interval 8`. Segunda salida `eve-log` con `filename: v2/eve.json` y `stats` (`totals: yes`) |
| Fichero leído | `/var/log/suricata/v2/eve.json`: lo lee el vigía (`vigia_v2.py:149`) y lo copia el archivador en `capturas/<ID>/eve/eve-<ID>.json` |
| `stats.log` | `null-values` comentado (por omisión **no**), así que **omite los contadores que valen 0** |

**La prueba de la procedencia.** Tomando, en cada ejecución, el primer evento `stats` de la captura:

- la EVE trae `capture.kernel_drops: 0` y un `kernel_packets` concreto;
- el bloque de `stats.log` con el **mismo instante y el mismo `uptime`** trae ese mismo
  `kernel_packets`, pero no la línea `kernel_drops`.

| Ejecución | Instante | uptime (s) | kernel_packets (EVE = stats.log) | kernel_drops EVE | En stats.log |
|---|---|---|---|---|---|
| VD2 | 09:07:38 | 118 140 | 23 401 101 | 0 | sin línea |
| VD3 | 10:43:47 | 123 909 | 24 979 554 | 0 | sin línea |
| VD4 | 14:14:45 | 136 567 | 27 724 962 | 0 | sin línea |
| VD6 | 15:16:14 | 140 256 | 29 013 398 | 0 | sin línea |

**Conclusión:** «no aparece en `stats.log`» quería decir «vale 0». La medida existe y es la de la
EVE dedicada: la afirmación «no medible» era **falsa**.

### 2.1 Datos publicados para verificarlo

Están en `evidencias/bloque1/suricata-r5/`, una carpeta por ejecución, en el repositorio:

- **`capturas/<ID>/eve/suricata-stats-<ID>.jsonl`:** los 228 eventos `stats` **originales y
  completos** de la EVE de la captura (unos 2 MB). El EVE filtrado de r4 no los lleva, porque su
  filtro exige IP del experimento.
  - Solo son contadores agregados: no tienen IP, MAC, nombres ni carga. El barrido de IP y MAC sale
    limpio.
  - Se publican sin modificar. `extraccion-stats.json` da el sha256 de la EVE original y del extracto.
- **`referencia/`:** el resultado del laboratorio recalculado con el código r5 sobre una **copia** de
  la fuente (`reanalisis/88c380d/<ID>` en Sensor1). `ORIGEN.json` dice de qué fuente sale cada uno.

**Comprobación de las 24 supervisiones.** Las seis lecturas de `supervision.jsonl` de cada ejecución
son iguales al evento `stats` inmediatamente anterior de la EVE, que está entre 0,8 y 7,7 s antes
(el intervalo es de 8 s). `reproducir_dictamen.py` lo comprueba automáticamente.

### 2.2 Estados que se distinguen ahora

Un dato ausente nunca se convierte en 0:

| Estado | Evaluador (`suricata_stats.evaluar`, C9) | Vigía (`supervision.jsonl`) | Efecto |
|---|---|---|---|
| Presente con 0 | `presente`, Δ = 0 → ok | `kernel_drops_estado: presente`, `kernel_drops: 0` | Cumple |
| Presente con Δ > 0 | `presente`, Δ cuantificado → decide C7 (PROTOCOLO §10) | Invalidación `kernel_drops` (`perdida_en_sensor`) | Pérdida cuantificada |
| Contador ausente | `ausente` → ok None | `ausente`, `kernel_drops: null` | Falta evidencia: `indeterminada`, nunca aprobada |
| Sin eventos `stats` | `sin_eventos` → ok None | `sin_stats` | Falta evidencia |
| Lectura fallida | Fichero ilegible o ausente → `sin_eventos` → None | `lectura_fallida`, `eve_error`, `kernel_drops: null` | Falta evidencia (`supervision: sin_datos`) |
| Reinicio | `reinicio` (`uptime` o `kernel_packets` retroceden): Δ sumado por tramos, **ok False** | `suricata_reinicio`, invalidación `reinicio_suricata` | Pérdida no cuantificable |

**Defecto de código corregido (vigía).** Antes, tras un reinicio, los contadores vuelven a 0. El vigía
comparaba con el valor previo al reinicio, así que unos descartes posteriores que no lo superaran
**no se detectaban**. Ahora el reinicio invalida el tramo y rehace la base. La prueba es
`test_reinicio_invalida_y_rehace_la_base`.

**Cambios** (88c380d, desplegado y verificado por hash en el bastión, Sensor1, Clientes y DC1):

- `operacion/suricata_stats.py`, nuevo;
- `revisar_criterios.py`: componente de Suricata en C9 y fuera la nota «no medible»;
- `vigia_v2.py`;
- `contadores_lab.sh`: lee Suricata de la EVE, no de `stats.log`;
- `reproducir_dictamen.py`: complemento r5;
- pruebas: `tests/test_suricata_stats.py` (10) y la adaptación de `test_revisar_criterios.py`.

**Suite: 296 pruebas**, todas pasan.

### 2.3 Efecto en el dictamen

| Ejecución | Dictamen r4 | Dictamen r5 | C9 r5 | Suricata (estado, eventos, Δ drops, Δ packets) |
|---|---|---|---|---|
| VD2 | indeterminada | indeterminada (igual) | None (por el sondeo del espejo, no por Suricata) | presente, 228, 0, 860 173 |
| VD3 | no_aprobada | no_aprobada (igual) | True | presente, 228, 0, 873 155 |
| VD4 | aprobada | aprobada (igual) | True | presente, 228, 0, 872 068 |
| VD6 | aprobada | aprobada (igual) | True | presente, 228, 0, 875 282 |

**Lo que cambia:**

- `pendientes_otra_comprobacion` deja de incluir C9 en las cuatro ejecuciones; quedan C10 (reloj de
  DC1) y C11 (deduplicación);
- para un `piloto_final`, `kernel_drops` **ya no bloquea**. No se ha retirado ningún requisito: el
  requisito se cumple con una medida que existía.

`reproducir_dictamen.py --sin-complemento` sobre r4 da NO SATISFACTORIO con el código actual, y es
lo correcto: sin los eventos `stats`, C9 queda en None y VD6 baja a `indeterminada`. Es la prueba de
que la ausencia de datos no se lee como cero. La referencia r4 solo es reproducible con el código
hasta 57b2293.

## 3. Documentación corregida

- **REVISION-3 §C9, REVISION-4 §6 y §8, e INFORME-PILOTO §4:** cada uno lleva una nota de corrección
  que remite aquí. No se reescribe lo que dijeron.
- **PENDIENTES:**
  - fila 12: el `write memory` está hecho;
  - filas 32, 33, 61, 62 y 63, conciliadas en §4;
  - filas nuevas 64–66.
- **README:** complemento r5 y comandos.

## 4. Conciliación de PENDIENTES con la política vigente

| Fila | Decía | Estado real | Qué queda |
|---|---|---|---|
| 12 | `mtu 9198` solo en la running-config; falta `write memory` (Mark) | **Hecho.** `show startup-config` de CORE-STACK (solo lectura, 26-nov) tiene `mtu 9198` en Gi2/0/19 | Nada |
| 32 | Política integrada; faltan 3 decisiones de Mark | **Las tres quedaron sustituidas** por cambios posteriores (abajo) | Ninguna decisión pendiente para el dictamen |
| 33 | Decisión de Mark: filtro de VLAN en el SPAN o `qos queue-softmax-multiplier` | **Ya no condiciona el dictamen.** La política evalúa el espejo tal como está, sin tocar SPAN ni búferes: un descarte en la captura da `espejo: con_descartes` y `no_aprobada` (VD3). Con la norma de transferencias (fila 54), VD4 y VD6 dieron 0 descartes. La sesión SPAN la comparte otro consumidor | **Condicional.** Es decisión de Mark solo si las ejecuciones prolongadas presentan descartes del destino del SPAN; mientras tanto no se aplica |
| 39 | Política vigente frente a propuesta | Sustituida por la 32 (ya lo decía) | Nada |
| 63 | «Con `kernel_drops` no medible, el piloto daría indeterminada» | Corregido: se mide (§2) | Un piloto final daría `indeterminada` solo mientras sigan abiertas C10 (DC1) y C11 (deduplicación) |

**Las tres decisiones de la fila 32 y por qué ya no hacen falta:**

1. **Fracción máxima de exclusión.** La 2.ª revisión la eliminó como vía para aprobar (POLITICA §1 y
   §6): una exclusión por incidente se informa, pero nunca convierte una pérdida en aprobación, y
   las guardas planificadas se fijan antes de capturar. No hay número que decidir.
2. **Capturar srv-dmz en las 49 h.** La referencia independiente (srv-dmz y DC1) es **obligatoria en
   cada ejecución** (fila 47, POLITICA §5). Sin ella el resultado es `indeterminada`. La política ya
   lo decide; lo que queda es comprobar en el bloque 4 que el espacio y la carga aguantan 49 h
   (`vigilar_referencias.py`, fila 51).
3. **Tratamiento definitivo de la sonda.** Las sondas van antes del periodo útil, con margen de 240 s
   derivado del extractor, y se registran con su clave completa (filas 41 y 46, POLITICA §6). La
   contaminación es `no_aprobada` y un registro reconstruido da `indeterminada`.

**Decisiones de Mark que siguen siendo necesarias:**

- **Fila 33, solo si hace falta:** cambiar o no el SPAN si las ejecuciones prolongadas presentan
  descartes.
- **Autorización del piloto final y de las 49 h:** no forman parte de este bloque y no se han pedido
  ni iniciado.

## 5. Matriz final del Bloque 1

**Leyenda:**

- **A** = reproducible desde los resultados intermedios publicados (`reproducir_dictamen.py`).
- **B** = reproducible desde los PCAP/EVE publicados (`recalcular_desde_capturas.py`).
- **Priv.** = se apoya en datos originales privados, publicados solo como valor y hash.

Los resultados se dan en el orden VD2 / VD3 / VD4 / VD6.

| Requisito | Evidencia pública | Resultado | Reproducible | Límite | Pendiente |
|---|---|---|---|---|---|
| Generador, archivador y vigía completos | `referencia/resultado-global.json` (r5); `manifiesto-fin.json`, `manifiesto.json`, `vigia.jsonl` (r4) | completa, completa, sin_paradas en las 4 | A | Solo ejecuciones de unos 30 min | Prolongada: bloque 4 |
| Supervisión sin invalidaciones (enlace, output drops, kernel_drops, huecos, relojes) | `registros/supervision.jsonl` (r4) + `suricata-stats-<ID>.jsonl` (r5) | sin_invalidaciones en las 4; 24/24 lecturas de `kernel_drops` iguales a la EVE | A | Lecturas cada 5 min | Supervisión de 49 h: bloque 4 (filas 44 y 59) |
| Espejo: sondeo del destino del SPAN toda la captura | `calidad-espejo-sondeo.json` | indeterminado (sondeo tardío, corregido 80627be) / con_descartes (scp mío, fila 54) / sin_descartes / sin_descartes | A (estado); el contador del switch, Priv. | Resolución de 2 s; contador del switch no publicable como traza | **Propio:** causa interna en el switch (fila 50). **Condicional:** fila 33 |
| `calidad_copias` (copias de la población por el espejo) | `calidad-copias-espejo.json` + anillo filtrado (release r4) | completo en las 4 | B, salvo los campos del anillo completo | Denominadores, bytes por VLAN y picos cuentan tráfico ajeno: Priv. | La pérdida de gestión no experimental (filas 30 y 43) no entra en el dictamen; su lugar exacto, **propio** (fila 50) |
| `calidad_dns` (PCAP de DC1) | `calidad-contraste-dns.*` + `dns-<ID>.pcap` filtrado | completo en las 4 | B | — | Reloj de DC1 6,5–7 ms: **bloque 4** (fila 38) |
| `calidad_extremo` (srv-dmz) | `calidad-extremo.json` + `extremo-<ID>.pcap` filtrado | completo en las 4 | B, salvo `sensor/paquetes` | `sensor/paquetes` cuenta el anillo completo: Priv. | Espacio y carga de srv-dmz en 49 h: **bloque 4** |
| `calidad_sonda` | `calidad-sonda.json` | completo en las 4 | A | — | — |
| Referencias vigiladas (srv-dmz y DC1) | `referencias` en el dictamen | sin registro / sin registro / completo / completo (VD2 y VD3 son anteriores a la 3.ª revisión) | A | — | Bloque 4 (49 h) |
| Transferencias fuera de la captura | `transferencias` | sin registro / sin registro / sin_copias / sin_copias | A | VD3 se conserva como fallida por una copia | — |
| Exclusión de V1 | `exclusion-v1.json` | cubre en las 4 | A | — | Aislamiento sostenido 49 h: bloque 4 |
| C7 cobertura | `cobertura/`, `criterios-revisados.json` | True en las 4 | A + B | — | Rotación del EVE a las 00:00: **bloque 4** |
| C9 pérdidas (switch, Sensor1, tcpdump, srv-dmz, **Suricata**) | `contadores-lab-*.txt`, `suricata-stats-<ID>.jsonl`, `PROCEDENCIA-SURICATA.txt` | None (sondeo) / True / True / True; Suricata `presente`, Δ 0 en las 4 | A; contadores del switch y del sensor, Priv. (texto publicado, sin traza independiente) | Instantáneas inicio/fin | Contadores durante 49 h: **bloque 4** |
| C10 relojes | `preflight-lab.jsonl`, `relojes-*.txt` | None / None (NTP final no registrado, corregido 5d4d51f) / True / True | A | — | **Bloque 4:** DC1 6,5–7 ms (fila 38) y deriva de 49 h |
| C11 extracción | `extraccion/`, `ventanas_meta`, `inicio-captura.json` | True en las 4 | B, salvo `orden_pcap`/`orden_eve` y descartes fuera de la población | — | **Bloque 3:** deduplicación (fila 37). **Bloque 4:** orden del EVE tras la rotación |
| C12 volumen | `volumen.jsonl`, `manifiesto.json` | True en las 4 | A | Extrapolado de 30 min | Volumen real de 49 h: bloque 4 |
| C13 aislamiento | `exclusion-v1.json`, contadores | True en las 4 | A | — | 49 h: bloque 4 |
| Dictamen y ocho casos | `referencia/` (r5) | indeterminada / no_aprobada / aprobada / aprobada; ocho casos iguales | A, desde un clon limpio | VD6 está aprobada **solo como verificación dirigida** | — |
| P2: conexiones persistentes | `extractos-539c48e/p2-…` (PCAP, EVE, transacciones) | 45/45 transacciones, 0 diferencias | B, desde un clon limpio | 6 conexiones | — |
| Requisitos por tipo de ejecución | `estado_global.REQUISITOS`, `lanzar_v2.sh` | Implementado; VD2–VD6 con tipo inferido `verificacion_dirigida` | Pruebas | — | Un piloto final exige además C10 y C11 de otros bloques |
| Publicación y trazabilidad | releases `bloque1-r4-2026-11-26`, `SHA256SUMS-bloque1-r4.txt`, `suricata-r5/SHA256SUMS`, registros de los clones | Hashes verificados; intentos 2 y 3 satisfactorios | Clon limpio | — | — |

**Qué no se puede reproducir sin los datos privados** (motivo en `entradas-r4/LEEME.md`):

- el anillo completo y el EVE completo, porque llevan tráfico y metadatos de terceros;
- la clave HMAC y la correspondencia de IP;
- los contadores internos del switch como traza;
- el análisis de la pérdida de gestión;
- T1–E3, que no tienen extractos.

~~**Ninguno decide el dictamen.**~~ **Corregido en la 6.ª revisión (§4):** es inexacto. No deciden el dictamen los campos que cuentan el anillo completo, pero sí lo deciden valores publicados cuya traza original es privada o irrepetible: lecturas del switch, contadores de Sensor1, tcpdump y srv-dmz, relojes, volumen del PCAP/EVE completos, recuentos de `nft` y la completitud de los eventos `stats` de Suricata. La comprobación A recalcula el dictamen desde esos valores; no los verifica de forma independiente.

**Pendientes del Bloque 1:**

- **Propios:**
  - la causa interna de la pérdida en el switch y su contador de sobresuscripción (fila 50), con el
    lugar exacto de la pérdida de gestión no experimental (filas 30 y 43);
  - la fila 33, solo si la causa lo exige.
- **De otros bloques:**
  - bloque 3: deduplicación del extractor (fila 37);
  - bloque 4: reloj de DC1 (fila 38), rotación del EVE y supervisión prolongada (filas 44 y 59),
    sondeo de 49 h (fila 34) y espacio y carga de las referencias.

## 6. Comprobación final desde una carpeta vacía (intento 3)

Se hace con el código final de r5 y la release r4. El complemento r5 va dentro del repositorio. Los
comandos son los mismos del README; `reproducir_dictamen.py` usa el complemento por omisión. El
resultado y el registro están en `evidencias/bloque1/suricata-r5/REPRODUCCION-CLON-LIMPIO-intento3.txt`.
