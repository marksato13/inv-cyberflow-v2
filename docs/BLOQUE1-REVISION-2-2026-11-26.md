# Bloque 1: segunda revisión del 26-nov-2026

Responde a los nueve puntos de la segunda revisión. La primera respuesta
(`BLOQUE1-REVISION-2026-11-26.md`) se conserva; lo que aquí se corrige se señala allí.

**No se han iniciado** el piloto final ni las 49 h. No se ha cambiado el SPAN, ningún búfer del
switch ni nada del ESXi: en el switch y en el ESXi solo se **leyeron** contadores y configuración.
Ningún original se ha borrado ni sobrescrito; todo lo nuevo está en carpetas nuevas
(`~/cyberflow-v2/bloque1/<prueba>/`). Las pruebas dirigidas de este documento (rx_dropped, gestión,
verificación VD2) son de preparación: ninguna es el piloto.

Repositorio: https://github.com/marksato13/inv-cyberflow-v2 (público).
Paquete: https://github.com/marksato13/inv-cyberflow-v2/releases/tag/bloque1-cierre-2026-11-26
(`paquete-bloque1.tgz`, sha256 `cc21f054bb5e1e1830e46555d9ccff8490d6bcebd681b39d75e3ee188cce270b`).

## Estado

| Punto | Estado |
|---|---|
| 1. PCAP saneado de DC1 y reproducción limpia | **Publicado; reproducido desde una descarga limpia** (§1) |
| 2. Identificación de sondas | **Corregida**: clave completa + ejecución + instante; la sonda antigua de T1 queda **incierta** (§2) |
| 3. Preflight completo registrado | **Hecho y desplegado**; comprobado en VD2 (§3) |
| 4. Sonda antes del periodo útil | **Hecho**: margen de 240 s derivado del extractor; comprobado con el extractor real en VD2 (§4) |
| 5. Criterio conservador | **En el dictamen**: guardas planificadas separadas de exclusiones por incidente; sin porcentaje (§5) |
| 6. Referencia independiente en srv-dmz y DC1 | **Integrada** en lanzador, cierre y dictamen; comprobada en VD2 (§6) |
| 7. rx_dropped de 120 s con PCAP | **Repetida y archivada**; extracto publicado (§7) |
| 8. Despliegue y pruebas del cierre | **Desplegado y verificado por hash**; dictamen probado con evidencia correcta, pérdida y ausente (§8) |
| 9. Pérdida de gestión | **Localizada en el switch**, antes de la cola de salida del destino del SPAN; ESXi descartado (§9) |

**El Bloque 1 sigue sin cerrarse por completo**: las ejecuciones antiguas (T1–E3) quedan
`no_aprobada` con el criterio nuevo (§4), y siguen abiertos los puntos de los bloques 3 y 4 (§10).

## 1. PCAP de DC1 publicado y reproducción desde una descarga limpia

`evidencias/bloque1/dns-entradas/dns-e3-pcap/dns-dc1-V2-E3-20261125T230032Z.saneado.pcap`
(50 098 B, sha256 `c95b92ef…`, 366 tramas, igual al original: el registrador ya filtraba a la
población). En 6ca07b1 faltaba porque `.gitignore` excluye `*.pcap`; ahora tiene una excepción
explícita para ese fichero y para el extracto de rx_dropped (§7), y ningún otro PCAP.

**Reproducción limpia** (portátil, sin laboratorio, 26-nov). En una carpeta vacía: `git clone`
de https://github.com/marksato13/inv-cyberflow-v2 (commit `ccb41a4`), `gh release download
bloque1-cierre-2026-11-26` (sha256 del paquete `cc21f054…`, comprobado), y

    python -I repo/operacion/reproducir_dns.py --paquete paquete/paquete --salida salida

(guion completo: `evidencias/bloque1/dns-entradas/reproduccion-limpia/repro-limpia.ps1`). Ahora
`reproducir_dns.py` pasa también los registros de sondas reconstruidos y compara la clasificación
de los eventos sin transacción con la del laboratorio.

| Ejecución | PCAP DC1 | Transacciones | Sin transacción | Explicados / inciertos | Igual al laboratorio (contraste y clasificación) |
|---|---|---|---|---|---|
| T1 | no (no existía) | 32/32 | 10 | 6 / 4 | sí |
| T2 | no (no existía) | 182/182 | 6 | 6 / 0 | sí |
| E1 | no (no existía) | 32/32 | 6 | 6 / 0 | sí |
| E2 | no (no existía) | 182/182 | 6 | 6 / 0 | sí |
| E3 | no | 182/182 | 6 | 6 / 0 | sí |
| **E3** | **sí** (`pcap_dc1: true`) | **182/182** | **8** | **8 / 0** | **sí** — la variante con PCAP termina (rc 0) |

`todo_igual: true`, salida 0, 7 s. Resultado y registro en
`evidencias/bloque1/dns-entradas/reproduccion-limpia/`. El rc 1 de T1 es el del contraste (eventos
inciertos), no de la reproducción.

## 2. Identificación de las sondas

**Qué estaba mal.** El contraste daba por explicada una consulta solo por el id 17611 y el prefijo
`portal.`. Cualquier consulta con esa firma, de cualquier momento, quedaba explicada.

**Ahora** (`captura/contraste_dns.py`, `clasificar_sueltos`), un evento sin transacción solo es
**explicado** si hay una sonda **registrada** de la **misma ejecución** con el mismo
**origen, puerto de origen, id y nombre completo**, y el evento cae en el **intervalo** de esa
sonda (± 0,5 s). Cada explicación queda en `relaciones` (evento → ejecución, sonda, origen, puerto,
id, nombre, instante e intervalo). Los demás casos no se explican y dicen por qué:
`sin_registro_de_sondas`, `registro_de_otra_ejecucion`, `sin_sonda_con_esa_clave`,
`nombre_distinto`, `fuera_del_intervalo_de_la_sonda`, `reconstruccion_ambigua`. Una consulta con la
firma de la sonda pero sin sonda acreditada queda **incierta**
(`incierto:firma_de_sonda_sin_ejecucion_acreditada`), no explicada.

**Registro.** `v2ctl.py` escribe ahora un registro por sonda (`_registro_sonda`): ejecución,
contexto, origen y puerto, destino, id y nombre DNS, ruta/método/código HTTP, clase, inicio y fin en
UTC y monotónico.

**Ejecuciones antiguas.** No tenían registro. `operacion/reconstruir_sondas.py` lo reconstruye de lo
que sí consta (instante de `iniciar` en el lanzamiento y primer perfil lanzado en el supervisor;
id derivado del código; puerto **desconocido**), marcado `fuente: reconstruido`. Un registro
reconstruido solo explica un evento si en su intervalo hay **una única** clave con la firma; si hay
más, `reconstruccion_ambigua`. El dictamen nunca da por **completo** un DNS explicado con
registros reconstruidos: queda `indeterminado`.

**Pruebas** (`tests/test_contraste_dns_sonda.py`, 11): sonda registrada explicada y relacionada;
firma sola insuficiente; otro puerto; otro nombre con el mismo prefijo; fuera del intervalo; otra
ejecución; otro evento cualquiera; reconstruida única frente a ambigua; la sonda antigua de T1 queda
incierta.

**Resultado sobre T1–E3** (`evidencias/bloque1/sonda-preflight-v2/dns-<ID>-{sin,con}-pcap.json`):

| Ejecución | Explicados (reconstruido) | Inciertos | No explicados |
|---|---|---|---|
| T1 | 6 | **4** (10.10.20.21:38742/17611, 06:25:16,819: sin ejecución acreditada) | 0 |
| T2, E1, E2 | 6 | 0 | 0 |
| E3 sin PCAP / con PCAP de DC1 | 6 / 8 | 0 | 0 |

**El origen de la consulta de T1 de las 06:25:16 sigue sin acreditar**: es anterior al
identificador de T1 (06:25:28), ningún registro del bastión ni de Clientes la asocia a una
ejecución, y el dictamen la trata como incierta.

## 3. Preflight completo registrado

`v2ctl.py preflight --registro` y `v2ctl.py sondear --registro` escriben JSONL. Cada comprobación
local (reloj, NTP, espacio, programa, no cruza 00:00 UTC…) es una línea `tipo: comprobacion`, y
cada sonda de red (DNS, obtener HTTP, obtener HTTPS, consulta, envío) una línea `tipo: sonda` con
la clave del §2. El lanzador guarda el registro de sondas en `registros/preflight-clientes.jsonl`
y `iniciar` escribe `generador/<ID>/preflight.jsonl` (sondas previas + comprobaciones de iniciar).
Así se distinguen las sondas de la generación experimental: tienen su propio registro, su
ejecución y su intervalo, y ninguna transacción del generador.

**Comprobado en VD2** (V2-VD2-20261126T090705Z, programa `prueba-niveles-transiciones.json`,
24 min): `generador/<ID>/preflight.jsonl` con 25 líneas: 10 comprobaciones de `sondear`, 5 sondas y
10 comprobaciones de `iniciar` (alias P1–P6, ningún generador en marcha, NTP, espacio, 00:00 UTC).
Las 5 sondas, todas desde 10.10.20.21 y con clase `ok`:

| Sonda | Puerto origen | DNS id / nombre | HTTP | Fin (UTC) |
|---|---|---|---|---|
| dns | 44220 | 17611 / `portal.cf-v2.lab` | — | 09:07:38,110 |
| obtener HTTP | 55741 | — | 200 | 09:07:38,113 |
| obtener HTTPS | 53269 | — | 200 | 09:07:38,125 |
| consulta | 43157 | — | 200 | 09:07:38,127 |
| envío | 43355 | — | 201 | 09:07:38,129 |

## 4. Sonda antes del periodo útil

**Margen.** La primera ventana útil cierra en t0 + 10 s y su historia mira 230 s atrás (horizonte
del motor). Para que ni los paquetes ni el estado de la sonda entren en una ventana útil, la sonda
tiene que terminar antes de t0 − 220 s; con un paso de rejilla de holgura:
`MARGEN_SONDA_S = HORIZONTE_S + PASO_S = 240 s`. Las constantes salen del extractor
(`extraer_v2.HORIZONTE_MOTOR_S`, `metadatos_v2.PASO_S`) y una prueba comprueba que coinciden con
`v2ctl.py` y con `lanzar_v2.sh` (`tests/test_sonda_margen.py`).

**Lanzador.** Tras confirmar el archivador, `v2ctl.py sondear` hace las sondas, y el generador no
arranca antes de `fin de la última sonda + 240 s` (`max(T_CONF + 150, NO_ANTES)`). `iniciar
--sondas-previas` **no** vuelve a sondear: valida que el registro sea de la misma ejecución, que
todas las comprobaciones y sondas estén bien y que el margen se cumpla; si no, no arranca.

**Comprobación con el Bloque 3.** `operacion/ventanas_sonda.py` (v3) usa las ventanas reales de
`extraccion/ventanas_meta.csv` (las del extractor) y la historia de 230 s, y separa las ventanas
tocadas que ya excluye una guarda planificada (E1, E5) de las útiles. Pruebas: sonda con margen → 0
útiles tocadas; sonda al arrancar (como T1–E3) → 22–23; justo por debajo del margen → ≥ 1; varias
sondas del mismo origen cuentan ventanas distintas; la salida real la entiende el dictamen.

**Comprobado en VD2.** Última sonda 09:07:38,129; generador no antes de +240 s; inicio real del
generador 09:11:39 (1795684299). `calidad-sonda.json` (con las ventanas reales del extractor):
`sin_contaminacion`, registro `v2ctl`, margen hasta t0 de **242,1 s** en las cinco sondas,
**0 ventanas útiles** tocadas y 23 tocadas que ya excluye la guarda E1 de la captura. El DNS de
VD2 explica sus 8 eventos sin transacción con el registro `v2ctl` (`sonda_preflight_v2ctl`), sin
reconstrucción.

**T1–E3 con el tratamiento nuevo** (`sonda-preflight-v2/ventanas-sonda-<ID>.json`, ventanas
**distintas** de 10.10.20.21 con la sonda en su historia; la primera respuesta contaba 23 por
sonda):

| Ejecución | Ventanas útiles contaminadas | Tocadas pero ya en guarda (E1/E5) | Antes → ahora |
|---|---|---|---|
| T1 | 22 | 2 | no_aprobada → no_aprobada |
| T2 | 19 | 5 | no_aprobada → no_aprobada |
| E1 | 18 | 5 | indeterminada → **no_aprobada** |
| E2 | 18 | 5 | indeterminada → **no_aprobada** |
| E3 | 19 | 4 | indeterminada → **no_aprobada** |

(`redictamen-v3.json`; el recuento por sonda de la versión 2, que sumaba las cinco sondas del
mismo origen, se conserva en `sonda-preflight-v2/v2-recuento-por-sonda/`.) Además, con el criterio
nuevo, en las cinco el DNS es `indeterminado` (explicado con registros reconstruidos) y T1–T2 no
tienen referencia del extremo (`sin_datos`).

Las cinco quedan **`no_aprobada`** (`calidad_sonda:contaminacion`). No se borran ni se reescriben
sus resultados: el redictamen está aparte (`sonda-preflight-v2/redictamen-v2.json`).

## 5. Criterio conservador

`docs/BLOQUE1-POLITICA-CALIDAD.md` (revisado):

- Ninguna ejecución definitiva se aprueba con **pérdida experimental comprobada** (copias,
  extremo, DNS) ni con **evidencia obligatoria indeterminada o ausente** (copias, DNS con PCAP de
  DC1 cuando existe, extremo, sonda). No hay porcentaje de tolerancia ni fracción de exclusión.
- `estado_global.exclusiones()` separa las **guardas y márgenes planificados** (E1 frontera de la
  captura, E5 fuera del programa, margen de sonda, captura previa de 150 s, margen final de 120 s:
  se fijan antes de capturar, `lanzamiento.json → guardas_planificadas`) de las **exclusiones por
  incidente** (E2–E4 y las invalidaciones de la supervisión). Una exclusión por incidente nunca
  convierte una pérdida en aprobación; la cuenta va al dictamen y la decide el criterio, no un
  porcentaje.

## 6. Referencia independiente en srv-dmz y DC1

| | srv-dmz (HTTP/HTTPS) | DC1 (DNS) |
|---|---|---|
| Captura | `tcpdump -i ens35 -n -s 0 -U`, arranca antes del archivador y para con SIGINT en el cierre | `registro_dns_v2.py` (unidad transitoria con tope de vida), JSONL + PCAP |
| Filtro | `host 10.10.30.10 and tcp and (port 80 or 443) and` población (.21–.26) | UDP/53 entre la población y 10.10.10.20 |
| Integridad | sha256 en origen y de la copia en Sensor1; si no coincide, la copia se renombra `.danado` y el dictamen da `entrada_danada` | sha256 en el cierre |
| Pérdidas | `packets dropped by kernel` de tcpdump; distinto de 0 → referencia `indeterminado` | conteos del registrador |
| Almacenamiento y carga | `df`, `/proc/loadavg` y `nproc` al principio y al final (`relojes-*.txt`) | ídem |
| Dictamen | `calidad_extremo`: pérdida si algo lo vio srv-dmz y no Sensor1 | `calidad_dns` con `pcap_dc1` obligatorio si el registrador lo declaró |

**Comprobado en VD2:**

| | srv-dmz | DC1 |
|---|---|---|
| Captura | 7 599 paquetes capturados = recibidos por el filtro, **0 descartados por el núcleo**; 13 261 614 B en 31 min de captura, de ellos 24 min de generación (≈ 33 MB por hora de generación) | PCAP 50 098 B y registro JSONL |
| Integridad | sha256 origen `c693d2f0…` = copia en Sensor1 | sha256 `6f76fb1e…` en el cierre |
| Carga (inicio → fin) | loadavg 0,00 → 0,35; 1 CPU | 0,01 → 0,00; 2 CPU |
| Espacio libre `/` (inicio → fin) | 10,23 → 10,21 GB | 35,27 → 35,27 GB |
| Resultado | `calidad_extremo: completo`: SYN 264/264, SYN-ACK 264/264, FIN 528/528, RST 32/32, ACK 4 217/4 217; 0 conexiones solo en un lado; 1 478 transmisiones de datos verificadas por rangos, 0 discrepancias; retransmisiones 0 = 0 | `calidad_dns: completo`: 182/182, `pcap_dc1: true` |

Para las 49 h: a ese ritmo serían unos 1,6 GB en srv-dmz frente a 10,2 GB libres. El programa de
49 h tiene otra carga, así que es una estimación que debe medirse en el piloto; el espacio de
srv-dmz se registra al principio y al final, pero **no** detiene la captura si se agota
(pendiente, fila 51 de PENDIENTES).

## 7. rx_dropped: prueba de 120 s repetida con los PCAP archivados

`rx_dropped_prueba.py` en Sensor1, sin tráfico V2, 26-nov 08:39:39–08:41:40 UTC; los 29 ficheros
del anillo del periodo se copiaron al terminar (`~/cyberflow-v2/bloque1/rx-dropped-r2/pcap/`,
privados, sha256 en `SHA256SUMS`).

| | Resultado |
|---|---|
| Δ`rx_packets` / Δ`rx_dropped` / Δ`rx_nohandler` | 19 447 / **1 688** / 0 |
| Tramas en el PCAP del periodo | 19 447 (igual que Δ`rx_packets`) |
| 802.3 LLC/SNAP con VLAN | **1 688 = Δ`rx_dropped`**: 1 684 PVST+ (pid 010b) y 4 CDP (pid 2000) |
| Otras sin manejador | 24 loopback (ethertype 9000) sin VLAN, que no cuentan en rx_dropped |

**Extracto publicable** (`evidencias/bloque1/rx-dropped-r2/extracto-sin-manejador.{pcap,csv,json}`,
`captura/extracto_rx_dropped.py`): las 1 712 tramas sin manejador IPv4/ARP/IPv6 con la cabecera
Ethernet, las VLAN y LLC/SNAP intactas, la MAC de destino de protocolo conservada (01:00:0c:cc:cc:cd),
las MAC unicast seudonimizadas (02:00:00:…) y el resto de la trama a ceros (sin identificadores de
puente ni TLV de CDP), conservando la longitud. Releído con `rx_dropped_prueba.clase()` da las
mismas clases: 1 688 `vlan/802.3_llc_snap` y 24 `sin_vlan/loopback`.

**Limitación honesta.** La serie por muestra de la versión 1.0 indexa por segundo entero desde t0
y las muestras no caen en fronteras de segundo, así que la igualdad se demuestra en el total, no
segundo a segundo. La versión nueva guarda el instante real de cada muestra. La prueba del 25-nov
(`rx-dropped-r1.json`) queda como **evidencia histórica incompleta**: sus PCAP rotaron.

## 8. Despliegue y pruebas del cierre y el dictamen

**Despliegue.** Cada versión se empaqueta con `git archive` y lleva una lista sha256 por fichero.
Se copia al bastión y `desplegar_codigo.sh` la instala en el bastión, Sensor1 y Clientes. Después
se cuenta, máquina a máquina, cuántos ficheros difieren de la lista. En DC1 se contrasta
`registro_dns_v2.py`. El script se niega a desplegar con una ejecución en curso.

| Versión | Qué trae | Verificación |
|---|---|---|
| 052fd66 | sondas con clave completa, preflight registrado, extremo, política | 0 diferencias en bastión, Sensor1 y Clientes; DC1 `registro_dns_v2.py` = `f4d17e4d…` |
| 1f4c485 | ventanas_sonda v3 (ventanas distintas) | ídem |
| c548ecd | lanzador: el `&` solo afecta al proceso de fondo (incidencia VD1, §11) | ídem |
| 9a99b74 | el dictamen lee `calidad-sonda` v3 (antes lo daba por `sin_datos`) | ídem |
| **80627be** (en el laboratorio ahora) | el sondeo del SPAN cubre el margen previo del archivador | ídem; paquete sha256 `f5a2bbd9…` |

**Lo que encontró VD2.** VD2 corrió con c548ecd. Su primer dictamen fue `indeterminada` por dos
motivos:

1. `falta:calidad_sonda`: el error de versión que arregló 9a99b74. Con 9a99b74, sin tocar la
   ejecución, la sonda sale `completo`.
2. `falta:espejo`: el archivador recoge también los PCAP de los 30 s anteriores a su arranque
   (`--margen-previo` 30 s + rotación 5 s). El primer paquete archivado es de 09:07:05,4, pero el
   sondeo del SPAN arrancó unos segundos antes que el archivador. Así, los primeros **30,5 s** de
   captura quedaban sin muestra (`antes_primera_muestra`). E3 tuvo el mismo defecto (34 s).
   80627be hace que el lanzador espere a que el sondeo cubra ese margen; la prueba
   `test_sondeo_cubre_el_margen_previo_del_archivador` lo fija. VD3 lo comprueba en el laboratorio
   (más abajo).

Ambos dictámenes de VD2 están publicados en `verificacion-VD2/dictamen/`. Ninguno es `aprobada`:
el espejo de VD2 sigue indeterminado, y no se reinterpreta.

**Exclusiones de VD2** (664 ventanas, 386 excluidas):

- **guardas planificadas:** E1 = 365 (frontera de captura y bloque) y E5 = 26 (fuera de programa);
- **incidentes:** E3 = 23, `cobertura_incompleta`, todas de 10.10.20.22 (P2).

El E3 **no es una pérdida**. P2 usa conexiones HTTP persistentes (34 conexiones, hasta 24
transacciones por conexión). `cobertura_v2.py` atribuye los bytes vistos de la conexión a una sola
de sus transacciones, así que 152 transacciones de P2 salen «incompletas». Sin embargo:

- en conjunto, P2 suma 1 626 730 B vistos frente a 1 615 901 esperados;
- el extremo ve 0 segmentos que no llegaran a Sensor1;
- la conciliación es `ok` en las 23 ventanas.

Con el criterio conservador, esas ventanas se quedan excluidas por incidente hasta que se corrija
el reparto (PENDIENTES 52, bloque 3). No se reclasifican a mano.

**Dictamen con evidencia correcta, pérdida y ausente.** `operacion/dictamen_casos.py` copia en una
carpeta nueva los JSON, JSONL y CSV de VD2 (sin tocar la ejecución), inyecta un caso en cada copia y
evalúa con el `estado_global.py` desplegado (`verificacion-VD2/dictamen/dictamen-casos.json`):

| Caso | Dictamen | Motivo añadido |
|---|---|---|
| correcta (copia tal cual) | indeterminada | ninguno: igual que la ejecución real (`falta:espejo`) |
| pérdida en el extremo (1 conexión solo en srv-dmz) | **no_aprobada** | `calidad_extremo:perdida` |
| pérdida de una copia de la población | **no_aprobada** | `calidad_copias:perdida` |
| sonda en una ventana útil | **no_aprobada** | `calidad_sonda:contaminacion` |
| sin referencia del extremo | indeterminada | `falta:calidad_extremo` |
| tcpdump de srv-dmz con 3 descartes del núcleo | indeterminada | `falta:calidad_extremo` (referencia incompleta) |
| sin calidad de la sonda | indeterminada | `falta:calidad_sonda` |
| sin contraste DNS | indeterminada | `falta:calidad_dns` |

Una pérdida comprobada da `no_aprobada`, y una evidencia ausente o incompleta da `indeterminada`.
Ninguna de las dos se aprueba.

⟨VD3⟩

## 9. Pérdida de gestión: dónde se pierde

**Camino del espejo** (`evidencias/bloque1/gestion-esxi-r1/ruta-espejo-esxi.txt`, MAC tapadas):
switch `CORE-STACK` sesión 1 (orígenes Gi1/0/23 = HV-EDGE-B y Gi2/0/23 = HV-EDGE-A, ambos
sentidos; destino Gi2/0/19, `replicate`) → ESXi `esxi-hv-siem` (8.0.3) `vmnic2` (I210-T1, igbn,
1 Gb/s) → vSwitch2 (MTU 1500, CDP en escucha) → grupo `PG-CYBERFLOW-SPAN` (VLAN 4095, promiscuo)
→ puerto 134217746 (vNIC `ens37` de Sensor1). El mismo grupo tiene un segundo consumidor
(VM-SURICATA, puerto 134217750). La vNIC de gestión de Sensor1 está en otro vSwitch.

**Prueba dirigida** (`operacion/prueba_gestion_esxi.sh`, 26-nov 08:43–08:49 UTC, sin ejecución
V2, solo lectura de contadores): F0 fondo 60 s, R3 1 × `scp` de 20 MB sin límite, R4
3 × `scp -l 160000`, F1 fondo 60 s; en cada marca se leen el switch (destino y orígenes), `vmnic2`,
los tres puertos del vSwitch2, `vmxnet3` de Sensor1 y `ens37`. Los PCAP del anillo del periodo
están archivados (55 ficheros, privados) y las copias se contaron con `copias_espejo.py`.

| Tramo | Copias de gestión que faltan (bastión↔Sensor1) | Gi2/0/19 Δ paquetes salida / Δ output drops | `vmnic2` Δ recibidos / descartes | Puerto Sensor1 Δ pktsRx / droppedRx | `vmxnet3` / `ens37` Δ |
|---|---|---|---|---|---|
| F0 (65 s) | 0 | 11 857 / 0 | 11 555 / 0 | 11 596 / 0 | 11 595 / 11 747 |
| R3 (11,5 s) | **13 691** (12 615 VLAN 60, 1 076 VLAN 10) | 19 564 / **38** | 19 535 / 0 | 19 472 / 0 | 19 470 / 19 330 |
| entre R3 y R4 (35 s) | 0 | 6 194 / 0 | 6 659 / 0 | 6 656 / 0 | 6 658 / 6 586 |
| R4 (70 s) | **3 902** (3 295 VLAN 60, 607 VLAN 10) | 108 977 / 1 | 108 745 / 0 | 108 749 / 0 | 108 747 / 108 821 |
| F1 (65 s) | 0 | 10 931 / 0 | 10 855 / 0 | 10 859 / 0 | 10 859 / 10 913 |

Las lecturas de los equipos no son simultáneas (unos segundos entre el switch y el ESXi): de ahí
diferencias de decenas a cientos de paquetes, también en los fondos, frente a miles de copias
faltantes. `vmnic2`: 0 descartes y 0 errores de recepción; vSwitch2 y `vmxnet3`: 0 descartes, 0
veces el anillo lleno, 0 falta de búferes (el `droppedRx` acumulado de 1 070 del puerto de Sensor1
es anterior y no se movió).

**Colas del destino** (una subida de 20 MB sin límite con `show platform hardware fed switch 2 qos
queue stats interface Gi2/0/19` antes y después, `resumen-qos-r3.json`): la cola 1 encoló
**25,3 MB**; las dos copias de la subida son unos 40 MB; la cola descartó 58 KB (+40 paquetes =
+40 `Total output drops`); faltan **11 917 copias** (unos 17 MB). 25,3 + 17,3 ≈ 42,6 MB.

**Conclusión respaldada por los contadores de ambos lados.**

1. Todo lo que el switch transmite por Gi2/0/19 lo reciben `vmnic2`, el vSwitch, la vNIC y el
   invitado: **el ESXi no pierde** (hipótesis 2 descartada).
2. Las copias que faltan **no llegan a encolarse** en la salida de Gi2/0/19: se pierden en la
   replicación del SPAN dentro del switch y no las cuenta ningún contador de la interfaz.
3. En R3 el tráfico entra por Gi2/0/23, el mismo miembro del stack que el destino: no hace falta
   cruzar el anillo del stack (estado del stack: 4 puertos OK, 1 cambio de enlace).

**Hipótesis que queda (no comprobada):** sobresuscripción del destino de 1 Gb/s en microrráfagas.
Con los orígenes en ambos sentidos, cada trama de la transferencia se refleja dos veces (hacia y
desde el cortafuegos), así que el espejo necesita el doble de la tasa; el pico de 10 ms medido es
de unos 1 018 Mb/s equivalentes incluso con `scp -l 160000`. Falta el contador interno del ASIC
que lo confirme; no se ha tocado el SPAN ni los búferes.

**Consecuencia para las capturas:** la norma de PENDIENTES 35 se mantiene (ninguna transferencia
grande por el cortafuegos durante una captura); 160 Mb/s de media no es seguro.

## 10. Qué se puede reproducir, qué necesita ficheros privados y qué sigue pendiente

| Resultado | Clase | Cómo |
|---|---|---|
| DNS de T1–E3, E3 con PCAP de DC1, y la clasificación de los eventos sin transacción | **Reproducible** | Descarga limpia del repositorio + release; `reproducir_dns.py` (§1) |
| Copias de la población y extremo (E1–E3) | **Reproducible** | Release + `copias_espejo.py` / `comparar_extremo.py` (CIERRE §10) |
| rx_dropped = SNAP (PVST+/CDP), por clase | **Reproducible** con el extracto | `rx_dropped_prueba.clase()` sobre `extracto-sin-manejador.pcap` |
| Ventanas tocadas por la sonda en T1–E3 | Requiere privados | `ventanas_meta.csv` de cada ejecución (en Sensor1); resultados y sha256 publicados |
| Copias de gestión de la prueba del ESXi y de la ráfaga QoS | Requiere privados | 55 + N PCAP del anillo, con tráfico de terceros; sha256 en `gestion-esxi-r1/SHA256SUMS-pcap-privados*` |
| Contadores del switch y del ESXi | Publicado (texto) | `gestion-esxi-r1/contadores-*.txt`, `qos-*.txt` |
| VD2: preflight, sondas, calidad (sonda, extremo, DNS, copias, espejo), cobertura y dictámenes | **Publicado (resultados)** | `evidencias/bloque1/verificacion-VD2/`; rehacerlos exige los PCAP de Sensor1, srv-dmz y DC1 (privados: tráfico del laboratorio, sha256 en `SHA256SUMS-pcap-privados`) |
| Casos del dictamen (correcta, pérdida, ausente) | Resultado publicado; **repetirlo requiere la carpeta de la ejecución** en Sensor1 (CSV del extractor) | `dictamen_casos.py` (§8) |
| Reparto de bytes en conexiones persistentes (E3 de P2 en VD2) | **Pendiente (bloque 3)** | PENDIENTES 52 |
| Contador interno que confirme la sobresuscripción del SPAN | **Pendiente** | Solo lectura en el ASIC, si se identifica el contador |
| Deduplicación del extractor | **Pendiente (bloque 3)** | |
| Relojes (DC1 ~6,5–7 ms por detrás) | **Pendiente (bloque 4)** | |
| Rotación del EVE a las 00:00 UTC y supervisión prolongada | **Pendiente (bloque 4)** | |
| Origen de la consulta de T1 de las 06:25:16 | **Incierto** | sin registro que la acredite |

## 11. Incidencia durante la verificación: VD1

El primer intento (V2-VD1-20261126T085911Z) se quedó parado al arrancar la captura de srv-dmz:
`ssh srvdmz "mkdir -p … && sudo -n setsid nohup tcpdump … &"` manda a segundo plano **toda** la
lista `&&`, y esa subshell retiene la salida de ssh, así que la sesión no termina. Se interrumpió
la sesión; el lanzador ejecutó `deshacer` («no arrancó la captura del extremo»): paró el tcpdump de
srv-dmz y el registrador de DC1; no había arrancado ni el archivador ni el generador. La regla de
exclusión de V1 (acotada en el tiempo, hasta 11:37:41 UTC, con respaldo del toml) se dejó como en
las ejecuciones anteriores. Corrección en c548ecd (`;` en vez de `&&`) con una prueba de
regresión (`tests/test_lanzar_fondo.py`) que falla con la línea antigua. La segunda verificación
se llama VD2.
