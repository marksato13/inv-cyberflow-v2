# Bloque 1 — Calidad de captura y espejo (25-nov-2026)

Complementa el encargo consolidado de 11 puntos (preparación de las 49 h); no lo sustituye.
T1 (`V2-T1-20261125T062528Z`) y T2 (`V2-T2-20261125T070500Z`) se conservan con sus resultados,
configuraciones y evidencias originales; nada de este bloque los reevalúa para aprobarlos.
No se han iniciado las 49 h, ataques, campañas A/B ni el piloto integrado final.

**Estado: la causa de los incrementos observados en T1 y T2 está identificada y corregida con
evidencia; la calidad de captura NO se declara cerrada** (§6: cuestiones abiertas).

Las horas son UTC. Las marcas de las pruebas usan el reloj del bastión (NTP); el reloj del switch
aparece en `show clock` con `*` (no autoritativo) y no se usa para fechar.

## 1. La observación

### 1.1 Equipo y configuración efectiva

| Dato | Valor | Comando |
|---|---|---|
| Equipo | Pila de dos Cisco Catalyst **C9300L-24T-4G** | `show version`, `show switch` |
| Software | **IOS XE 17.9.3** (CAT9K_IOSXE, modo INSTALL) | `show version` |
| Sesión | `monitor session 1`, tipo local | `show monitor session all detail` |
| Fuentes | **Gi1/0/23 y Gi2/0/23, sentido Both** (RX y TX): los dos troncos del cortafuegos (nodos A y B), 802.1Q, VLAN permitidas 10, 20, 30, 40, 50, 60, 70, 80, 85, 88, 90, 95, 99, 100 | `show running-config interface …` |
| Filtro de VLAN / ACL | Ninguno | ídem |
| Destino | **Gi2/0/19**, `encapsulation replicate` (conserva la etiqueta 802.1Q), ingreso deshabilitado, 1000 Mb/s full, MTU 9198 | `show interfaces GigabitEthernet2/0/19` |
| Receptor | Sensor1, interfaz `ens37` (vmxnet3, anillo RX 1024), tcpdump del anillo `ppi-motor-capture` y Suricata v2 | `ethtool -i/-g/-S ens37` |

Consecuencia de esta configuración: todo paquete que entra al cortafuegos por un tronco y sale por
un tronco aparece **dos veces** en el espejo (una por VLAN), y ambas copias comparten el puerto
destino de 1 Gb/s con el resto de VLAN del tronco. Lo experimental se ve así:
cliente (VLAN 20) ↔ servidor (VLAN 30): copias en 20 y 30; cliente ↔ DNS de DC1: copias en 20 y 10.

### 1.2 El contador

- Nombre: **«Total output drops»** de `show interfaces GigabitEthernet2/0/19`; el mismo valor sale
  como **OutDiscards** en `show interfaces GigabitEthernet2/0/19 counters errors`.
- Unidad: **paquetes** descartados a la salida del puerto destino (no avisos, no bytes).
- Desglose por cola: `show platform hardware fed switch 2 qos queue stats interface Gi2/0/19`
  muestra que **todos** los descartes acumulados están en la **cola 1, umbral 2** (`Drop-TH2`, en
  bytes): 321 734 588 B al empezar este bloque. Al terminar B1 (145 paquetes más) subió a
  321 942 800 B: 208 212 B / 145 ≈ 1 436 B por paquete, es decir, tramas casi completas.
- Significado según Cisco: en Catalyst 9000 los descartes de salida se producen cuando la cola de
  salida no tiene búfer para lo que llega
  ([Troubleshoot Output Drops on Catalyst 9000](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-switch/216236-troubleshoot-output-drops-on-catalyst-90.html),
  [Understand Queue Buffer Allocation on Catalyst 9000](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/218444-understand-queue-buffer-allocation-on-ca.html)).
  Para SPAN, la guía de configuración del 9300 indica que un destino sobresuscrito puede perder
  paquetes y que un paquete puede reenviarse normalmente y perderse para la monitorización
  ([Configuring SPAN and RSPAN, 9300, 17.12](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/nmgmt/b_1712_nmgmt_9300_cg/configuring_span_and_rspan.html)).
  Que la suma RX+TX de dos fuentes duplique la carga en el destino es una deducción nuestra a partir
  de esa documentación, comprobada en el laboratorio (§3), no una frase de Cisco.

### 1.3 Avisos frente a paquetes

El vigía consulta el contador cada ~305 s y escribe un **aviso** (`invalidaciones.jsonl`) cuando
sube. Un aviso no es un paquete:

| Ejecución | Avisos | Valores del contador (marca del vigía) | Paquetes |
|---|---:|---|---:|
| T1 | 4 | 215521 (06:29:54) → 215525 (06:35:00) → 215526 (06:40:06) → 215527 (06:55:22) → 215530 (07:00:27) | 9 |
| T2 | 4 | 215530 (07:07:52) → 215531 (07:12:59) → 215534 (07:18:05) → 215536 (07:28:17) → 215539 (07:33:28) | 9 |
| T2, después de la última supervisión (cierre y copias) | — | 215539 → 215546 (`contadores-lab-fin.txt`) | 7 |

Tráfico del puerto destino en esas ejecuciones (de la propia captura de Sensor1): pico de 1 s
52 Mb/s (T1) y 78 Mb/s (T2), pero **picos de 10 ms equivalentes a 995 y 977 Mb/s**.

## 2. Tráfico experimental en T1 y T2

`captura/copias_espejo.py` agrupa cada paquete experimental (IP de P1–P6 o del servidor) por su
identidad (origen, destino, protocolo, ipid, longitud, puertos, seq, ack, flags) y cuenta en qué
VLAN aparece. Si el destino SPAN descarta una copia, el paquete queda con menos copias que el
patrón de su flujo.

| Ejecución | Tramas totales | Paquetes experimentales distintos | Con 2 copias | Con copia faltante | Ráfagas ≥ 0,4 línea en 10 ms | Composición de esas ráfagas |
|---|---:|---:|---:|---:|---:|---|
| T1 | 441 557 | 6 541 | 6 538 | **0** | 15 | solo VLAN 10 + 60 (+ unos bytes de 100), 0 B experimentales |
| T2 | 384 677 | 18 997 | 18 977 | **0** | 14 | ídem |

Los paquetes con 1 copia corresponden a flujos cuyo patrón es de una sola VLAN (servidor ↔ hosts
de VLAN 10 sin cruzar dos troncos); los de 4 copias, a repeticiones idénticas.

Las ráfagas de T1 están a 1795588194.22, …499.75, …805.74, 89110.69, …416.31, …722.13, 90026.45:
**una cada ~305 s, entre 0,6 y 0,8 s antes de cada registro de supervisión**. Cada aviso agrupa
justo una de esas ráfagas. El vigía lee el contador antes de transferir; por eso los descartes de
una ráfaga aparecen en el aviso siguiente.

**Lo que esto prueba y lo que no.** Prueba que ningún paquete experimental perdió UNA de sus dos
copias. No prueba que ninguno perdiera LAS DOS (eso solo se ve desde un extremo, §3.3). «100 % de
bytes de aplicación» (C7) tampoco lo prueba: las copias se unen al deduplicar. Y «0 descartes en
Sensor1» (tcpdump/Suricata) no dice nada de la pérdida antes del sensor.

## 3. Pruebas dirigidas

### 3.1 B1: fondo y reproducción controlada (`V2-B1-20261125T182207Z`)

Sin generadores ni vigía. Contador sondeado cada ~6 s con una sola sesión SSH
(`operacion/sondear_span.sh`). Fases y marcas en `marcas.jsonl` (`operacion/prueba_espejo_b1.sh`).

| Fase | Qué se hizo | Incremento del contador |
|---|---|---|
| F0 fondo | 300 s sin nada | **0** |
| R1 | 5 × `ssh sensor1 "tail -n 2000 /var/log/suricata/v2/eve.json"` (la orden del vigía, ~1 MB), cada 30 s | **+2, +1, +4, +1, 0** (4 de 5) |
| R2 | 5 × la misma lectura **filtrada en Sensor1** (solo la última línea `stats`, ~8 KB) | **0** |
| R3 | 3 × `scp` de 20 MB bastión → Sensor1 sin límite | **+47, +48, +42** |
| R4 | 3 × `scp -l 160000` (160 Mb/s) | **0** |
| F1 fondo | 240 s sin nada | **0** |

Total: 145 paquetes. Cola 1 TH2: +208 212 B.

### 3.2 Corrección aplicada

`operacion/vigia_v2.py` (commit `cc70836`): la supervisión lee la EVE filtrando en Sensor1
(`tail -n 2000 … | grep -F '"event_type":"stats"' | tail -n 1`). Desplegado en el bastión, Sensor1
y Clientes como `~/cyberflow-v2/codigo` (VERSION `cc70836`, tgz sha256
`b25e57e6…b558`); la versión anterior queda en `~/cyberflow-v2/codigo-a5c70ab`.

**No se tocó el switch** (ni SPAN, ni QoS, ni búferes). Antes de cualquier cambio de configuración
se guardó la efectiva (§1.1 y `evidencias/bloque1/switch/`).

Nota sobre un cambio anterior: el servidor v3.0.1 (`0525eba`, trozos de 16 KiB en `/contenido`) se
hizo esta mañana con la hipótesis de que la escritura del servidor causaba los descartes. **Esa
hipótesis no se comprobó y los datos la contradicen** (las ráfagas no contienen tráfico del
servidor). El cambio se mantiene porque es inocuo e iguala `/contenido` a `/estatico`, pero no es
la corrección.

### 3.3 B2: ejecuciones normales con sondeo fino y captura independiente en el extremo

`operacion/prueba_espejo_b2.sh`: lanzar_v2 + sondeo del contador cada ~6 s + tcpdump en srv-dmz
(`ens35`, `host 10.10.30.10 and tcp and (port 80 or port 443)`). Tras la captura, `cerrar_v2.sh`,
`copias_espejo.py` y `captura/comparar_extremo.py` (rangos de bytes por sentido y segmentos de
control, extremo frente a Sensor1).

| Prueba | Programa | Incremento del contador | Avisos | Paquetes exp. distintos | Copia faltante | Extremo: conexiones / bytes | Bytes no vistos en Sensor1 | Control (SYN/SYN-ACK/FIN/RST/ACK puro) extremo → Sensor1 |
|---|---|---:|---:|---:|---:|---|---:|---|
| E1 `V2-E1-20261125T185323Z` | cada perfil por separado (P1…P6, 300 s cada uno) | **0** | 0 | 6 453 | **0** | 52 / 3 340 224 B | **0** | 52/52/104/2/994 → 104/104/208/4/1988 (exactamente ×2) |
| E2 `V2-E2-20261125T194609Z` | los seis simultáneos: reducido/base/aumentado y ráfaga P1/P2/P4 (mayor carga de las pruebas) | **0** durante la captura | 0 | 18 513 | **0** | 269 / 12 634 360 B | **0** | 269/269/538/32/4723 → 538/538/1076/64/9446 (exactamente ×2) |

Ni E1 ni E2 tuvieron ráfagas a línea (pico de 10 ms: 114 y 113 Mb/s equivalentes; pico de 1 s: 37 y
64 Mb/s) y las dos dan `supervision: sin_invalidaciones`. El contador sí subió **fuera** de las
capturas, en los cierres: +40 entre E1 y E2 y +42 a las 20:15:53, 31 s después de que terminara el
archivador de E2 (20:15:22), mientras `cerrar_v2.sh` copiaba registros por SSH a través del
cortafuegos. Es el mismo mecanismo y no afecta a ninguna captura, pero obliga a una norma
operativa: **durante una captura no se hacen transferencias de gestión grandes a través del
cortafuegos; si son imprescindibles, limitadas a ≤ 160 Mb/s** (R4: 0 descartes).

Resultado global: E1 `indeterminada` (solo faltan los criterios de revisión manual C7, C9–C13).
E2 `indeterminada` con un motivo más, `falta:analisis`, que es un **defecto de registro, no del
análisis**: la salida de `/usr/bin/time -v` (stderr) y la línea `verificar rc=0` (stdout) viajaron
por flujos separados de SSH y se entremezclaron («…Si**verificar rc=0**\ngnals…»), y
`estado_global.py` no la reconoció. Los seis pasos dieron rc 0. Corregido en `cerrar_v2.sh`
(`exec 2>&1` en el análisis remoto). El `resultado-global.json` original de E2 se conserva sin tocar.

Limitaciones del contraste con el extremo:
- srv-dmz tiene TSO/GSO/GRO/LRO activos: su captura agrupa segmentos; por eso se comparan rangos de
  bytes y segmentos de control, no números de paquetes de datos. Los ACK puros entrantes pueden
  estar agrupados (GRO): su recuento es orientativo (aquí coincidió exactamente).
- El extremo solo ve HTTP/HTTPS del servidor. El DNS (clientes ↔ DC1) se contrasta con el registro
  del cliente y del servicio DNS por transacción (`conciliacion/`, `cobertura/`), no con una captura
  en DC1 (Clientes y DC1 no permiten sudo sin contraseña).
- tcpdump del extremo informó 0 descartes del núcleo.

### 3.4 Perfiles y carga

- Por perfil: E1 (y T1 antes de la corrección) recorren P1…P6 por separado.
- Simultáneo y carga máxima: E2 (y T2) contienen el tramo [480, 720) s con los seis perfiles en
  `aumentado` (factor 2), que es igual o superior al nivel más alto del calendario de 49 h.

## 4. Causas compatibles comprobadas

| Causa | Evidencia | Conclusión |
|---|---|---|
| Copias duplicadas (RX+TX de dos troncos) | 2 copias por paquete experimental; las transferencias de gestión que cruzan el cortafuegos llegan dos veces en 10 ms | **Mecanismo confirmado** (multiplica por 2 la carga de lo que cruza el cortafuegos) |
| Alcance del espejo (todas las VLAN del tronco) | El fondo de otras VLAN es bajo (≤ ~2 Mb/s medios) y en F0/F1 no causó ningún descarte | No es la causa de los incrementos observados; sí ocupa capacidad |
| Capacidad del destino (1 Gb/s) | Ráfagas de 10 ms a 977–1 023 Mb/s equivalentes coinciden con cada incremento | **Confirmado**: ráfagas cortas, no carga media |
| Colas/búferes (cola 1, TH2; softmax de la cola 1 = 1200 con el multiplicador por omisión) | Todos los descartes en Q1-TH2 | Es donde se pierden; no se ha cambiado `qos queue-softmax-multiplier` |
| Escritura del servidor (64 KiB) | Las ráfagas no contienen tráfico del servidor; E1/E2 con v3.0.1 sin descartes, pero también sin el vigía antiguo | **No demostrada** como causa |
| Tráfico experimental en carga máxima | E2 (seis perfiles, `aumentado`): pico de 10 ms 113 Mb/s equivalentes, 0 descartes | El tráfico experimental previsto no satura el destino |
| Pérdida en Sensor1 | tcpdump 0 descartes, vmxnet3 `drv dropped rx total` 0, `rx buf alloc fail` 0, Suricata `kernel_drops` 0 | Sin evidencia de pérdida en el sensor (§6 para `rx_dropped`) |

## 5. Propuesta de política de calidad (para decidir; no aplicada a T1/T2)

### 5.1 Clases

1. **Pérdida comprobada de tráfico experimental**: algún paquete experimental con copia faltante
   (`copias_espejo.py`), bytes o control vistos en el extremo y no en Sensor1
   (`comparar_extremo.py`), petición/respuesta DNS o HTTP de una transacción no vista (`cobertura`),
   o hueco TCP sin retransmisión.
2. **Incremento del contador de impacto no determinado**: el contador sube y no se puede demostrar
   que lo descartado fuera ajeno al estudio. Incluye siempre la posibilidad de que un paquete
   experimental perdiera sus dos copias.
3. **Tráfico ajeno, identificado con evidencia**: solo se admite si, en el intervalo localizado,
   (a) ningún paquete experimental tiene copia faltante, (b) el extremo no tiene bytes ni control sin
   ver, (c) todas las transacciones del intervalo tienen sus fases vistas y (d) la ráfaga que explica
   el incremento está compuesta sin tráfico experimental. Aun así se registra; nunca se borra.

### 5.2 Localización

- El contador se sondea cada ~6 s durante toda la captura (sesión SSH única; `sondear_span.sh`), no
  cada 300 s. El intervalo potencialmente afectado es [última lectura sin cambio, lectura con cambio].
- Si en ese intervalo la captura muestra una única ráfaga a línea (≥ 0,4 de línea en 10 ms), el
  intervalo puede estrecharse a [ráfaga − 1 s, ráfaga + 1 s]; si hay varias o ninguna, se usa el
  intervalo de sondeo completo. No se limita automáticamente a los 5 min de supervisión ni se
  descarta un incremento por ser pequeño.

### 5.3 Propagación a ventanas

Una ventana usa los paquetes de su retrospectiva y, además, el estado de flujos del extractor en
modo continuo hasta 230 s atrás (`GUARDA_ESTADO_S`). Por eso una ventana se marca afectada si
`[antecedentes_desde_utc, ventana_cierre_utc]` se solapa con el intervalo afectado (equivale a
excluir los cierres desde el inicio del intervalo hasta su fin + 230 s):
- clase 1: se excluyen todas las ventanas afectadas de las entidades del paquete perdido; si no se
  puede atribuir entidad, todas las entidades;
- clase 2: se excluyen las ventanas afectadas de **todas** las entidades (motivo nuevo
  `E6:espejo_impacto_no_determinado`, con el intervalo);
- clase 3: no se excluye; se marca (`M:espejo_ajeno`) y se informa por partición.

### 5.4 Parada

Se mantiene la tabla de `PROTOCOLO.md` (§ Tiempos): los descartes del espejo invalidan, no paran.
Se propone añadir una **parada** si en una hora hay más de 3 intervalos de clase 1 o 2, porque
indicaría un cambio del laboratorio (tráfico de otro origen, enlace) que no se debe absorber en
silencio. Umbral a decidir.

### 5.5 Criterio anterior y efecto

El criterio vigente (PROTOCOLO §10, versión 2) no cambia y sigue aplicado:

> **C9** — Pérdidas en toda la cadena: Δ output drops de Gi2/0/19 y de los orígenes,
> Δ`rx_missed_errors`/softnet y descartes de tcpdump/Suricata registrados antes y después. Se acepta
> Δdrops = 0; si no, se cuantifica y C7 decide.

Efecto sobre las ventanas elegibles (sin otro motivo de exclusión) de T1 y T2, calculado con su
`ventanas_meta.csv` e `invalidaciones.jsonl`:

| Ejecución | Ventanas elegibles | (a) Criterio vigente | (b) Intervalo de supervisión de 5 min + retrospectiva | (c) Propuesta: ráfaga ± 1 s + retrospectiva/230 s |
|---|---:|---|---:|---:|
| T1 | 65 | Δdrops = 9 ≠ 0 → «se cuantifica y C7 decide» (no se excluyen ventanas; la ejecución queda no aprobada) | 59 afectadas | 53 afectadas |
| T2 | 265 | Δdrops = 9 (+7 tras la supervisión) → ídem | 265 afectadas | 164 afectadas |

Con el vigía antiguo, una ráfaga cada 5 min y retrospectivas de 230 s afectan a casi todas las
ventanas con cualquier variante: la corrección del vigía es necesaria, no la política.
**T1 y T2 siguen `no_aprobada`.**

## 6. Cuestiones no resueltas

1. **Copias faltantes de gestión sin descarte contado.** En B1, el tráfico de gestión
   bastión ↔ Sensor1 tuvo 1 843 paquetes con copia faltante, mientras el contador subió 145; en R4
   (limitada, 0 descartes) faltaron 10–45 copias por subida. No todas las copias que faltan se
   explican por «Total output drops». Hipótesis no comprobadas: pérdida en el vSwitch del ESXi que
   aloja Sensor1 (no visible desde el invitado), descarte de replicación SPAN no contabilizado en el
   destino, o un patrón esperado mal inferido para flujos de gestión. **Hasta resolverlo, la ausencia
   de incrementos del contador no basta para afirmar que no hubo pérdida antes del sensor**; la
   evidencia válida para lo experimental es la de copias + extremo + cobertura.
2. **`rx_dropped` de `ens37`** sube también sin pruebas (1 568 157 al inicio de T1; 2 193 062 tras B1).
   tcpdump y el driver informan 0. Probablemente son tramas sin manejador de protocolo (VLAN no
   configuradas en el sensor), que AF_PACKET sí captura, pero **no está demostrado**.
3. **DNS sin captura en extremo**: solo contrastado por registros.
4. **Carga real de las 49 h**: E2 cubre el nivel `aumentado` con los seis perfiles durante 240 s; no
   cubre horas seguidas ni la noche (rotación).
5. **Opciones de configuración no aplicadas** (requieren decisión de Mark, y la sesión SPAN la
   comparte otro sistema de monitorización): `monitor session 1 filter vlan 10,20,30` (quitaría la
   doble copia de gestión de VLAN 60 y el fondo ajeno, pero sigue habiendo dos copias de lo
   experimental y cambia lo que ve el otro consumidor del espejo); `qos queue-softmax-multiplier
   1200` (más búfer para ráfagas; cambio global del switch). Ninguna reduce la captura a un solo
   sentido.

## 7. Requisitos relacionados

| Requisito | Estado tras el bloque 1 |
|---|---|
| Encargo, punto 6 (captura, EVE, supervisión; pérdida antes del sensor frente a en el sensor) | Causa de T1/T2 identificada y corregida; detector de copia faltante y contraste con extremo implementados; **abierto** por §6.1 |
| Punto 7 (resultado global) | E1 `indeterminada` (solo criterios manuales); E2 `indeterminada` (criterios manuales + defecto de registro ya corregido); T1/T2 `no_aprobada` sin cambios |
| C9 | Sin cambios; propuesta §5 pendiente de decisión |
| Piloto integrado final | **No iniciado** (no procede hasta decidir §5 y §6) |

### Definición completa de C7 y C9–C13 (PROTOCOLO §10, versión 2) y evaluabilidad

| # | Definición | ¿Evaluable con T1/T2/E1/E2? |
|---|---|---|
| C7 | Cobertura de la captura: conexión, petición y respuesta vistas en el 100 % de lo que aplica; bytes de respuesta vistos / bytes TCP recibidos ≥ 95 % en el total, en cada acción comparable y en cada perfil; 0 `no verificable` | Sí (`cobertura/`). Cumple en T1, T2 y E1. No basta por sí solo para la pérdida antes del sensor (§2) |
| C9 | Pérdidas en toda la cadena: Δ output drops de Gi2/0/19 y de los orígenes, Δ`rx_missed_errors`/softnet y descartes de tcpdump/Suricata antes y después; se acepta Δdrops = 0; si no, se cuantifica y C7 decide | Sí. E1 y E2: Δ = 0 (`contadores-lab-inicio/fin`: 215728→215728 y 215768→215768; el sondeo fino lo confirma durante toda la captura; los descartes del cierre llegan después de `contadores-lab-fin`). T1/T2: Δ = 9 cada una (cuantificado aquí) |
| C10 | Relojes: NTP sincronizado en los cuatro equipos al principio y al final; \|desfase aparente\| mediano ≤ 5 ms | Parcial: hay `relojes-*` y desfase de supervisión (~0,17 s bastión↔Sensor1/Clientes por SSH, que no mide el desfase real). Requiere el bloque 4 |
| C11 | Extracción: `extraer_v2` y `verificar_v2` rc 0; verificación 40/40; inventario de IP; constantes justificadas; tardías = 0 | Sí (bloque 3 para la revisión completa de las 28) |
| C12 | Volumen: GB/h de PCAP comprimido, EVE y registros por fase medidos; recálculo de la estimación | Parcial; recálculo de 49 h en el bloque 4 |
| C13 | Aislamiento de V1: regla `*@` que cubre; sets de srv-dmz vacíos, DC1 sin reglas, agente sin `--aplicar` al principio y al final | Sí (`preflight-lab.jsonl`, `contadores-lab-*`); revisión en el bloque 4 |

(Las filas C2–C4 de PROTOCOLO §10 v2 describen fases y pulsos del generador v2; `evaluar_piloto.py`
ya evalúa niveles y ON/OFF de P6 del programa v3. Se actualizará el texto en el bloque 4.)

## 8. Comandos y versiones

- Switch (solo lectura): `show version`, `show switch`, `show monitor session all detail`,
  `show running-config | section monitor`, `show running-config interface Gi1/0/23|Gi2/0/23|Gi2/0/19`,
  `show interfaces Gi2/0/19 [counters errors]`,
  `show platform hardware fed switch 2 qos queue stats|config interface Gi2/0/19`.
- Sensor1: `ethtool -i/-g/-S ens37`, `/sys/class/net/ens37/statistics/*`, journal de
  `ppi-motor-capture` (descartes de tcpdump).
- Pruebas: `bash operacion/prueba_espejo_b1.sh`; `bash operacion/prueba_espejo_b2.sh <programa> <TAG> 2`.
- Análisis: `python3 captura/copias_espejo.py <dir_pcap> --salida X.json [--ips …] [--detalle-umbral 0.4]`;
  `python3 captura/comparar_extremo.py --extremo srv.pcap --sensor <dir_pcap> --salida Y.json`.
- Código desplegado durante B1: `a5c70ab`; durante E1/E2: `cc70836`.

## 9. Evidencias

En `evidencias/bloque1/` (saneadas: sin direcciones ni datos de VLAN ajenas más allá de sus
números, sin capturas). Las capturas completas quedan privadas en Sensor1
(`~/cyberflow-v2/capturas/<ID>`) y srv-dmz (`~/bloque1/`); aquí solo sus hashes (`SHA256SUMS`).
