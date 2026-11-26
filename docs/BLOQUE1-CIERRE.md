# Cierre del Bloque 1: calidad y trazabilidad de la captura (25/26-nov-2026)

> **Revisión del 26-nov (`BLOQUE1-REVISION-2026-11-26.md`). Este documento NO cierra el Bloque 1.**
>
> - **DNS (§4):** el E3 publicado se contrastó sin el PCAP de DC1. Está corregido y es reproducible
>   desde lo publicado (REVISION §1).
> - **Eventos sin transacción (§4):** son la sonda del preflight de `v2ctl.py`; están explicados
>   (REVISION §2).
> - **Política (§7):** ahora entra en el dictamen (`BLOQUE1-POLITICA-CALIDAD.md`).
> - **Alcance:** B1 **no tiene eventos experimentales**. Las cifras experimentales son de las cinco
>   ejecuciones con generador.
> - **Estado:** el de REVISION, «Estado del Bloque 1». La matriz del §13 está actualizada.
>
> **Segunda revisión del 26-nov (`BLOQUE1-REVISION-2-2026-11-26.md`)**, que prevalece sobre la
> primera: sondas identificadas por ejecución, clave e instante; sondas antes del periodo útil;
> referencia de srv-dmz y DC1 obligatoria; criterio conservador sin fracción de exclusión; §5.1
> repetido con PCAP archivados; §5.2 localizado en el switch (ESXi descartado). T1–E3 quedan
> `no_aprobada` (sonda en ventanas útiles). Paquete: https://github.com/marksato13/inv-cyberflow-v2/releases/tag/bloque1-cierre-2026-11-26

Continúa `BLOQUE1-CALIDAD-CAPTURA.md`, que se conserva como estaba. Lo que este documento corrige
de aquel está en el §12.

**No se han iniciado** el piloto integrado final, las 49 h, ataques ni campañas A/B. Solo se
hicieron pruebas dirigidas: E3, la prueba de cierre con un fallo deliberado y una prueba de 120 s
de `rx_dropped`. Se conservaron los originales, los resultados anteriores y los intentos fallidos
(§11).

Código: `main` de https://github.com/marksato13/inv-cyberflow-v2. En el laboratorio está desplegado
**1cb6cbf**; cada despliegue anterior se guarda como `codigo-<versión>` en cada equipo.
Suite: `python -m pytest -q tests` da **156 pasan** (con la entrada estándar cerrada, como en el
laboratorio).

---

## 1. Comprobador de copias del espejo (`captura/copias_espejo.py`, v2)

**Qué hace.** Una trama del espejo se identifica por:

- protocolo;
- IP de origen y de destino;
- puertos;
- `seq`/`ack`/`flags` en TCP, y tipo e identificador en ICMP;
- `ipid`;
- longitud IP.

Para cada evento se deduce la ruta esperada a partir de `captura/rutas_span.json`: la
configuración del SPAN, las subredes 10/20/30/60/99 con su VLAN y la pasarela `.1`. Con esa ruta se
sabe qué VLAN deben aparecer. Las copias se agrupan por identidad y proximidad temporal.

| Regla | Valor | Por qué |
|---|---|---|
| Ventana de copia | **20 ms** (antes 5 ms) | E3: dos copias llegaron a 5,1 ms, bajo ráfaga (§3) |
| Misma VLAN y mismo TTL ⇒ otra transmisión | nuevo | E3: el cliente envía **dos RST idénticos** (ipid 0) en el mismo instante; llegan 4 copias. Antes se fundían en un evento con «copias de más» |
| Misma VLAN con TTL distinto ⇒ copia en VLAN equivocada | se mantiene | clase `vlan_incorrecta` |
| Grupos a menos de 2 × ventana | `ambiguo`, salvo que el grupo esté completo | con tramas idénticas, cualquier reparto de un grupo completo da los mismos totales |

**Clases.**

- `completo`
- `falta_copia`
- `vlan_incorrecta`
- `copias_de_mas`
- `ambiguo`
- `inesperado`: una ruta sin VLAN esperada.
- `no_determinable`: fuera de las subredes configuradas, o difusión y multidifusión, que el
  fichero declara `no_determinable`.

**Una sola VLAN.** Un evento visto en una sola VLAN no se da por completo: cuenta como
`falta_copia` y se indica la VLAN que falta.

**Entrada dañada.** Ante ficheros ausentes, ilegibles o truncados:

- el resultado es `incompleto`;
- cada problema se registra con el fichero y su intervalo;
- el código de salida es 3.

**Indicios.** `ttl_incorrecto`, `orden_incorrecto`, `carga_distinta` y `mac_igual` se cuentan pero
**no cambian la clase**. En las seis ejecuciones, `ttl_incorrecto` y `orden_incorrecto` coinciden
siempre (50–294 por ejecución). Son eventos en los que la primera copia del grupo trae el TTL menor:
el espejo entregó antes la copia de la segunda VLAN, la misma reordenación del §2. No se
interpretan como pérdida.

**Pruebas.**

- `tests/test_copias_espejo.py`: 12 pruebas. Cubren los 7 casos del encargo y los dos casos reales
  de E3.
- `tests/test_deduplicacion.py`: 6 pruebas, que cubren por separado la deduplicación del extractor.
- `tests/test_extracto.py`.

**Deduplicación del extractor** (`extract_multilayer_v3.deduplicar_espejo`). Está documentada en
`extraccion/README.md` y probada aparte, con los conteos antes y después.

- **Limitación conocida:** la clave no lleva `ack`/`flags` y la ventana es de 5 ms.
- **Efecto de esa limitación en E3:**
  - funde en uno cada par de RST idénticos (16 pares);
  - deja duplicadas las 4 tramas cuyas copias se separaron más de 5 ms.
- **Se corrige en el bloque de características**, no aquí, porque cambia las características y no
  la captura. Hasta entonces queda como pendiente con estos conteos.

## 2. Contraste con el extremo (`captura/comparar_extremo.py`, v2)

**Qué compara.** Cuatro cosas:

- las conexiones, por tupla e ISN, que soportan la reutilización de puertos;
- los eventos de control uno a uno (SYN, SYN-ACK, FIN, RST, ACK puro);
- los datos;
- la cobertura de bytes por conexión y sentido.

**Modo de comparación.**

- **Sin offload:** se comparan paquete a paquete los tamaños, los desfases y las retransmisiones.
- **Con offload:** TSO/GSO/GRO cambian la segmentación vista en el extremo. Se comparan rangos de
  bytes, y el número de paquetes de datos y las retransmisiones quedan **no comprobados**, cosa que
  el informe dice expresamente.

**Alineación temporal.** El desfase se estima por la media de los pares de identidad. Se publican
la mediana, el p99, el máximo, la deriva y si se conserva el orden.

**Correcciones de este cierre**, cada una con su prueba:

- Las transmisiones idénticas no se funden y la ventana de copia pasa a 20 ms (igual que en el §1).
- **SYN reordenado.** En E2, Sensor1 recibió las dos copias del SYN de un cliente 0,85 ms
  **después** del SYN-ACK del servidor; en srv-dmz estaban en orden. El comparador dejaba esa
  conexión como «parcial» y contaba 2 discrepancias falsas. Ahora un SYN que llega hasta
  `--margen-par-s` (50 ms) tarde abre su conexión.

**Pruebas.** `tests/test_comparar_extremo.py`, 13 pruebas.

## 3. Reanálisis antes y después (B1, T1, T2, E1, E2 y E3)

- **Dónde corrió:** en Sensor1, con la versión c7c0b49; el contraste con el extremo se rehizo con
  a845082.
- **Qué lee:** los PCAP originales, solo en lectura. No se ha sobrescrito ningún original.
- **E1** se reanaliza con su copia `pruebas/V2-E1-…original-cd06fcf`.
- **Resultados:** en `evidencias/bloque1/reanalisis/`, con un `SHA256SUMS`.
- **Comando:** `operacion/reanalisis_bloque1.sh`.

**Población experimental:** los clientes 10.10.20.21–26. Antes incluía DC1, lo que metía tráfico
de DC1 con otros equipos. Por eso los denominadores de «antes» y «después» no coinciden.

| Ejecución | Copias, antes (cd06fcf / v1) | Copias, después (v2) | Extremo, antes | Extremo, después | DNS (generador ↔ DC1 ↔ Sensor1) |
|---|---|---|---|---|---|
| B1 (experimental) | sin eventos: no aplica (el «0 faltantes» anterior era vacío) | sin eventos de clientes en la ventana (B1 no tenía generador) | — | — | — |
| B1 (gestión bastión↔Sensor1) | **1 843** faltantes, 7 428 «de más» | **42 418** faltantes (§5) | — | — | — |
| T1 | 0 faltantes, 1 «de más» | **3 888 completos** | — | — | 32/32 coinciden |
| T2 | 0 faltantes, 16 «de más» | **16 791 completos** | — | — | 182/182 coinciden |
| E1 | 0 faltantes, 1 «de más» (RST) | **3 822 completos** | rangos, 0 faltas | rangos, **0 discrepancias** (47 conexiones) | 32/32 coinciden |
| E2 | 0 faltantes, 16 «de más» | **16 341 completos** | rangos, 0 faltas | rangos, **0** (antes de a845082: 2, por el SYN reordenado) | 182/182 coinciden |
| E3 | — (nueva) | **16 088 completos** | paquetes: 21 (herramienta anterior) | **paquetes: 15 663 / 15 663**, 0 discrepancias, tamaños idénticos | 182/182 coinciden |

**Las «copias de más» de antes no eran copias de más.** Eran los pares de RST idénticos (1 en
T1/E1, 16 en T2/E2), ahora contados como dos eventos completos.

**El ensayo con offload desactivado en srv-dmz** es E3, lanzado con
`operacion/prueba_espejo_b3.sh`.

- Se registró `ethtool -k ens35`, se desactivaron TSO, GSO, GRO y LRO, y al final se restauraron.
- La comparación del antes con el después dio **idéntico**.
- tcpdump en el extremo: 15 722 paquetes capturados y 0 descartados por el kernel.

**La aprobación de T1 y T2 no cambia.** El reanálisis demuestra que, para la población
experimental, **no faltó ninguna copia** en T1/T2 pese a los descartes del destino del SPAN. Eso
es evidencia para la propuesta de política (§7), no una reclasificación: T1 y T2 siguen
`no_aprobada` con el criterio vigente.

## 4. DNS: generador ↔ DC1 ↔ Sensor1

**El generador.** Usa un socket UDP crudo directo a DC1 (10.10.10.20), con una consulta por
resolución. No hay caché del sistema operativo ni reintentos, así que «resolución pedida» equivale a
«consulta emitida». El efecto de caché y de TTL no aplica: el TTL de las respuestas se registra
pero no se usa.

**El registrador de DC1** (`servidor/registro_dns_v2.py` 2.0.0) es nuevo; la v1 está en
`servidor/historico/`.

- Toma la marca de tiempo del kernel (`SO_TIMESTAMPNS`).
- Guarda el TTL de cada respuesta A.
- Escribe un PCAP opcional en ns.
- Lee los descartes del socket (`PACKET_STATISTICS`) cada 60 s.
- Prueba en vivo: 40/40 tramas y 0 descartes del socket.
- E3 es la primera ejecución con ese PCAP de DC1 (en el cierre: `pcap_dc1: true`).

**Resultados** (`captura/contraste_dns.py`).

- En las cinco ejecuciones con generador, **todas las transacciones coinciden en los tres puntos**:
  0 discrepancias, 0 timeouts, 0 ambiguas y 0 tramas ilegibles.
- El código de salida 1 se debe solo a `sin_transaccion`: 6 eventos por ejecución, 10 en T1. Es un
  intercambio DNS de 10.10.20.21 que DC1 y Sensor1 (dos copias) ven igual, pero que el registro
  del generador no tiene.
  - **No es pérdida.**
  - Hipótesis, no comprobada: la sonda del preflight o el arranque.

**Reloj de DC1.** En E3, DC1 − Sensor1 da p50 −6,55 ms, p99 −6,0 ms y un máximo de −5,65 ms. A la
vez, el inicio del generador menos la consulta en DC1 da +6,8 ms. Una consulta no puede llegar a
DC1 antes de emitirse, así que **el reloj de DC1 va unos 6,5–7 ms por detrás** del de Clientes y
del de Sensor1, y de forma estable.

- **Contradice** el «+0,6 ms frente a NTP» que da `chronyc` en DC1.
- Hipótesis, no comprobada: DC1 sincroniza con `a.ntp.br` (estrato 3), y Clientes y srv-dmz con
  `ntp.ubuntu.com`.
- **Pendiente:** medir el desfase entre equipos directamente, no contra su propio servidor NTP.
- No afecta al contraste, porque el margen es de 0,5 s.

## 5. Contadores: hechos, explicaciones respaldadas, hipótesis e incertidumbre

**No se atribuye ninguna causa por parecido de porcentajes.** La conclusión de T9 («2,74 % frente a
2,90 %») queda **sustituida** por la de este apartado.

### 5.1 `rx_dropped` de `ens37` en Sensor1

| | |
|---|---|
| **Hecho** (prueba dirigida de 120 s, `captura/rx_dropped_prueba.py`, Sensor1 `bloque1/rx-dropped-r1.json`) | Δ`rx_dropped` = **1 708** = exactamente las tramas 802.3/SNAP etiquetadas del PCAP del mismo intervalo (1 704 PVST+ a 01000ccccccd, pid 010b, y 4 CDP). Δ`rx_packets` 19 037 = tramas del PCAP, 19 037. `rx_nohandler` = 0. `/proc/net/ptype` solo tiene manejadores para ip, arp, ipv6 y mctp |
| **Explicación respaldada** | El kernel entrega esas tramas a los sockets de paquetes (tcpdump y Suricata las ven) y luego las descarta por no tener manejador de protocolo, contándolas en `rx_dropped`. **No es pérdida de captura** |
| **Comprobación retrospectiva** (`captura/clases_tramas.py`, `clases-<ID>.json`) | En las seis ejecuciones, SNAP etiquetadas − Δ`rx_dropped` = **+344 a +425**, nunca negativo. El PCAP empieza unos 30 s antes que el intervalo de los contadores (el anillo ya tenía ficheros), y a unas 14 tramas SNAP/s eso da unas 420 tramas. La retrospectiva es **coherente con la prueba**, pero no exacta, porque los intervalos no coinciden |
| **Incertidumbre** | Una pérdida real en la NIC que se sumara a `rx_dropped` quedaría oculta solo si fuera menor que esa holgura de 344–425. Los indicadores de pérdida que se usan son otros: tcpdump `dropped by kernel` y vmxnet3 `drv dropped`/`rx_missed`, ambos en 0 |

### 5.2 Copias faltantes de gestión en B1 sin descartes contados

La cifra «1 843» de `BLOQUE1-CALIDAD-CAPTURA.md` §6 venía de la herramienta v1, que con tramas
idénticas en ráfaga **infracontaba**: confundía copias faltantes con «copias de más». Con la v2,
para el par bastión 10.10.10.30 ↔ Sensor1 10.10.60.11, por fase de B1 (marcas en
`evidencias/bloque1/V2-B1-…/marcas.jsonl`):

| Fase | Copias faltantes (v2) | Δ`Total output drops` Gi2/0/19 |
|---|---|---|
| F0, fondo de 300 s | 0 | 0 |
| R1, 5 × `tail -n 2000` (≈1 MB) | 3 979 (962 de VLAN 60 y 3 017 de VLAN 10) | +8 |
| R2, 5 × la lectura filtrada (≈8 KB) | 0 | 0 |
| R3, 3 × `scp` de 20 MB sin límite | **38 328** (35 790 de VLAN 60 y 2 538 de VLAN 10) | **+137** |
| R4, 3 × `scp -l 160000` | **111** (52 + 59), unos 0,23 % de los eventos de la fase | **0** |
| F1, fondo de 240 s | 0 | 0 |

**Hecho comprobado en tramas crudas** (segundo 1795631641 de R3):

- Por VLAN 10 pasan 13 843 tramas, 20,9 MB, de bastión → Sensor1, en 0,45 s.
- Por VLAN 60 pasan **1 076**, con el TTL −1 y el mismo ipid y seq.
- La transferencia llegó entera a su destino (TCP).
- Lo que falta siempre es **la segunda copia**, la de después del cortafuegos: la VLAN 60 en
  bastión → Sensor1 y la VLAN 10 en Sensor1 → bastión.

**Explicación respaldada.**

- El espejo pierde copias en ráfagas a velocidad de línea, y el contador del destino del SPAN no
  registra todas esas pérdidas: +137 frente a 38 328.
- Con 160 Mb/s también se pierden copias (111) sin que el contador suba.
- Los contadores del invitado no muestran pérdida: tcpdump 0, `rx_dropped` solo SNAP (§5.1),
  vmxnet3 0.
- Por tanto, la pérdida es anterior a la VM.

**Hipótesis** (no se distingue entre ellas sin acceso a ESXi o a más contadores del switch):

1. replicación del SPAN entre miembros del stack, que no se cuenta en `Total output drops` de
   Gi2/0/19;
2. descarte en `vmnic2`/vSwitch2 del ESXi.

**Dato que falta.** Las estadísticas de `vmnic2` en el ESXi (`esxcli network nic stats get -n
vmnic2`) antes y después de una transferencia: **equipo ESXi, cuenta de Mark**.

**Consecuencia.**

- **La ausencia de incrementos del contador no prueba ausencia de pérdida.**
- Para la población experimental, la evidencia es el comprobador de copias, el extremo y el DNS de
  cada ejecución. En E1–E3 y en T1/T2: **0 copias faltantes**.

**Tráfico excluido.** Las SYN del bastión hacia otros equipos de la VLAN 60 (≈2 cada 50 s, al
puerto 1514) no tienen copia en VLAN 60. Son equipos de otro proyecto: **no se analizan** y no
entran en el extracto publicado (§10).

## 6. Supervisión del destino del SPAN integrada en el lanzador

**Piezas.** `operacion/sondeo_span.py` y `operacion/analizar_sondeo.py`.

**Cómo se lanza.** Es el paso 4b de `lanzar_v2.sh`, antes del archivador.

- Arranca con `--hasta-epoch` igual al tope inicial más 900 s y un intervalo de 2 s.
- El lanzador espera la primera `muestra`. Si no llega en 30 s, deshace el lanzamiento.
- `cerrar_v2.sh` lo detiene por su PID y analiza el periodo de captura en
  `calidad-espejo-sondeo.json`.

**Qué registra cada muestra:**

- hora de envío y de recepción;
- latencia;
- `Total output drops`, paquetes y bytes de salida;
- filas de la cola 1.

**Reconexión:** si cae la sesión SSH al switch, se reconecta, y el hueco queda como
`indeterminado`.

**Clasificación** de cada tramo `[envío_i, recepción_{i+1}]`:

- `sin_descartes`;
- `con_descartes`;
- `indeterminado` en tres casos: antes de la primera muestra, durante un hueco y cuando el contador
  disminuye.

El reloj del switch **no** se usa. El analizador devuelve 0, 1, 2 o 3 (sin registro).

**Medido en E3, con el switch real:**

- 809 muestras;
- intervalo p50 2,16 s y máximo 2,24 s;
- latencia p50 0,16 s y máximo 0,24 s;
- 1 746 s sin descartes, 0 con descartes;
- **34 s `indeterminado` al principio**: el PCAP arranca con ficheros del anillo anteriores al
  lanzamiento. Es margen, 188 s antes del generador, pero se declara.

**Nuevo en `estado_global.py`:** el estado `espejo`.

- Sin `calidad-espejo-sondeo.json`, o con un error, es `sin_datos`, y aparece el motivo
  `falta:espejo`.
- Con un tramo indeterminado es `indeterminado`, también con `falta:espejo`.
- Con descartes es `con_descartes`, que da `no_aprobada`.
- **La falta de supervisión nunca se lee como «sin pérdidas».**
- Pruebas: `tests/test_estado_global.py` (10) y `tests/test_sondeo_span.py` (11, con un switch
  falso).

**Pendientes:** la caída del supervisor durante horas, y si el sondeo de 2 s es aceptable para el
switch en 49 h. Se mide en el bloque 4.

## 7. Política de calidad de captura

### 7.1 Criterio vigente (no cambia)

Se conserva tal cual el criterio con el que se dictaminaron T1 y T2 (C1–C13 de PROTOCOLO §10, en
`estado_global.py` y `evaluar_piloto.py`):

- cualquier aumento de `Total output drops` de Gi2/0/19 durante la supervisión invalida el
  intervalo de supervisión entero (≈305 s) y las ventanas afectadas;
- T1 y T2 siguen **no aprobadas** con ese criterio.

### 7.2 Propuesta (separada; la decide Mark)

| Clase | Evidencia necesaria | Intervalo potencialmente afectado | Entidades afectadas | Acción | Registro |
|---|---|---|---|---|---|
| **Pérdida comprobada** | Un evento de la población con una copia esperada ausente (`falta_copia`/`vlan_incorrecta`), o un evento del extremo o de DC1 sin ninguna copia en Sensor1 | El tramo del sondeo que contiene el evento, `[envío_i, recepción_{i+1}]`. **No** «ráfaga ±1 s»: el instante de la ráfaga no tiene referencia independiente | Las dos IP del evento | Excluir las ventanas de esas entidades cuyo intervalo de antecedentes toque el tramo | `calidad-copias-espejo.json`, `calidad-contraste-dns.json`, `extremo-*.json` y una línea en `invalidaciones.jsonl` con clase, intervalo, entidades y fichero |
| **Impacto indeterminado** | `con_descartes` sin pérdida comprobada en la población; o `indeterminado` (hueco, contador que baja, supervisor caído, sin sondeo); o descartes del socket de DC1 | El tramo del sondeo; en un hueco, desde la última muestra válida hasta la siguiente | **Todas** | Excluir las ventanas afectadas de todas las entidades; si se supera el límite de la ejecución (7.4), la ejecución **no es utilizable** | `calidad-espejo-sondeo.json` + `invalidaciones.jsonl` |
| **Tráfico ajeno identificado** | Descartes cuya composición (`detalle_10ms`) es de gestión, **y** el comprobador de copias da «completo» para la población en el tramo | El mismo | Ninguna de la población; si falta una copia, pasa a «pérdida comprobada» | **Registrar**; si se repite, **detener** y corregir la fuente (como se hizo con el vigía) | `invalidaciones.jsonl` con `accion: registrar` |

Una pérdida de las dos copias no la ve Sensor1. «Sin impacto» solo se puede afirmar con la
referencia independiente: srv-dmz para HTTP/HTTPS y DC1 para DNS. Para el tráfico de la población
sin referencia, la clase «tráfico ajeno» no es aplicable.

**Evidencia nueva de este cierre:**

- en T1/T2 hubo descartes sin pérdida de la población, el caso de «tráfico ajeno»;
- en B1-R4 faltaron copias sin descartes contados (§5.2), así que **los descartes no son la única
  señal**: el comprobador de copias va en cada cierre (`calidad_copias`).

### 7.3 Propagación a ventanas

Una ventana cierra en `cierre` y depende de los paquetes desde `antecedentes_desde`. En el
extractor V2 en modo continuo eso son **230 s** (`--historia-s 230`, `extraccion/verificar_v2.py`):

    ventana afectada  ⇔  [cierre − 230 s, cierre] ∩ intervalo_afectado ≠ ∅

En modo por bloque la historia se corta en la frontera del bloque. **Los 230 s son un dato del
extractor**, no un parámetro libre. Que el estado efectivo del extractor sea de 230 s se verifica
en el bloque de características. `operacion/sesgo_exclusion.py` aplica exactamente esta regla.

### 7.4 Parada y utilizabilidad

- **No** se adopta «más de 3 incidentes por hora» como garantía, ni 160 Mb/s como límite seguro.
  R4 perdió 111 copias de gestión a 160 Mb/s sin que el contador subiera.
- La norma operativa es: **durante una captura no se transfiere nada grande a través del
  cortafuegos**; el cierre copia después.
- Se detiene al primer incidente de pérdida comprobada sin una fuente identificada y corregible, y
  con el sondeo caído más de 15 min.
- La ejecución no es utilizable si la exclusión supera una fracción, que fija Mark, o si elimina de
  forma desproporcionada un perfil o la actividad alta (7.5).

### 7.5 Sesgo de la exclusión (cuantificado)

`operacion/sesgo_exclusion.py` aplicado a los 4 intervalos invalidados de T1 y de T2, con la regla
de 7.3:

| | Ventanas consideradas | Afectadas | Por perfil (afectadas/todas) | Por nivel |
|---|---|---|---|---|
| T1 | 65 | **59 (91 %)** | P1 27/27, P2 14/14, P3 1/1, **P4 0/6**, P5 11/11, P6 6/6 | base 59/65 |
| T2 | 265 | **265 (100 %)** | todos al 100 % | aumentado 72/72, base 52/52, reducido 141/141 |

**La exclusión no es aleatoria.** En T1 elimina todos los perfiles salvo P4, cuyas ventanas cerraban
fuera de los intervalos. Una ejecución no se acepta porque «quedan filas».

**Limitación.** Los cuartiles por paquetes en la ventana salen degenerados (mediana 0), porque la
mayoría de ventanas de estas pruebas cortas tienen 0 paquetes en la ventana. El sesgo por actividad
se medirá con la carga de las 49 h. La herramienta ya lo calcula.

Resultados: `evidencias/bloque1/sesgo/sesgo-*.json`.

## 8. Trazabilidad por prueba

`operacion/trazabilidad.py <ejecución>` genera una ficha JSON. Las fichas están en
`evidencias/bloque1/trazabilidad/`. Contiene:

- **identificadores:** ejecución, programa con su sha256 y unidad DNS;
- **versión del código:** registrada o inferida, y la ficha dice cuál;
- **horas:** planificadas y reales;
- **desvíos y márgenes:** del inicio y fin del generador, y márgenes de captura antes y después;
- **fases del programa:** con su hora UTC;
- **referencia temporal:** NTP de cada equipo y desfases de la supervisión (el reloj del switch no
  es autoritativo);
- **inventario de PCAP/EVE:** ficheros, bytes, huecos y sha256;
- **sha256 de cada fichero** de la ejecución;
- **sondeo, pasos del análisis y dictamen.**

**Estos campos no son atributos del IF.**

Desde c7c0b49 (desplegado el 25-nov a las 23:45Z), `lanzar_v2.sh` escribe `codigo_version` en `lanzamiento.json`. Para las ejecuciones
anteriores la versión es **inferida**:

| Ejecución | Código | Margen antes / después del generador | Huecos PCAP / EVE | Δ`rx_packets` / Δ`rx_dropped` | Dictamen |
|---|---|---|---|---|---|
| T1 | a5c70ab (inferida) | 277,7 s / 133,1 s (arranque 93 s tarde: prueba de arranque tardío) | 0 / 0 | 434 426 / 30 624 | no_aprobada |
| T2 | a5c70ab (inferida) | 183,8 / 133,3 | 0 / 0 | 378 052 / 24 285 | no_aprobada |
| E1 | cc70836 (inferida) | 183,3 / 130,2 | 0 / 0 | 1 132 354 / 29 309 | indeterminada (C7, C9–C13 manuales) |
| E2 | cc70836 (inferida) | 186,2 / 136,3 | 0 / 0 | 966 921 / 24 312 | indeterminada |
| E3 | 60fc6df (VERSION al lanzar) | 187,7 / 135,2 | 0 / 0 | 828 084 / 24 312 | indeterminada |

B1 no es una ejecución del lanzador; su trazabilidad son sus marcas por fase (`marcas.jsonl`) y el
sondeo.

## 9. Pruebas de `cerrar_v2.sh`

| Prueba | Resultado | Evidencia |
|---|---|---|
| Análisis correcto (E1, 25-nov 22:42Z) | los 6 pasos obligatorios con rc 0; `calidad_dns` rc 1 (6 `sin_transaccion`, §4); dictamen `indeterminado`, salida **2**, solo por C7 y C9–C13, que son manuales | `evidencias/bloque1/cierre-pruebas/pasos-analisis-correcto-E1.jsonl`, `resultado-global-correcto-E1.json` |
| Fallo deliberado (`CF_FALLO_PASO=extraer`) | `extraer` rc **97** con `fallo_deliberado: true`; los demás pasos corren; `analisis: incompleto`, `global: no_aprobada`, dictamen `fallido`, salida **1** | `…/cerrar-fallo-extraer-E1.txt`, `pasos-analisis-fallo-extraer-E1.jsonl`, `resultado-global-fallo-extraer-E1.json` |
| Cierre de E3 | igual que el análisis correcto: salida 2 | `evidencias/bloque1/E3/` |

Los pasos `calidad_*` no son obligatorios: informan, y la política del §7 decide qué hacer con
ellos.

## 10. Publicación y paquete reproducible

**En el repositorio:**

- el código y las pruebas;
- la configuración (`captura/rutas_span.json`, programas);
- los resultados estructurados del reanálisis, con sus `SHA256SUMS`;
- las fichas de trazabilidad, las pruebas de cierre y E3;
- las herramientas anteriores en `captura/historico/` y `servidor/historico/`, con un README.

**Paquete reproducible:** el *release* `bloque1-cierre-2026-11-26` de GitHub, con
`paquete-bloque1.tgz`. Por cada ejecución:

- `pcap/live-00000000000000.pcap.gz`: el extracto de `captura/extracto_pcap.py`;
- `copias-desde-extracto.json`;
- para E1–E3, `extremo/srvdmz-<ID>.pcap.gz` y `extremo-desde-extracto.json`.

**Qué contiene el extracto:**

- tramas de los clientes 10.10.20.21–26 **completas**. Su contenido es sintético: generador, zona
  `cf-v2.lab` y servidor del laboratorio;
- tramas bastión 10.10.10.30 ↔ Sensor1 10.10.60.11 **solo con cabeceras** (96 B, con la longitud
  original en el registro), y **solo si los dos extremos son esos**;
- nada más: ni otras VLAN, ni control del switch, ni equipos de otros proyectos, ni tráfico del
  bastión hacia otros equipos. Las tramas descartadas se cuentan por motivo en `extracto-*.json`.

**Reproducibilidad comprobada:** `copias_espejo.py` sobre el extracto da **los mismos conteos**
que sobre la captura en las seis ejecuciones. Por ejemplo:

- E2: 16 341 = 16 341;
- B1, gestión del par: 42 418 faltantes = 42 418.

**Qué no se publica, y por qué:**

| Qué | Por qué | Efecto en el análisis |
|---|---|---|
| Los PCAP completos | Contienen tráfico de otros equipos y proyectos, y la carga cifrada de la gestión | Lo que no es de la población no se puede recalcular desde el paquete: el desglose de 10 ms de todas las VLAN, `clases_tramas` (SNAP/PVST+) y la composición de las ráfagas. Esos resultados se publican como JSON, verificables por hash pero **no recalculables** |
| El EVE completo de Suricata | Incluye flujos de toda la red espejada | Ídem |
| Las credenciales y la configuración privada del switch | Nunca | — |

Los hashes **no sustituyen** la revisión del contenido. Antes de publicar se buscaron en
todos los ficheros de `evidencias/bloque1/` las direcciones IP que no son de la población ni de la
gestión. Solo aparecieron en `copias-V2-B1-…-gestion.json`, el reanálisis de gestión sobre la
captura completa: incluye las identidades de las anomalías del bastión hacia equipos ajenos y hacia
Internet.

- **Ese fichero no se publica.** Queda en Sensor1 y su sha256 está en
  `evidencias/bloque1/SHA256SUMS-privados.txt`.
- Su versión pública es `paquete/V2-B1-…/copias-gestion-desde-extracto.json`, que solo contiene
  el par bastión↔Sensor1 y da las mismas **42 418** copias faltantes.

Tras ese cambio, la búsqueda no encuentra ninguna dirección ajena en lo publicado.

## 11. Conservación

- **Originales de E1:**
  - bastión `~/cyberflow-v2/ejecuciones/V2-E1-…original-cd06fcf`;
  - Sensor1 `pruebas/V2-E1-…original-cd06fcf`.
- **El cierre correcto de E1, antes del fallo deliberado:** `registros/pasos-analisis.20261125T234852Z.jsonl`.
- **Los resultados del comparador sobre E3 con versiones anteriores:**
  - `extremo-V2-E3-….json.prueba-b3-60fc6df`;
  - `*.c7c0b49`.
- **El paquete anterior:** `bloque1/paquete.antes-<epoch>`.
- **El código anterior:** `codigo-<versión>` en cada equipo.
- **Intentos fallidos:** se conservan en `evidencias/bloque1/`. Entre ellos, `b2-intento1-fallido.txt`
  y el commit 018fdd3, que entró con 11 pruebas fallidas por WinError 6 (corregido en c11cdde).

## 12. Correcciones a la documentación anterior

| Documento | Decía | Corrección |
|---|---|---|
| `PENDIENTES.md` fila 14 y `INFORME-PRUEBAS` T9 | «`rx_dropped` = tramas sin manejador; 2,74 % frente a 2,90 %» | La conclusión es correcta, pero la prueba era un parecido de porcentajes. **Sustituida** por la igualdad exacta de §5.1 |
| `PENDIENTES.md` fila 31 | «Probablemente tramas sin manejador; no demostrado» | Demostrado (§5.1). La fila 14 contradecía a la 31: ahora las dos remiten al §5.1 |
| `PROTOCOLO.md` §8 | «`rx_dropped` sube entre un 4 y un 6 %… sigue abierta» | Cerrada (§5.1) |
| `BLOQUE1-CALIDAD-CAPTURA.md` §6.1 | «1 843 copias faltantes» | 42 418 con la v2 (§5.2); 1 843 venía de la v1 |
| Varios | «42 h» frente a «49 h» | El programa vigente son **49 h**, siete segmentos de una sola captura continua (`CONTRATO-GENERADOR-49H.md`). «42 h» es el programa anterior (siete jornadas de 6 h) y se conserva solo en los documentos históricos |
| `PROTOCOLO.md` §5 frente a §Tiempos | §5: «el preflight comprueba que la jornada no cruza las 00:00 UTC»; §Tiempos: «la primera noche cruza» | Vigente (`v2ctl.py` preflight): cruzar las 00:00 UTC está **permitido** y la comprobación es **informativa**. El archivador sigue el EVE a través de la rotación y la clasifica en `eve/huecos.jsonl`. `exclusion_v1.py` amplía sola la regla V1 cuando el tope pasa de las 00:00; en E3 quedó `*@2026-11-25T22:50:32/2026-11-26T01:39:02`. La rotación real **sigue sin verificarse** en una captura (PENDIENTES 15) |
| `PROTOCOLO.md` (criterio) | criterios antiguos (v1 «sin cruzar las 00:00») | El criterio vigente es la versión 2 (PROTOCOLO §10) más el estado `espejo` del §6 |
| Configuración vigente | — | SPAN 1: Gi1/0/23 y Gi2/0/23 (both) → Gi2/0/19, encapsulación replicate, `mtu 9198` en Gi2/0/19 (running-config; falta `write memory`, Mark). Offload de srv-dmz activado, como de fábrica |

## 13. Dictamen del Bloque 1

| Requisito | Comprobación | Resultado | Evidencia | Limitación | Estado |
|---|---|---|---|---|---|
| 1. Comprobador de copias | 12 + 6 pruebas; 6 ejecuciones reales; extracto reproducible | Experimental: 0 faltantes en las **5 con generador** (B1 sin eventos experimentales: no aplica). Gestión de B1: 42 418 | `reanalisis/copias-*.json`, `tests/test_copias_espejo.py` | Una pérdida de las dos copias no es visible sin referencia | **Cerrado** (reproducido) |
| 1b. Deduplicación del extractor | 6 pruebas, conteos documentados | Funde los RST idénticos y no empareja copias a más de 5 ms | `extraccion/README.md` | Se corrige en el bloque de características | **Pendiente (bloque 3)** |
| 2. Contraste con el extremo | 13 pruebas; E1–E3 | 0 discrepancias; E3 paquete a paquete 15 663/15 663 | `reanalisis/extremo-*.json` | Con offload, el número de paquetes de datos no es comprobable | **Cerrado** |
| 3. DNS | 11 + 8 pruebas; 5 ejecuciones; E3 con PCAP de DC1 | Todas las transacciones coinciden. Los `sin_transaccion` son la sonda del preflight (explicada). E3 con las tres fuentes: 182/182 | `dns-entradas/`, `sonda-preflight/`, reproducción 6/6 idéntica | Reloj de DC1 a −6,5/−7 ms, sin causa (bloque 4). Sonda: 23 ventanas de .21 por ejecución sin excluir aún (bloque 3) | **Hecho (reproducido)**; tratamiento definitivo de la sonda pendiente |
| 4. Reanálisis antes/después | 6 ejecuciones, originales intactos | Tabla del §3 | `evidencias/bloque1/reanalisis/` | Denominadores distintos por la población | **Cerrado** |
| 5. Contadores | Prueba dirigida + retrospectiva | `rx_dropped` = SNAP (conteo exacto). Pérdida de gestión sin contador | §5; `rx-dropped-r1.json` publicado | PCAP de la prueba de 120 s rotado: la igualdad trama a trama (1 704 PVST+ y 4 CDP) no es revisable. Lugar de la pérdida de gestión (switch o ESXi) sin localizar | **Abierto**: la localización necesita los accesos de REVISION §8 |
| 6. Sondeo en el lanzador | 11 pruebas + E3 real | 809 muestras, 0 descartes; hueco inicial declarado | `E3/calidad-espejo-sondeo.json` | No ejercitado durante horas | **Cerrado (horas: bloque 4)** |
| 7. Política | Integrada en `estado_global.py`; 16 pruebas; las 5 ejecuciones redictaminadas | Pérdida o entrada dañada = fallo; evidencia ausente o que no decide = indeterminado. Sin umbrales elegidos | `BLOQUE1-POLITICA-CALIDAD.md`, `redictamen/` | Faltan decisiones de Mark: fracción máxima de exclusión, extremo en srv-dmz durante las 49 h, tratamiento definitivo de la sonda | **Integrada; pendiente de 3 decisiones** |
| 8. Trazabilidad | Ficha por ejecución | 5 fichas | `trazabilidad/` | Versión inferida antes de c7c0b49 | **Cerrado** |
| 9. `cerrar_v2.sh` | Caso correcto + fallo deliberado | Salidas 2 y 1, coherentes | `cierre-pruebas/` | — | **Cerrado** |
| 10. Publicación | Repositorio + release; reproducibilidad | Extracto = captura | §10 | Lo que no es de la población no es recalculable | **Cerrado** |

**Conclusión.** Sustituida por el estado de `BLOQUE1-REVISION-2026-11-26.md`: el Bloque 1 **no
está cerrado**. Las herramientas y la política están hechas y probadas, y el DNS es reproducible.
Quedan las decisiones de política y la localización de la pérdida de gestión. El texto que sigue
se conserva como estaba el 26-nov por la mañana:

~~El Bloque 1 queda cerrado en lo técnico: las herramientas están verificadas con pruebas y con
datos reales, y los resultados se reproducen desde lo publicado.~~ Queda:

- **decisión de Mark:** la política (§7.2), el filtro de VLAN en la sesión SPAN o
  `queue-softmax`, y `write memory`;
- **acceso de Mark:** las estadísticas de `vmnic2` del ESXi, para localizar la pérdida silenciosa
  del espejo;
- **bloque 3:** la deduplicación del extractor.

Nada de eso impide medir: cada cierre ejecuta el comprobador de copias, el DNS y el sondeo, y su
falta se declara como `falta`.

**Todo queda detenido:** sin generador, archivador, sondeo ni tcpdump en srv-dmz; offload de
srv-dmz restaurado; unidad DNS de E3 parada. Ni el piloto final ni las 49 h tienen autorización de
inicio.

## 14. Comandos

    # pruebas (portátil)
    python -m pytest -q tests

    # despliegue (bastión, gadmin; rechaza si hay una ejecución en curso)
    git archive --format=tar.gz -o codigo-<c>.tgz <c>      # en el portátil
    bash ~/cyberflow-v2/codigo/operacion/desplegar_codigo.sh /tmp/codigo-<c>.tgz <c>

    # reanálisis (Sensor1, m4rk)
    IDS="V2-B1-… V2-T1-…" bash ~/cyberflow-v2/codigo/operacion/reanalisis_bloque1.sh

    # ensayo con offload desactivado y extremo (bastión)
    bash ~/cyberflow-v2/codigo/operacion/prueba_espejo_b3.sh <programa>

    # cierre con fallo deliberado (bastión)
    CF_FALLO_PASO=extraer bash ~/cyberflow-v2/codigo/operacion/cerrar_v2.sh <ID>

    # ficha de trazabilidad (bastión)
    python3 ~/cyberflow-v2/codigo/operacion/trazabilidad.py ejecuciones/<ID> --programas codigo/programas

    # reproducir desde el paquete publicado (cualquier equipo con Python 3)
    tar -xzf paquete-bloque1.tgz
    python3 captura/copias_espejo.py paquete/<ID>/pcap --salida c.json
    python3 captura/copias_espejo.py paquete/V2-B1-…/pcap --ips 10.10.10.30,10.10.60.11 --salida g.json
    gzip -dc paquete/<ID>/extremo/srvdmz-<ID>.pcap.gz > e.pcap
    python3 captura/comparar_extremo.py --extremo e.pcap --sensor paquete/<ID>/pcap --salida x.json
