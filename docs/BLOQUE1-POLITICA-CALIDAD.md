# Política de calidad de captura (Bloque 1, revisada el 26-nov-2026, segunda revisión)

Sustituye la **propuesta** de `BLOQUE1-CIERRE.md` §7.2 en lo que se refiere al dictamen. El
criterio C1–C13 de PROTOCOLO §10 sigue igual. Las comprobaciones de calidad (`calidad_copias`,
`calidad_dns`, `calidad_extremo`, `calidad_sonda`) **entran en el dictamen**.

Implementada en `operacion/estado_global.py` (`calidad_*()`, `exclusiones()` y las tablas
`fallos`/`faltantes`) y probada en `tests/test_estado_global_calidad.py`,
`tests/test_estado_global.py` y `tests/test_sonda_margen.py`. Cambios frente a la primera
revisión: el extremo y la sonda pasan a ser **obligatorios**; desaparece la «fracción máxima de
exclusión» como vía para aprobar (§6).

## 1. Criterio conservador

**Ninguna ejecución definitiva se aprueba**:

- con **pérdida experimental comprobada** (una copia de la población que falta, una conexión que
  vio srv-dmz y Sensor1 no, una discrepancia DNS), o
- con **evidencia obligatoria indeterminada o ausente** (copias, DNS —con el PCAP de DC1 cuando el
  registrador lo declara—, extremo, sonda registrada).

No se ha fijado ningún porcentaje de pérdida ni de exclusión «aceptable». No hay forma de
justificar un número antes de ver los datos, y elegirlo después favorecería el resultado.

## 2. Tres desenlaces, con definición operativa

| Desenlace | Definición | Estado global |
|---|---|---|
| **Fallo** | La evidencia existe, es legible y muestra un defecto | `no_aprobada` (código 1) |
| **Indeterminación** | Falta evidencia obligatoria, o existe pero no permite decidir | `indeterminada` (código 2), motivo `falta:<estado>` |
| **Evento explicado** | Un evento que no encaja con lo esperado, con su origen **acreditado** por un registro y una regla probada | Se registra; no cambia el estado si no toca ventanas útiles |

Si en una ejecución hay a la vez un fallo y una indeterminación, el fallo prevalece: una falta de
evidencia no tapa una pérdida.

## 3. Copias del espejo (`calidad-copias-espejo.json`, `captura/copias_espejo.py`)

Población: clientes 10.10.20.21–26, con rutas y VLAN conocidas hacia DC1 y srv-dmz.

| Estado | Condición | Desenlace |
|---|---|---|
| `completo` | Entrada completa y todos los eventos de la población en `completo` | — |
| `perdida` | Algún evento en `falta_copia` o `vlan_incorrecta` | **Fallo** |
| `entrada_danada` | `entrada_completa` falsa o `resultado_global` ≠ `examinado_completo` | **Fallo** |
| `indeterminado` | Algún evento `ambiguo`, `copias_de_mas`, `inesperado`, `no_determinable` o de clase desconocida | Indeterminación |
| `sin_eventos` / `sin_datos` | 0 eventos de la población / fichero ausente o ilegible | Indeterminación |

Una pérdida de **las dos** copias no la ve Sensor1: la detectan las referencias independientes
(§4 y §5), que por eso son obligatorias.

## 4. DNS (`calidad-contraste-dns.json`, `captura/contraste_dns.py`)

| Estado | Condición | Desenlace |
|---|---|---|
| `completo` | Toda transacción comprobada y sin discrepancias; todo evento sin transacción **explicado con un registro `v2ctl`**; 0 tramas ilegibles; PCAP de DC1 usado si el registrador lo declara | — |
| `discrepancia` | `discrepancias` > 0 | **Fallo** |
| `entrada_danada` | El contraste no pudo leer sus entradas | **Fallo** |
| `indeterminado` | Transacciones ambiguas, `indeterminado_dc1`, no determinables o no comprobadas; algún evento sin transacción no explicado o **incierto**; explicaciones solo con registros **reconstruidos**; tramas ilegibles; resultado en formato antiguo con eventos sueltos | Indeterminación |
| `falta_pcap_dc1` | El registrador declara un PCAP y el contraste no lo usó | Indeterminación |
| `sin_transacciones` / `sin_datos` | | Indeterminación |

Tramas recortadas: una trama recortada por el snaplen cuya cabecera excluye DNS no cuenta como
ilegible; una que podría ser DNS, sí.

## 5. Referencia del extremo (`calidad-extremo.json`, `captura/comparar_extremo.py`)

| Estado | Condición | Desenlace |
|---|---|---|
| `completo` | srv-dmz y Sensor1 ven las mismas conexiones y eventos de la población | — |
| `perdida` | Conexiones o eventos que vio srv-dmz y no Sensor1 (`conexiones_solo_extremo`, `sin_sensor`) | **Fallo** |
| `entrada_danada` | La copia del PCAP del extremo no coincide con su sha256 de origen (`.danado`) | **Fallo** |
| `indeterminado` | tcpdump de srv-dmz con descartes del núcleo o sin estadísticas, sin periodo común, algo visto solo por Sensor1, discrepancias, retransmisiones que no coinciden | Indeterminación |
| `sin_datos` | Sin captura del extremo o sin comparación | Indeterminación |

## 6. Sonda del preflight y exclusiones

**Sonda** (`calidad-sonda.json`, `operacion/ventanas_sonda.py`): las sondas DNS/HTTP/HTTPS del
preflight salen de una IP de la población. Desde el 26-nov se hacen **antes del periodo útil**
(margen de 240 s = horizonte 230 + paso 10, derivado del extractor) y se registran con su clave
completa (BLOQUE1-REVISION-2 §2–§4).

| Estado | Condición | Desenlace |
|---|---|---|
| `completo` | Ninguna ventana útil tiene una sonda en su historia, con registro `v2ctl` | — |
| `contaminacion` | Alguna ventana útil (no excluida por una guarda planificada) tiene la sonda en su historia de 230 s | **Fallo** |
| `indeterminado` | Sin contaminación, pero con registro reconstruido (no acredita el instante exacto) | Indeterminación |
| `sin_datos` | Sin registro de sondas o sin resultado | Indeterminación |

**Guardas planificadas frente a exclusiones por incidente** (`estado_global.exclusiones()`):

| Clase | Qué | Cuándo se fija |
|---|---|---|
| **Guarda / margen planificado** | E1 (frontera de la captura y de bloque), E5 (fuera del programa), margen de sonda 240 s, captura previa 150 s, margen final 120 s | Antes de capturar; constan en `lanzamiento.json → guardas_planificadas` |
| **Exclusión por incidente** | E2–E4 del extractor e invalidaciones de la supervisión | Después, por algo que pasó |

Las guardas planificadas forman parte del diseño y no afectan a la aprobación. Una exclusión por
incidente se informa con su cuenta, pero **nunca convierte una pérdida comprobada en aprobación**.
No existe fracción de exclusión que lo permita.

## 7. Otros eventos explicados

- **`rx_dropped` = tramas 802.3 SNAP (PVST+ y CDP)** sin manejador de protocolo en el invitado
  (BLOQUE1-REVISION-2 §7, con extracto publicado). No es pérdida; no entra en el dictamen.
- **Descartes del destino del SPAN por tráfico ajeno identificado** (CIERRE §7.2): siguen siendo
  `con_descartes` en el estado `espejo`.

## 8. Parada

- **Sondeo sin muestras más de 15 min:** se detiene (cualquier hueco ya es `indeterminado`; los
  15 min son solo el tiempo de captura que se acepta perder antes de intervenir).
- **Primer `con_descartes` del sondeo:** se registra, y se detiene si no hay una fuente identificada
  y corregible. Durante una captura no se transfiere nada grande por el cortafuegos: la pérdida de
  copias en microrráfagas está localizada en el switch (BLOQUE1-REVISION-2 §9).
- **Al cerrar:** el dictamen aplica §3–§6.

## 9. Qué queda abierto

- El tratamiento paquete a paquete de la sonda en el extractor (Bloque 3) deja de ser necesario
  para las capturas nuevas (la sonda ya no toca ventanas útiles), pero las ejecuciones antiguas
  T1–E3 siguen `no_aprobada` por contaminación.
- Deduplicación, relojes, rotación del EVE y supervisión prolongada: bloques 3 y 4.
