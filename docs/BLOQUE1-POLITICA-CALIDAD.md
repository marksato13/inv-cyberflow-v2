# Política de calidad de captura (Bloque 1, revisión del 26-nov-2026)

Sustituye la **propuesta** de `BLOQUE1-CIERRE.md` §7.2 en lo que se refiere al dictamen. El
criterio C1–C13 de PROTOCOLO §10 sigue igual. Lo que cambia es que las comprobaciones de calidad
(`calidad_copias`, `calidad_dns`) **entran en el dictamen**: antes podían fallar sin impedir una
aprobación.

Está implementada en `operacion/estado_global.py` (`calidad_copias()`, `calidad_dns()` y la
tabla `fallos`), y probada en `tests/test_estado_global_calidad.py` (16 pruebas).

## 1. Principio: no hay umbrales elegidos

No se ha fijado ningún porcentaje de pérdida «aceptable». La razón es que no hay forma de
justificar un número **antes** de saber qué cambia en las características. Una copia que falta en
la población altera el registro del que aprende el IF, y cuánto lo altera depende de la ventana.
Elegir un umbral después de ver los datos favorecería el resultado. Por eso:

- A nivel de evidencia, la tolerancia es **cero**: cualquier pérdida comprobada en la población es
  un fallo.
- La única vía para usar una ejecución con pérdida es **excluir** las ventanas afectadas con la regla
  del §7.3 de `BLOQUE1-CIERRE.md`. Esa vía exige una fracción máxima de exclusión que **fija Mark
  antes de la captura de 49 h**, sin conocer sus resultados. Mientras no esté fijada, una ejecución
  con pérdida comprobada es `no_aprobada`.

## 2. Tres desenlaces, con definición operativa

| Desenlace | Definición | Estado global |
|---|---|---|
| **Fallo** | La evidencia existe, es legible y muestra un defecto | `no_aprobada` (código 1) |
| **Indeterminación** | Falta evidencia obligatoria, o la evidencia existe pero no permite decidir | `indeterminada` (código 2), con motivo `falta:<estado>` |
| **Evento explicado** | Un evento que no encaja con lo esperado, cuyo origen está identificado con evidencia y cuya regla de identificación está probada | Se registra; no cambia el estado. Si contamina ventanas, se excluyen (§5) |

Si en una misma ejecución hay a la vez un fallo y una indeterminación, el fallo prevalece. Así, una
falta de evidencia no puede tapar una pérdida.

## 3. Copias del espejo (`calidad-copias-espejo.json`, `captura/copias_espejo.py`)

La población son los clientes 10.10.20.21–26. Sus eventos van a DC1 o a srv-dmz, que son rutas
con VLAN conocidas, de modo que todos sus eventos son determinables.

| Estado | Condición | Desenlace | Por qué |
|---|---|---|---|
| `completo` | Entrada completa y todos los eventos de la población en `completo` | — | |
| `perdida` | Algún evento en `falta_copia` o `vlan_incorrecta` | **Fallo** | Es una copia esperada que no está: un defecto comprobado del registro |
| `entrada_danada` | `entrada_completa` falsa o `resultado_global` distinto de `examinado_completo` (ficheros ausentes, ilegibles o truncados) | **Fallo** | La captura está dañada: es un defecto conocido, no una falta de información |
| `indeterminado` | Algún evento `ambiguo`, `copias_de_mas`, `inesperado` o `no_determinable`, o una clase desconocida | Indeterminación | No se puede afirmar ni pérdida ni completitud |
| `sin_eventos` | 0 eventos de la población | Indeterminación | En una ejecución con generador es imposible; indica que el análisis no vio lo que debía |
| `sin_datos` | Fichero ausente o ilegible | Indeterminación | Evidencia obligatoria ausente |

**Limitación declarada.** Una pérdida de **las dos** copias no la ve Sensor1. Solo la detecta una
referencia independiente: srv-dmz (`comparar_extremo.py`) para HTTP/HTTPS y DC1 para DNS. Para DNS
la referencia es obligatoria (§4). Para HTTP/HTTPS, el extremo solo se ha capturado en E1–E3.
**Decisión de Mark:** si en las 49 h se captura también en srv-dmz. Hasta que lo decida, el
contraste con el extremo **no entra en el dictamen**, y la limitación aparece en el informe de cada
ejecución.

## 4. DNS (`calidad-contraste-dns.json`, `captura/contraste_dns.py`)

| Estado | Condición | Desenlace | Por qué |
|---|---|---|---|
| `completo` | Toda transacción comprobada y sin discrepancias; todo evento sin transacción explicado; 0 tramas ilegibles; PCAP de DC1 usado si el registrador lo declara | — | |
| `discrepancia` | `discrepancias` > 0 | **Fallo** | Las tres fuentes se contradicen |
| `entrada_danada` | El contraste no pudo leer sus entradas (`error`) | **Fallo** | Igual que en copias |
| `indeterminado` | Alguna transacción `ambigua`, `indeterminado_dc1` (descartes del socket de DC1) o `no_determinable`, o `comprobadas` ≠ `transacciones`, o algún evento sin transacción **no explicado**, o alguna trama ilegible | Indeterminación | No se puede decidir; un evento no explicado de la población es tráfico sin etiqueta |
| `falta_pcap_dc1` | El registrador declara un PCAP (`pcap` en su arranque) y el contraste no lo usó | Indeterminación | La tercera fuente es obligatoria cuando existe. Es exactamente lo que pasó con el E3 publicado |
| `sin_transacciones` | 0 transacciones DNS | Indeterminación | |
| `sin_datos` | Fichero ausente o ilegible | Indeterminación | |

**Un resultado de una versión anterior** sin `sin_transaccion_clasificacion` no se aprueba con
eventos sueltos: todos cuentan como no explicados.

**Tramas recortadas.** `contraste_dns.py` ya no cuenta como «ilegible» una trama recortada por el
snaplen si su cabecera excluye DNS (no es UDP, o es UDP sin el puerto 53). El extracto publicado
deja la gestión en 96 B y daba unas 100 000 tramas «ilegibles» que no eran DNS. Una trama
recortada que **podría** ser DNS, o una trama dañada sin recorte declarado, sigue siendo ilegible.
En el laboratorio el número es 0 y el resultado queda idéntico.

## 5. Eventos explicados

Un evento solo se explica con una regla que esté **en el código, probada, y que no pueda casar por
accidente con tráfico del programa**. Hoy hay una:

| Evento | Regla | Prueba | Tratamiento |
|---|---|---|---|
| Sonda DNS de `v2ctl.py` | id 17611 (`random.Random(1).randint(0, 65535)`, semilla fija del preflight) y nombre `portal.*` | `tests/test_contraste_dns_sonda.py`: la constante se deriva del propio `v2ctl.py`. Si cambian la semilla o el nombre, la prueba falla y el evento vuelve a ser «no explicado», nunca al revés | Se registra en `sin_transaccion_clasificacion`. Las ventanas de la entidad cuya historia (230 s) contiene la sonda deben excluirse: son **23 ventanas de 10.10.20.21 por ejecución**, calculadas con `operacion/ventanas_sonda.py`. **Hoy se calculan pero no se aplican solas**: `cerrar_v2.sh` no escribe todavía esa exclusión en `invalidaciones.jsonl` (Bloque 3) |

Otros eventos ya explicados con evidencia, que no pasan por esta regla:

- **`rx_dropped` = tramas SNAP/PVST+** (CIERRE §5.1). No es un indicador de pérdida y no entra en
  el dictamen.
- **«Tráfico ajeno identificado»** (CIERRE §7.2). Son descartes del destino del SPAN con la
  población completa. Sigue siendo `con_descartes` en el estado `espejo`, porque el criterio
  vigente no cambia (CIERRE §7.1).

## 6. Exclusión y utilizabilidad

- La regla de propagación a ventanas es la del CIERRE §7.3: una ventana está afectada si
  `[cierre − 230 s, cierre]` toca el intervalo afectado.
- Las exclusiones se registran en `invalidaciones.jsonl` con clase, intervalo, entidades y fichero.
- Una ejecución con exclusiones solo es utilizable si la fracción excluida no supera el límite que
  fije Mark **antes** de las 49 h. También deja de serlo si elimina de forma desproporcionada un
  perfil o la actividad alta; `operacion/sesgo_exclusion.py` lo cuantifica.
- **Mientras no haya límite**, ninguna exclusión por pérdida convierte una ejecución en
  utilizable. La exclusión de la sonda es independiente: es un evento explicado, no una pérdida.

## 7. Parada

Durante la captura solo hay señales en vivo del sondeo del SPAN y de la supervisión. El
comprobador de copias y el contraste DNS se ejecutan al cerrar.

- **Sondeo sin muestras más de 15 min:** se detiene. Los 15 min no deciden ningún resultado, porque
  cualquier hueco ya es `indeterminado`. Es solo el tiempo de captura que se acepta perder antes de
  intervenir.
- **Primer `con_descartes` del sondeo:** se registra, y se detiene si no hay una fuente
  identificada y corregible. Es la norma del CIERRE §7.4: durante una captura no se transfiere nada
  grande por el cortafuegos.
- **Al cerrar:** el dictamen aplica §3 y §4. Un fallo invalida la ejecución entera hasta que se
  aplique la vía de exclusión del §6.

## 8. Qué queda pendiente de decisión (Mark)

1. La fracción máxima de exclusión (§6), antes de las 49 h.
2. Si se captura en srv-dmz durante las 49 h, para cubrir la pérdida de las dos copias en
   HTTP/HTTPS (§3).
3. El tratamiento definitivo de la sonda. La exclusión de las 23 ventanas es **temporal**. La
   alternativa es que `v2ctl.py` registre la sonda (instante, puerto, id) y que el extractor la
   quite paquete a paquete. Es trabajo del Bloque 3, porque toca el extractor.
