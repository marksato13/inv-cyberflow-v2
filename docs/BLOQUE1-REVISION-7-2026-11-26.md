# Bloque 1 — 7.ª revisión (26-nov-2026): Suricata por intervalos, continuidad con uptime y paso de cierre comprobado

Atiende la revisión de R6. **No se inició** el piloto final ni las 49 h, no se capturó nada y no se
tocaron SPAN ni búferes. Los originales y los complementos r4, r5 y r6 se conservan sin cambios. El
reanálisis se hizo sobre copias nuevas (Sensor1 `~/cyberflow-v2/reanalisis/f0f10e8/`). El laboratorio
queda parado.

Código: **f0f10e8** (desplegado y verificado por hash: bastión, Sensor1 y clientes con 0 diferencias;
`registro_dns_v2.py` de DC1 sin cambios).

## 1. Continuidad sin uptime

**Defecto (r6).** La continuidad solo se comprobaba si las dos muestras traían `uptime`. Si faltaba, no
había forma de detectar un reinicio, y dos muestras sin ese campo que acotaran el periodo salían
`presente` con C9 aprobado. Un reinicio que pusiera los contadores a 0 y volviera a subirlos por encima
del valor anterior quedaría oculto.

**Corrección.** Basta con que **una** muestra usada no tenga `uptime` para que la continuidad no sea
verificable. El estado pasa a `insuficiente` («sin uptime en N muestras: continuidad no verificable»),
C9 queda en None y el dictamen en `indeterminada`. Nunca sale `presente`. Un aumento de `kernel_drops`
entre dos muestras sigue siendo pérdida demostrada aunque falte el `uptime` (§2).

En el **vigía** se hicieron dos cambios:

- una lectura sin `uptime` pasa a `sin_uptime` y su `kernel_drops` queda en None: no completa la supervisión. Si `kernel_drops_leido` aumenta, la supervisión sí se invalida;
- la continuidad se mide ahora como en C9: el `uptime` debe avanzar lo mismo que las marcas de tiempo de las muestras. Antes solo se detectaba un `uptime` que retrocedía, así que un salto hacia delante también es ahora un reinicio.

## 2. Pérdida demostrada frente a evidencia insuficiente

**Defecto (r6).** Un periodo de 24 s, con muestras justo en sus extremos y `kernel_drops` de 0 a 3,
salía `insuficiente` por el hueco de 24 s. Así se perdía una pérdida demostrada dentro del periodo.

**Corrección.** `evaluar` trabaja ahora por intervalos entre muestras consecutivas. Toma las muestras
desde la última en o antes del inicio hasta la primera en o después del fin, y clasifica cada intervalo
`[t_i, t_i+1]`:

| Clase | Qué es | Un aumento de `kernel_drops` en él |
|---|---|---|
| **atribuible** | entero dentro de `[inicio, fin]` | ocurrió en el periodo: **pérdida demostrada** |
| **ampliado** | cruza el inicio o el fin | solo se localiza en el intervalo exterior ampliado: pudo ocurrir fuera del periodo |

Un aumento es pérdida demostrada en su intervalo **aunque falten** continuidad, `uptime` u otras
muestras. Si el proceso se hubiera reiniciado dentro del intervalo, el contador nuevo solo cuenta
descartes posteriores a su arranque, que también caen dentro del intervalo; en ese caso se cuenta como
cota inferior.

**Precedencia** (el fallo manda sobre la falta de evidencia):

| Estado | Cuándo | C9 | Dictamen |
|---|---|---|---|
| `perdida` | algún aumento atribuible (aunque además falte evidencia; se registra en `falta_evidencia`) | False | `no_aprobada` |
| `reinicio` | `uptime` discontinuo o contadores que retroceden | False | `no_aprobada` |
| `perdida_no_localizada` | solo aumentos en intervalos ampliados | None | `indeterminada` |
| `ausente` | alguna muestra sin `kernel_drops`/`kernel_packets` | None | `indeterminada` |
| `insuficiente` | sin acotar, huecos > 16 s, una sola muestra o sin `uptime` | None | `indeterminada` |
| `presente` | acotado, sin huecos, `uptime` continuo en todas y Δ 0 | True | — |

`perdida_no_localizada` no es fallo, porque no está demostrado que la pérdida ocurriera en el periodo.
Tampoco es aprobación, porque no se puede descartar. Se guardan por separado
`delta_kernel_drops_atribuible`, `delta_kernel_drops_ampliado` e `intervalos_con_perdida`: cada intervalo
con su inicio, su fin, el aumento y la clase.

Esto cambia un caso de la 6.ª revisión. Un descarte que solo aparece en la muestra posterior al fin cae
en un intervalo ampliado: antes daba `no_aprobada`; ahora da `indeterminada`, con la pérdida
registrada. Un descarte posterior a la última supervisión periódica, pero entre dos muestras del
periodo, sigue dando `no_aprobada`. PROTOCOLO §10 (C9 e invalidación) se actualizó.

## 3. Paso de cierre (`cerrar_v2.sh`): comprobado

**Defecto encontrado al probarlo.** Al reescribir el paso en esta revisión, la línea
`log suricata_stats_ventana …` quedó unida al comentario siguiente, sin salto de línea. El paréntesis
de ese comentario habría producido un error de sintaxis en el cierre real. La prueba del fragmento lo
detectó antes de publicar. Una prueba nueva ejecuta `bash -n` sobre todos los `operacion/*.sh`. El código
desplegado en r6 (2a3478b) no tenía el defecto.

**Cómo queda el paso:**

- Ejecuta una sola orden por ssh: `suricata_stats.py ventana … --reintentos 4 --espera 6`.
- `ventana_cierre` repite la lectura **solo** mientras falte la muestra posterior al fin. Las demás insuficiencias no mejoran esperando.
- La salida se escribe en un temporal y se renombra, así que nunca queda un fichero a medias.
- Códigos de salida:

  | rc | Significado |
  |---|---|
  | 0 | decidido |
  | 3 | sin decidir al agotar los intentos |
  | 4 | EVE ausente o ilegible: no escribe salida y borra una anterior |
  | 5 | manifiesto ilegible |

- El cierre registra el rc y continúa (`|| rc_ventana=$?`). C9 trata los rc 3 a 5 como falta de evidencia.

**Pruebas controladas sin tocar ejecuciones originales:**

| Nivel | Casos | Resultado |
|---|---|---|
| `tests/test_cierre_ventana.py`: función | extracción al primer intento; muestra posterior retrasada (2 esperas y luego presente); reintentos agotados (rc 3, 4 intentos, 3 esperas); otra insuficiencia sin reintento; EVE ausente (rc 4, sin salida y borrada la anterior); EVE ilegible (rc 3, `sin_eventos`); manifiesto ilegible (rc 5) | 7/7 |
| `tests/test_cierre_ventana.py`: **fragmento real** de `cerrar_v2.sh`, con bash y un `ssh` falso que ejecuta la orden en local | rc 0 con salida que C9 usa (`presente`); EVE ausente (rc 4 registrado, el cierre continúa, C9 None); manifiesto ilegible (rc 5, continúa); el paso va antes de `revisar_criterios`; `bash -n` de todos los guiones | 5/5 |
| Sensor1 (f0f10e8), la misma orden ssh desde el bastión, sobre la EVE dedicada viva (**solo lectura**) y manifiestos y salidas en `/tmp/cf-prueba-cierre` | A: periodo terminado ahora (presente al primer intento: la lectura de 383 MB tardó 7,8 s y la muestra ya existía); B: periodo de hace 2 min (presente); C: EVE inexistente (rc 4, sin salida); D: manifiesto roto (rc 5); **E: fin a +15 s** (intentos `insuficiente`, `presente`; rc 0; 20,7 s); **F: fin a +300 s** (4 × `insuficiente`, rc 3; 47,1 s) | 6/6 como se esperaba |

Los JSON de A–F están en `evidencias/bloque1/suricata-r7/prueba-cierre/`. En una primera pasada, F dio
rc 4: mi forma de lanzar el guion desde PowerShell añadía un `\r` a la última línea y con él a la ruta.
Se repitió con una línea final inocua y dio rc 3.

**Lo que solo una ejecución real verificará:**

- el paso dentro de `cerrar_v2.sh` completo, al final de una captura, con el archivador recién parado;
- la espera real hasta la muestra posterior en esas condiciones;
- el **tiempo de lectura de la EVE dedicada al cabo de 49 h**. Cada intento lee la EVE entera: hoy, 383 MB tardan unos 7,5 s. Si la EVE crece mucho, cada intento tardará proporcionalmente más. Queda como fila 73 de PENDIENTES, para el bloque 4: leer desde el final o usar la EVE ya rotada.

## 4. Pruebas

`python -m pytest -q -p no:cacheprovider tests` dio **335 passed, 38 subtests passed** (última pasada, 61 s; la anterior, con la máquina cargada (175 s), dio 1 fallo que no se identificó) (Python 3.14.3,
pytest 9.0.3). Pruebas nuevas o rehechas:

- `tests/test_suricata_stats.py`:
  - sin `uptime` (todas, una sola, dos que acotan);
  - hueco de 24 s con pérdida da `perdida` + `no_aprobada`;
  - pérdida solo ampliada da `perdida_no_localizada` (C9 entra como falta, no como fallo);
  - atribuible y ampliado en la misma serie;
  - reinicio;
  - vigía sin `uptime` y `uptime` que salta;
- `tests/test_dictamen_global_suricata.py`: el **dictamen global completo**, sobre una copia temporal de las entradas publicadas de VD4, cambiando solo la ventana de stats:

  | Caso | Dictamen |
  |---|---|
  | sin alterar | `aprobada` |
  | pérdida dentro del periodo | `no_aprobada` |
  | pérdida dentro con hueco de 24 s | `no_aprobada` |
  | pérdida solo en el intervalo que cruza el inicio | `indeterminada` |
  | sin `uptime` | `indeterminada` |

- `tests/test_cierre_ventana.py` (§3).

`tests/test_sondeo_span.py` ya fallaba de vez en cuando, y nada de esta revisión le afecta. Arranca un
switch falso (otro proceso Python) dentro de una ventana de 1,2 s, y con la máquina cargada salían 0–1
muestras. Su ventana pasa a 3 s; las aserciones no dependen del número de muestras. La prueba de
reconexión tras un tiempo de espera, con su propia ventana de 4,6 s, aún puede fallar con carga (1 de 4
pasadas aisladas). La suite completa pasó.

## 5. Reproducción de los cuatro dictámenes con f0f10e8

El reanálisis se hizo en Sensor1, sobre copias nuevas. La ventana de stats se volvió a extraer de la EVE
dedicada y es **byte a byte igual** a la de r6 en las cuatro ejecuciones.

| Ejecución | r6 | r7 | Suricata r7 |
|---|---|---|---|
| VD2 | indeterminada | **igual** (`falta:espejo`, C9 None por el sondeo del switch, C10) | `presente`: atribuible 0, ampliado 0, sin falta de evidencia |
| VD3 | no_aprobada | **igual** (`espejo:con_descartes`) | `presente`, 0 / 0 |
| VD4 | aprobada | **igual** | `presente`, 0 / 0 |
| VD6 | aprobada (verificación dirigida) | **igual** | `presente`, 0 / 0 |

**No cambia ninguno**, porque las 230 muestras usadas de cada ejecución traen `uptime` continuo, no hay
huecos (máximo 8,005 s) y `kernel_drops` no aumenta en ningún intervalo, ni atribuible ni ampliado. Las
reglas nuevas cambian el dictamen cuando la evidencia lo exige: lo demuestran las cinco variantes de
VD4 de §4. Contraste: el código r7 frente a la referencia r6 solo difiere en los dos campos nuevos
(`delta_kernel_drops_atribuible` y `_ampliado`, ausentes en r6).

El paquete está en `evidencias/bloque1/suricata-r7/`. Se aplica después de r5 y r6, y
`reproducir_dictamen.py` lo usa por omisión. El registro del clon limpio está en
`suricata-r7/REPRODUCCION-CLON-LIMPIO-intento5.txt`.

## 6. Sigue abierto

- Del propio bloque: la causa interna de la pérdida en el switch.
- Bloque 3: la deduplicación del extractor (fila 37).
- Bloque 4:
  - el reloj de DC1 (fila 38);
  - la rotación del EVE;
  - la supervisión prolongada;
  - el tiempo de lectura de la EVE en el cierre (fila 73).
