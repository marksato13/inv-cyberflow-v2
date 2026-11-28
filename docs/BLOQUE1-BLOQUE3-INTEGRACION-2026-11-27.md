# Integración revisable de los Bloques 1 y 3 (27-nov-2026, hora de Lima)

## Alcance y procedencia

Se conserva íntegra la revisión 8 y sus evidencias. Esta integración incorpora las referencias que faltaban para ejecutar los comandos vigentes desde un clon publicado y corrige la memoria del paso de stats del cierre. No se ha iniciado el piloto final ni una captura de 49 h. Tampoco se ha desplegado este commit en el laboratorio.

El complemento `evidencias/bloque3/deduplicacion/` contiene 32 ficheros de texto copiados byte a byte del reanálisis de los originales en Sensor1, `~/cyberflow-v2/reanalisis/91b9798/`, con la deduplicación V2 del Bloque 3. `SHA256SUMS` comprueba los 32. Los originales y la copia privada recuperada se conservan; los PCAP y EVE completos permanecen privados. `calidad-sonda.json` era idéntico al ya publicado en r4. Se revisó el subconjunto publicado para excluir IP y MAC de gestión ajenas al experimento y rutas locales.

El código de extracción y deduplicación del Bloque 3 ya estaba en el árbol; esta integración conserva ese trabajo y añade su referencia pública. El pequeño cambio previo en la descripción de `recalcular_desde_capturas.py` se incluye sin sobrescribirlo. La referencia histórica de r4 usa la deduplicación anterior; la vigente por omisión usa la de B3. README y `evidencias/bloque3/deduplicacion/LEEME.md` detallan los dos modos.

## Reproducción del dictamen

Antes de incorporar B3, `python -X utf8 operacion/reproducir_dictamen.py` terminaba `NO SATISFACTORIO` en los cuatro IDs: exigía por omisión `evidencias/bloque3/deduplicacion/<ID>`, ausente en el clon. Se conserva ese diagnóstico; no se interpreta una ejecución histórica r4 como la integrada.

Con las 32 entradas, el mismo comando local termina rc 0: VD2 `indeterminada`, VD3 `no_aprobada`, VD4 y VD6 `aprobada`, cada uno `SATISFACTORIO`, y `GLOBAL SATISFACTORIO`. Esto coteja resultados publicados con las referencias del laboratorio. No verifica de forma independiente todos los campos que dependen del anillo completo privado. La comprobación desde un clon remoto limpio y la descarga de la release se documentan abajo.

## V4-b: intervalo técnico sintético y fallo conservado

`tests/generar_eve_sintetica_49h.py` produjo en `/tmp` de Sensor1 una EVE de **2 799 997 693 bytes** con **22 051** eventos stats desde 2026-01-01 00:00 UTC hasta 2026-01-03 01:00 UTC, cada 8 s. `uptime` avanza 176 400 s; `kernel_packets` va de 1 000 000 a 23 050 000, `kernel_drops` y `errors` valen 0. Todos los valores se sustituyeron por sintéticos; los flow solo rellenan el volumen. El archivo se excluye del conjunto de investigación. Su manifiesto y SHA-256, así como el hash de la salida stats, están en `evidencias/bloque1/rendimiento-b1-b3/`. El generador permite reconstruir el archivo sin publicarlo entero.

Se midió primero el código de r8 (`78bcc20`) con la misma EVE: 21,971 s y **1 686 068 KiB** de RSS máximo para una lectura; produjo las 22 051 muestras y el hash esperado, pero **incumplió** el límite de 256 MiB. La causa es la lista de eventos stats completos y la concatenación de ~242 MB de salida antes de escribirla. `medicion-r8-fallida.json` conserva este resultado, que la pasada correcta posterior no sustituye.

`suricata_stats.py ventana` ahora combina en orden cronológico las fuentes, escribe cada evento y su hash de forma incremental, y retiene solo los campos de contador que `evaluar()` necesita. Si una fuente presenta timestamps desordenados, vuelve al ordenamiento anterior para conservar la semántica. Dos pruebas comparan bytes y dictamen con el comportamiento anterior para varias fuentes y para una fuente desordenada. Las aserciones anteriores no se eliminaron ni debilitaron.

El fichero `operacion/suricata_stats.py` medido tiene SHA-256 `dd8384c26211987d948ecfb8938c903a4eb167e872146ddbcb392b1ba0814d3a` y está en el commit integrado `da9c62a`.

Medición en Sensor1 con el código corregido y el archivo completo:

| Caso | Resultado | Lectura, escritura, evaluación | Paso completo | RSS máximo | Salida |
|---|---|---|---:|---:|---|
| 49 h acotadas | rc 0, `presente`, 22 051/22 051 | 15,254 s; 1,413 s; 0,170 s | 16,847 s | 39 316 KiB | SHA-256 `2ee45968…8aa8e94` |
| Falta muestra posterior | rc 3, `insuficiente`, cuatro intentos y tres esperas de 6 s | por intento: lectura 15,361–15,525 s; escritura 1,398–1,428 s; evaluación 0,157–0,170 s | 86,846 s | 39 360 KiB | mismo SHA-256 |

El hash coincide con el producido por el generador y por el código r8. En el caso completo se verificaron las marcas de los bordes, hueco máximo de 8 s, contadores iniciales y finales, `delta_kernel_drops=0`, `delta_kernel_packets=22 050 000` y continuidad de uptime. En el segundo, cada intento volvió a leer, evaluar y escribir; los 18 s de espera están incluidos en la duración. Todas las lecturas quedaron bajo 60 s, el paso bajo 5 min y RSS bajo 256 MiB. `medicion-integrada.json` conserva cada fase y el máximo observado. `ppi-motor-capture` y Suricata seguían activos, ambos con `NRestarts=0` tras la prueba. No se registró una pareja de contadores de descartes del anillo durante la carga, así que el criterio V4-b.5 de no pérdida concurrente **aún no está demostrado**.

Tras copiar manifiesto y mediciones al repositorio, se eliminó únicamente `/tmp/cf-b1b3-49h-20261127` de Sensor1 para recuperar el espacio. El generador y el manifiesto publicado permiten reconstruir la entrada sintética y verificar su hash.

La suite local sobre el árbol de código integrado dio **350 passed, 38 subtests passed** en 54,59 s, rc 0. Se guardaron `suite-resultados.tsv` y `suite-resumen.json` (388 resultados individuales; ningún fallo) en la carpeta de evidencias. El registro indica el commit padre y `arbol_con_cambios=true`, porque se ejecutó antes de consolidar el código. La prueba posterior desde el clon publicado verificó el commit consolidado `da9c62a`.

## Verificación desde un clon publicado limpio

Se clonó `https://github.com/marksato13/inv-cyberflow-v2.git` en `C:\b1b3-da9c62a` con `git clone -c core.longpaths=true`. HEAD fue `da9c62a0d8cf5184da4c3d2481f4bc6ca89c4f0d`, con `git status --porcelain` vacío. No se copiaron archivos del árbol local al clon. Desde allí:

1. `python -X utf8 operacion/reproducir_dictamen.py`: rc 0, cuatro `SATISFACTORIO`, `GLOBAL SATISFACTORIO`. Registro `clon-limpio-dictamen.txt`.
2. `gh release download bloque1-r4-2026-11-26 -D descargas` y `python -X utf8 operacion/verificar_paquetes.py descargas`: rc 0; cuatro SHA-256 de la release correctos y 490, 491, 483 y 479 ficheros de los manifiestos internos sin diferencia. Registro `clon-limpio-paquetes.txt`. Esas son entradas publicadas descargadas, no ficheros locales añadidos.
3. Los 32 SHA-256 de `evidencias/bloque3/deduplicacion/SHA256SUMS` coincidieron en el clon.
4. `python -m pytest -q -p no:cacheprovider tests`: rc 0, 350 pruebas y 38 subpruebas pasadas en 57,53 s. `clon-limpio-suite-resumen.json` registra ese commit y `arbol_con_cambios=false`; se conserva además el listado de los 388 resultados individuales.
5. El primer intento del recálculo se invocó equivocadamente con `descargas` como directorio de ejecuciones: rc 1, `NO SATISFACTORIO: no hay ejecuciones en ...\descargas`. `verificar_paquetes.py` extrae en `evidencias/bloque1/entradas-r4`; README ya indicaba esa ruta. Se conserva `clon-limpio-recalculo-intento1-fallido.txt`; se corrigió la nota nueva de B3, que repetía mi error.
6. `python -X utf8 operacion/recalcular_desde_capturas.py evidencias/bloque1/entradas-r4 --p2 evidencias/bloque1/extractos-539c48e/p2-V2-VD2-20261126T090705Z`: rc 0, los cuatro IDs `SATISFACTORIO`, cobertura, extremo, DNS, copias y extracción reproducidas, **0 diferencias inesperadas**; P2, 45 transacciones, 0 diferencias; `GLOBAL SATISFACTORIO`. Registro `clon-limpio-recalculo-intento2.txt`. El clon seguía con `git status --porcelain` vacío después de extraer y probar.

La verificación final de parada se hizo con `operacion/comprobar_parado.sh` por SSH, en solo lectura. El primer y segundo envío del texto desde PowerShell devolvieron rc 127 **después** del JSON `parado: si`, por un `\r` final introducido al canalizar; sus registros se conservan. Se envió el mismo script como bytes con saltos LF y terminó rc 0, `parado: si`, 0 fallos, sin candado ni procesos V2; `ppi-motor-capture`, Suricata y la limpieza activos, PCAP nuevo y código de laboratorio `91b9798`. Registros `laboratorio-parado*.jsonl`. Ese código aún no es el commit integrado.

## Pasos que siguen abiertos antes de la captura definitiva

1. **Despliegue del commit integrado.** Verificar por hash el código en Sensor1, bastión, Clientes y el motor, preservando el trabajo del Bloque 3. Este paso no se hizo en esta revisión.
2. **V4-a: cierre completo.** En el piloto integrado real del Bloque 4, ejecutar `lanzar_v2.sh` → `cerrar_v2.sh`; comprobar registro `suricata_stats_ventana rc=0`, hash del fichero de ventana, muestra anterior y posterior a ≤ 16 s, hasta cinco intentos solo por falta de muestra posterior, C9 decidido y dictamen reproducible. Un rc 3/4 deja el piloto indeterminado y exige diagnóstico antes de las 49 h.
3. **V4-b en el entorno definitivo.** Repetir lectura, evaluación, escritura y reintentos sobre el tamaño real previsto de la EVE; cada lectura ≤ 60 s, paso ≤ 5 min, RSS ≤ 256 MiB, salida byte a byte correcta, `ppi-motor-capture` sin descartes del kernel y Δ`kernel_drops` de Suricata 0 durante la carga. La prueba técnica sintética cubre los primeros cuatro criterios con margen de volumen, pero no sustituye la medida concurrente ni un cierre real.
4. Solo después de aceptar V4-a y V4-b, decidir e iniciar la captura definitiva de 49 h. Esta revisión no concede esa autorización.

Permanecen además las comprobaciones prolongadas C7 y C9–C13, la rotación del EVE, el reloj de DC1 y la supervisión durante 49 h según `docs/PENDIENTES.md` y el protocolo. Ninguna salida sintética constituye evidencia de esas propiedades en una captura real.
