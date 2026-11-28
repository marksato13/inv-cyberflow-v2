# Bloque 4: despliegue y prueba técnica preparatoria (28-nov-2026)

## Alcance y estado por bloque

| Bloque | Resultado comprobado | Pendiente |
|---|---|---|
| 1 | Código de stats integrado en el laboratorio; prueba sintética de 49 h aprobada con observación concurrente de descartes | Paso de stats dentro de un cierre completo real y C7/C9–C13 prolongados |
| 2 | Seis perfiles y siete jornadas contrastados con el Excel, programa y T1/T2; programa definitivo y piloto validados también en Clientes tras desplegar | Piloto integrado y siete jornadas efectivas |
| 3 | Deduplicación integrada desplegada con el mismo hash en los tres equipos de código | Resultado dentro del cierre completo y evaluación con datos definitivos |
| 4 | Código desplegado y V4-b técnica sintética aprobada | V4-a cierre completo; volumen real y capacidad local para 49 h; piloto y captura definitiva |

Esta ejecución no inició el piloto final ni la captura de 49 h. La EVE de carga es **técnica sintética**, excluida del conjunto de investigación.

## Despliegue coordinado

Se desplegó `268083be0e49ed3078c26ba1cd2520bff80def7a` (`268083b`), que contiene la integración B1–B3 y la corrección B2. El `git archive` de 1 597 entradas tenía SHA-256 `abb16fa2abe184a58742e48f22ef9abc5fdfb8263c6bbd363634268bc6bbc644`; se comprobó ese hash en bastión, Sensor1 y Clientes antes del cambio. `operacion/comprobar_parado.sh` dio `parado: si` antes. El script de despliegue rechazaba archivador o generador activos.

| Equipo | Versión anterior → actual | Respaldo | SHA-256 `suricata_stats.py` actual / anterior | SHA-256 `deduplicar_v2.py` actual |
|---|---|---|---|---|
| Bastión | `91b9798` → `268083b` | `codigo-91b9798` | `dd8384c2…0814d3a` / `080f36c6…d4d787` | `6ec71ab6…d04b2d` |
| Sensor1 | `91b9798` → `268083b` | `codigo-91b9798` | iguales | igual |
| Clientes | `91b9798` → `268083b` | `codigo-91b9798` | iguales | igual |
| DC1 | archivo DNS idéntico | `registro_dns_v2.py.antes-268083b` | SHA-256 actual y respaldo `f4d17e4d…4c116` | no aplica |

Los hashes completos, rutas y salida de instalación están en `evidencias/bloque4/preparacion-2026-11-28/despliegue-268083b.txt` y `verificacion-despliegue-268083b.txt`. `programas/piloto-30min.json` fue idéntico en los tres equipos (`fa2e789e…e5a9312`); Clientes validó `V2-C49 (176400 s)` y `V2-P49 (1800 s)`, en `validacion-programa-desplegado.txt`. El servidor de srv-dmz no forma parte de este paquete; el cambio B1–B3 no modificó su código. Los respaldos remotos se conservaron.

## V4-b: carga de lectura, evaluación y escritura

`tests/generar_eve_sintetica_49h.py` regeneró en Sensor1 una EVE de 2 799 997 693 bytes, SHA-256 `6fd4071a…70af70e`, con 22 051 stats cada 8 s durante 176 400 s, `uptime` de 100 000 a 276 400, `kernel_packets` de 1 000 000 a 23 050 000 y `kernel_drops=0`. El manifiesto y el hash están publicados. `tests/medir_suricata_49h.py` verificó los bordes, la continuidad, los contadores, todos los intentos y los bytes de salida; `tests/registrar_carga_b4.py` tomó contadores de los servicios permanentes sin cambiarlos. El código medido fue `operacion/suricata_stats.py` con SHA-256 `dd8384c2…0814d3a`.

| Caso | Lectura | Escritura | Evaluación | Total | Pico RSS | Resultado |
|---|---:|---:|---:|---:|---:|---|
| Intervalo completo | 15,284 s | 1,414 s | 0,170 s | 16,876 s | 39 452 KiB | rc 0, `presente`, 22 051/22 051 |
| Falta muestra posterior | 4 lecturas, cada una < 60 s | 4 escrituras | 4 evaluaciones | 88,060 s, incluidas tres esperas de 6 s | 39 460 KiB | rc 3, `insuficiente`, cuatro intentos esperados |

Ambas salidas tienen SHA-256 `2ee45968cecab2d5435804e4560a7df14302b30bbfe0d972c6f9550bd8aa8e94`, igual al manifiesto. Ningún intento usó el retroceso por marcas temporales desordenadas (`retroceso_por_desorden=false`). La alternativa sigue cubierta por las pruebas semánticas B1–B3. Se cumplen los umbrales técnicos: lectura ≤ 60 s, paso ≤ 5 min y RSS ≤ 256 MiB. La medición con 2,8 GB cubre el tamaño estimado de la EVE de cierre; no mide el volumen real del programa definitivo.

Hubo una muestra antes, 12 muestras de seguimiento cada 10 s y una después. El observador etiqueta las 12 como `durante` al despertar, aunque las últimas pueden caer justo después de terminar el medidor; las marcas originales permiten distinguirlas. Hay múltiples muestras mientras se ejecuta. El diario de `ppi-motor-capture` (timer SIGUSR1 cada 30 s) registró `0 packets dropped by kernel` en todas; la EVE dedicada de Suricata registró `kernel_drops=0` en todas. Los dos servicios siguieron activos, con el mismo PID y `NRestarts=0`; la diferencia de descartes fue 0. `contadores.json` conserva marcas y contadores originales. La salida anterior de r8 que **falló** memoria (1 686 068 KiB) permanece en `evidencias/bloque1/rendimiento-b1-b3/medicion-r8-fallida.json` y su causa en la integración B1–B3; esta pasada no la sustituye.

La entrada sintética de 3,1 GB en `/tmp/cf-b4-49h-20261128` se retiró después de copiar y verificar el paquete de evidencia (SHA-256 `a7f1f1a1…f1f3ee`), dejando 16 221 007 872 bytes libres en Sensor1. Se conserva el generador, el manifiesto, los registros, las fases, los hashes y el paquete pequeño; la EVE grande se puede regenerar. Véase `evidencias/bloque4/preparacion-2026-11-28/`.

## Volumen y espacio: condición aún abierta

La única cota empírica conservadora disponible es T8, **0,78 GB/h de PCAP comprimido durante una prueba corta**. A 49 h da 38,22 GB. La EVE dedicada observada con V2 creció unos 12,3 MB/h (≈ 0,60 GB/49 h) y la referencia de srv-dmz fue ≈ 33 MB/h (≈ 1,62 GB/49 h); proceden de otras pruebas cortas y cargas. Como presupuesto provisional, 25 % de margen sobre PCAP más esas dos referencias suman **≈ 50 GB**. No es una cota demostrada ni el C12 definitivo. El propio piloto debe medir tasas por nivel y recalcular el presupuesto; la ejecución larga debe registrar volumen por minuto y el efecto nocturno del SPAN.

El 28-nov a las 06:02 UTC, Sensor1 tenía **16,22 GB** libres en `/`; la parada del archivador está configurada a **4 GB**. Sin descarga concurrente o ampliación, solo se pueden consumir unos 12,22 GB antes de parar: menos que los 38,22 GB de la extrapolación T8. Para alojar el presupuesto provisional de 50 GB y conservar la reserva de 4 GB se necesitarían **≈ 54 GB libres al inicio**, unos **38 GB adicionales** a los actuales. La referencia de srv-dmz disponía de 10,20 GB y DC1 de 35,17 GB, suficientes solo frente a las tasas cortas estimadas; deben revalidarse con el piloto. Bastión tenía 2,57 GB y no es destino para la captura. La estación tenía 54,48 GB libres en C: y 61,03 GB en D: (USB exFAT); su capacidad sola no elimina la falta de espacio local de Sensor1 durante una captura continua. Evidencia: `espacio-laboratorio.txt` y `espacio-estacion.txt`.

**Bloqueante antes de las 49 h:** elegir y probar una ampliación de Sensor1 o una transferencia concurrente verificable a almacenamiento privado, con suficiente margen y sin descartes; medir primero el volumen del piloto. No se han elegido ni aplicado cambios de disco, montaje, red o borrado de originales. El destino final y su procedimiento de retención siguen sin verificarse. No debe declararse C12 aprobado por el presupuesto provisional.

## V4-a: comprobación del cierre completo preparada, pendiente de ejecutar

En el piloto integrado autorizado posteriormente, antes de cualquier captura definitiva:

1. Comprobar `parado: si`, versiones y hashes desplegados, espacio, referencias y relojes; fijar `CF_TIPO_EJECUCION=piloto_final` y ejecutar `lanzar_v2.sh` con `programas/piloto-30min.json` (1800 s), guardando salida, ID, estado, contadores y manifiestos originales.
2. Dejar terminar el programa y ejecutar `cerrar_v2.sh <ID>`; conservar el registro incluso si falla. Exigir el paso `suricata_stats_ventana rc=0` y `registros/suricata-stats-ventana-<ID>.jsonl` con SHA-256 idéntico al del resumen `suricata-stats-ventana.json`.
3. Exigir muestra stats anterior/en inicio y posterior/en fin a ≤ 16 s, huecos ≤ 16 s, `uptime` y contadores continuos; solo se reintenta si falta la muestra posterior (hasta cinco lecturas con `--reintentos 4`). Cualquier rc 3/4, ausencia de contador o reinicio deja C9 sin aprobación y exige diagnóstico.
4. Conciliar `resultado-global.json`, C7/C9–C13, transacciones de P1–P6, cobertura, referencias de srv-dmz y DC1, aislamiento, espacio y relojes; reproducir el dictamen desde las entradas y conservar cualquier intento fallido. La salida sintética de V4-b no sustituye este cierre.
5. Medir el volumen real por nivel y comprobar que la solución de almacenamiento soporta las siete jornadas más el margen y reserva. Solo entonces revisar la autorización separada de las 49 h.

V4-a sigue **pendiente** porque requiere iniciar el piloto final, excluido expresamente de este encargo. La comprobación final `parado-despues.jsonl` terminó rc 0, `parado: si`, sin procesos V2 ni candado; `ppi-motor-capture`, Suricata y la limpieza de V1 siguen operativos.
