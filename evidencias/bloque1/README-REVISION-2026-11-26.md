# Evidencia de la revisión del 26-nov (Bloque 1)

Explicación en `docs/BLOQUE1-REVISION-2026-11-26.md`. Cada carpeta tiene su `SHA256SUMS`.

| Carpeta / fichero | Qué es | Origen |
|---|---|---|
| `dns-entradas/V2-*/` | Entradas del contraste DNS de T1, T2, E1 (copia `original-cd06fcf`), E2 y E3: transacciones del generador y registro de DC1 | Sensor1 `~/cyberflow-v2/pruebas/<ID>/`, solo lectura |
| `dns-entradas/dns-e3-pcap/` | PCAP de DC1 de E3 saneado (idéntico al original: ya solo tenía tráfico de la población), informe del saneado y contraste de E3 con el PCAP | Sensor1 `~/cyberflow-v2/bloque1/dns-e3-pcap/` |
| `dns-entradas/reproduccion/` | Contraste DNS recalculado en el portátil solo con lo publicado (paquete del release + `dns-entradas/`), con la comparación frente al laboratorio | `operacion/reproducir_dns.py` |
| `sonda-preflight/` | Contraste DNS con la clasificación de eventos sin transacción, y ventanas de 10.10.20.21 cuya historia contiene la sonda | Sensor1 `~/cyberflow-v2/bloque1/sonda-preflight/`, con el código de esta revisión |
| `redictamen/redictamen.json` | Dictamen de las cinco ejecuciones con la política integrada, junto al dictamen anterior (no se sobrescribió ninguno) | Sensor1 `~/cyberflow-v2/bloque1/redictamen/` |
| `rx-dropped-r1.json` | Prueba de 120 s de `rx_dropped` (contadores, clases, serie y `ptype`). Los PCAP de esa prueba ya no existen (rotados) | Sensor1 `~/cyberflow-v2/bloque1/rx-dropped-r1.json` |

Antes de publicar se buscaron direcciones IP y MAC en todo lo anterior. Solo aparecen la población
(10.10.20.21–26), DC1 (10.10.10.20) y srv-dmz (10.10.30.10).
