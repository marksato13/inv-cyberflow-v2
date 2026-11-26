# Verificación dirigida VD2 (V2-VD2-20261126T090705Z)

El programa fue `prueba-niveles-transiciones.json` (24 min de generación), con el código c548ecd.
No es el piloto final ni las 49 h. El análisis está en `docs/BLOQUE1-REVISION-2-2026-11-26.md`,
§3, §4, §6 y §8.

| Carpeta | Contenido |
|---|---|
| `ejecucion/` | Bastión: lanzamiento, preflight del laboratorio y de Clientes, relojes, carga y espacio de srv-dmz y DC1, sondeo del SPAN analizado, pasos del análisis, salida del lanzador y del cierre |
| `resultados/` | Sensor1: `calidad-*.json` (sonda, extremo, DNS, copias), `cobertura.json`, `criterios.json`, `fronteras.json`, `resultado-global.json`; `registros/` (vigía, supervisión, manifiestos, extremo-captura); `generador/preflight.jsonl` (25 líneas); `captura/manifiesto.json` |
| `dictamen/` | `resultado-global-c548ecd.json` (primer dictamen, con el error de versión de la sonda), `dictamen-9a99b74.json` (reevaluado), `dictamen-casos.json` (correcta, pérdida, ausente) |
| `vd1/` | Intento VD1, interrumpido al arrancar la captura de srv-dmz (incidencia, §11) |

**Datos ocultos.** Las IP que aparecen son todas del laboratorio (10.10.0.0/16). Solo había una
IP externa, la de un servidor NTP público de Ubuntu, y se ha sustituido por `<ntp-publico>`. No
hay ningún PCAP: sus sha256 están en `SHA256SUMS-pcap-privados`, y el `SHA256SUMS` cubre lo
publicado.
