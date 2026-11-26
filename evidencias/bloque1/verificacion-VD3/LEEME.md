# Verificación dirigida VD3 (V2-VD3-20261126T104230Z)

- **Programa:** `prueba-niveles-transiciones.json`, 24 min de generación.
- **Código:** 80627be, desplegado y verificado por hash.
- **Objetivo:** comprobar en el laboratorio que el sondeo del SPAN cubre ya toda la captura.
- **Qué no es:** ni el piloto final ni las 49 h.
- **Análisis:** `docs/BLOQUE1-REVISION-2-2026-11-26.md`, §8.

**Dictamen: `no_aprobada`.** El motivo es `espejo:con_descartes`: hubo 1 descarte de salida en
Gi2/0/19 entre las 10:46:51 y las 10:46:53 UTC, durante la captura previa y 55 s antes del
generador. `gestion/resumen-descarte-gestion.json` demuestra que lo provocó el operador: hubo 606
copias de gestión faltantes, 598 de ellas entre las 10:46:47 y las 10:46:49, justo cuando se hizo
el `scp` de la evidencia de VD2 de Sensor1 al bastión. Eso incumple la norma 35 de PENDIENTES.

Las copias de la población están completas (15 767/15 767). El extremo, el DNS y la sonda también
están completos. El sondeo cubre la captura entera (0 s indeterminados). Aun así, el criterio
conservador no se relaja, y el dictamen se queda como está.

| Carpeta | Contenido |
|---|---|
| `ejecucion/` | Bastión: lanzamiento, preflight, relojes, carga y espacio, sondeo analizado, salida del lanzador y del cierre |
| `resultados/` | Sensor1: calidad (sonda, extremo, DNS, copias), cobertura, criterios, `resultado-global.json`, registros y manifiestos |
| `gestion/` | Resumen de las copias de gestión faltantes en 10:46:35–10:47:05. El JSON de detalle no se publica porque tiene una IP ajena; solo va su sha256 |

Las IP son todas del laboratorio. El NTP público de Ubuntu aparece como `<ntp-publico>`.
