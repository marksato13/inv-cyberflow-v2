# Reanálisis de la 3.ª revisión (26-nov-2026)

Ninguno de estos reanálisis borra resultados. Cada uno se hizo sobre una **copia** de la carpeta de
la ejecución, en Sensor1 `~/cyberflow-v2/reanalisis/<código>/<ID>/`. Lo que había antes está en
`<ID>/anterior/`. Los originales de `~/cyberflow-v2/pruebas/<ID>/` no se tocaron.

| Carpeta | Ejecución | Qué se rehízo | Dictamen original → reanalizado |
|---|---|---|---|
| `5d4d51f/V2-VD2-…` | VD2 | `cobertura_v2` v2 (conexiones persistentes), `metadatos`, `calidad_sonda`, `revisar_criterios`, `estado_global`. Revisión de criterios repetida con 539c48e | `indeterminada` → `indeterminada` (`falta:espejo`, C9 sin decidir por 30,5 s sin sondeo, C10 sin el NTP final de Sensor1) |
| `5d4d51f/V2-VD3-…` | VD3 | lo mismo | `no_aprobada` → **`no_aprobada`** (`espejo:con_descartes`, conservado; C10 sin decidir) |
| `3e0c73e/V2-VD4-…` | VD4 | `vigilar_referencias analizar --recalcular-progreso` y revisión de criterios con 539c48e | `indeterminada` (`falta:referencias`: falso `sin_progreso` de srv-dmz) → `aprobada` en los requisitos de una verificación corta |

`anterior/` conserva los dictámenes, criterios y coberturas previos:
`criterios-revisados-intento*.json` y `*-antes-539c48e.json`.

En VD4, `registros/calidad-referencias.json` incluye `recalculado_progreso`, con el incidente
registrado que se sustituyó y la regla aplicada. El registro de muestras está en
`registros/referencias.jsonl`.
