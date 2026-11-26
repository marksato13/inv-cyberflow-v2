# Suricata r6: muestras que acotan el periodo y referencia recalculada

Complemento de la 6.ª revisión del Bloque 1 (`docs/BLOQUE1-REVISION-6-2026-11-26.md`). Se aplica
**después** de `../suricata-r5/` con `operacion/reproducir_dictamen.py`, que los usa por omisión.

Por ejecución (`<ID>/`):

| Fichero | Qué es |
|---|---|
| `pruebas/<ID>/registros/suricata-stats-ventana-<ID>.jsonl` | Eventos `stats` de la EVE dedicada completa de Sensor1 (`/var/log/suricata/v2/eve.json`) en `[inicio − 30 s, fin + 30 s]` del archivador, sin modificar. Aportan las muestras anterior al inicio y posterior al fin, que el recorte del archivador no lleva |
| `extraccion-ventana.json` | Salida de `suricata_stats.py ventana`: número de eventos, sha256 y evaluación (`presente`, muestras antes/después, huecos, Δ) |
| `referencia/` | `resultado-global.json`, `criterios-revisados.json` y `dictamen-casos.json` recalculados con el código 2a3478b sobre copias nuevas (Sensor1 `reanalisis/2a3478b/`), y `ORIGEN.json` |

Lectura hecha el 26-nov-2026, sin captura nueva. Los eventos `stats` no llevan IP, MAC ni metadatos de
terceros (barrido hecho). La fuente original (`pruebas/<ID>`) y las referencias r4 y r5 no se tocaron.

`SHA256SUMS` cubre los 24 ficheros de los cuatro `<ID>/`; se generó en Sensor1 y se verificó en el
bastión y en el portátil. Los registros de reproducción de este directorio van aparte, en
`SHA256SUMS-reproduccion`.