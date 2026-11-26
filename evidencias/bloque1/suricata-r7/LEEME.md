# Suricata r7: referencia recalculada con la evaluación por intervalos

Complemento de la 7.ª revisión del Bloque 1 (`docs/BLOQUE1-REVISION-7-2026-11-26.md`). Se aplica
**después** de `../suricata-r5/` y `../suricata-r6/` con `operacion/reproducir_dictamen.py`, que usa los
tres por omisión.

Por ejecución (`<ID>/`):

| Fichero | Qué es |
|---|---|
| `pruebas/<ID>/registros/suricata-stats-ventana-<ID>.jsonl` | Eventos `stats` de la EVE dedicada completa, extraídos de nuevo. **Idénticos byte a byte** a los de r6 |
| `extraccion-ventana.json` | Salida de `suricata_stats.py ventana`, con la evaluación r7 (atribuible / ampliado / falta de evidencia) |
| `referencia/` | Resultado global, criterios revisados y ocho casos, recalculados con f0f10e8 sobre copias nuevas (Sensor1 `reanalisis/f0f10e8/`), más `ORIGEN.json` |

`prueba-cierre/`: salidas JSON de la prueba controlada del paso de cierre en Sensor1, casos A–F de
REVISION-7 §3. Se leyó la EVE dedicada sin modificarla; los manifiestos eran temporales. No contienen
IP ni MAC.

Hashes:

- `SHA256SUMS`: los 24 ficheros de los cuatro `<ID>/`, generados en Sensor1 y verificados en el bastión y en el portátil;
- `SHA256SUMS-otros`: `prueba-cierre/` y los registros de reproducción.