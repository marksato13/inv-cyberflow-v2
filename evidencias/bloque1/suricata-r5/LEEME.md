# Complemento r5: Suricata `kernel_drops` (Bloque 1, revisión 5)

Complementa a `../entradas-r4/` y a la release `bloque1-r4-2026-11-26`, que no se modifican.
Detalle en `docs/BLOQUE1-REVISION-5-2026-11-26.md` §2.

| Ruta | Qué es |
|---|---|
| `PROCEDENCIA-SURICATA.txt` | Versión, proceso, systemd (arranque y reinicios), configuración efectiva (sha256 y extractos), fichero que lee el vigía, y `stats.log` frente a la EVE en el mismo instante y `uptime` |
| `<ID>/capturas/<ID>/eve/suricata-stats-<ID>.jsonl` | Los eventos `stats` **originales y completos** de la EVE de la captura (228 por ejecución). Solo contadores agregados: sin IP, MAC, nombres ni carga (barrido limpio). Sin modificar |
| `<ID>/extraccion-stats.json` | sha256 del extracto, número de eventos y su evaluación (`presente`, Δ `kernel_drops` 0) |
| `<ID>/referencia/` | Resultado del laboratorio recalculado con el código 88c380d sobre una **copia** de la fuente (Sensor1 `reanalisis/88c380d/<ID>`); `ORIGEN.json` da la fuente y el sha256 de la EVE original. Sustituye a la referencia r4 para el código actual |
| `SHA256SUMS` | sha256 de cada fichero de esta carpeta (generado en Sensor1 y verificado en el portátil: 0 distintos) |
| `REPRODUCCION-CLON-LIMPIO-intento3.txt` | Registro de la comprobación desde `C:\r5`, vacía |

`operacion/reproducir_dictamen.py` superpone este complemento por omisión. Con `--sin-complemento`
y el código actual sale NO SATISFACTORIO a propósito: sin los eventos `stats`, C9 queda sin
evidencia (None) y no se toma como 0.