# VD6: verificación dirigida sin transferencias de evidencia (26-nov-2026)

- **Ejecución:** V2-VD6-20261126T151456Z, con el código 9196712 y el programa
  `prueba-niveles-transiciones.json` (24 min).
- **Captura:** de 15:15 a 15:46 UTC.
- **No es** el piloto final ni las 49 h.

`resultados/` contiene:

- `resultado-global.json`: **`aprobada`** sin motivos, con `alcance`: verificación corta;
- `criterios.json` y `criterios-revisados.json`: C7 y C9–C13 con evidencia, y lo de duración
  prolongada aparte;
- `cobertura.json`;
- `calidad-referencias.json` y `referencias.jsonl`: vigilancia de srv-dmz y DC1;
- `transferencias.json`: `sin_copias`.

Las entradas mínimas saneadas para reproducirlo están en
`../extractos-539c48e/entradas-V2-VD6-20261126T151456Z/`, y se reproduce con
`operacion/reproducir_dictamen.py`. Los PCAP y el EVE completo son privados: sus sha256 están en
`pruebas/<ID>/SHA256SUMS` en Sensor1. Análisis en `docs/BLOQUE1-REVISION-3-2026-11-26.md` §7.
