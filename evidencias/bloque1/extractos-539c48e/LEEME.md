> **Sustituido por `../entradas-r4/` (4.ª revisión, 26-nov).** Las carpetas `entradas-*` de aquí nunca se publicaron: `.gitignore` las excluía. Además, su saneado sustituía las redes 10.10.X.0 del laboratorio. El extracto de P2 (`p2-V2-VD2-…`) sigue vigente y ya está publicado completo, con sus PCAP y su EVE.

# Extractos saneados y entradas mínimas (3.ª revisión, 26-nov-2026)

Generados en Sensor1 con el código 539c48e: `operacion/extracto_saneado.py` y
`captura/sanear_pcap_tcp.py`. Se trasladaron con `transferir.py copiar` (registrado) sin ninguna
ejecución en marcha. El EVE completo se retiró después en el portátil, con la misma regla que ya
aplica `extracto_saneado.py`.

## Contenido

| Carpeta | Qué es | Para reproducir |
|---|---|---|
| `entradas-V2-VD2-…`, `entradas-V2-VD3-…`, `entradas-V2-VD4-…` | Ficheros de texto de la ejecución (`pruebas/<ID>` y `capturas/<ID>`) que leen `evaluar_piloto`, `revisar_criterios`, `estado_global` y `dictamen_casos`. Para VD2 y VD3 se parte del reanálisis 5d4d51f y para VD4 del reanálisis 3e0c73e | dictamen, C7 y C9–C13, y los 8 casos del dictamen |
| `p2-V2-VD2-…` | 6 conexiones persistentes de P2 (3 HTTP y 3 HTTPS, con 4 a 14 transacciones cada una): PCAP saneado, EVE de esas conexiones, sus 45 transacciones y la cobertura de referencia | `cobertura_v2.py` sobre el extracto |
| `REPRODUCCION-PORTATIL.json` | Resultado de reproducirlo en Windows, fuera del laboratorio | — |

**Cómo se reproduce** (desde la raíz del repositorio):

```
python -X utf8 operacion/reproducir_dictamen.py
python -X utf8 captura/cobertura_v2.py --capturas evidencias/bloque1/extractos-539c48e/p2-V2-VD2-20261126T090705Z/capturas/V2-VD2-20261126T090705Z \
  --transacciones evidencias/bloque1/extractos-539c48e/p2-V2-VD2-20261126T090705Z/transacciones-P2-extracto.jsonl --salida /tmp/cob.json
```

**Resultado en el portátil, 26-nov:**

- VD2, VD3 y VD4 dan el **mismo dictamen, los mismos motivos, los mismos C7 y C9–C13 y los mismos
  8 casos** que en el laboratorio: `indeterminada`, `no_aprobada` y `aprobada`.
- En P2, 45/45 transacciones coinciden con la cobertura del laboratorio en todos los campos
  comparados (`comparacion.json`).

## Saneado

- Se conservan las IP del experimento: las que aparecen en las transacciones del generador, más
  DC1, srv-dmz, el bastión y la gestión de Sensor1.
- Cualquier otra IPv4 (equipos ajenos, NTP público) se sustituye **de forma consistente** por una
  de 198.51.100.0/24 o 203.0.113.0/24. Los recuentos y las reglas por IP no cambian. La
  correspondencia no se guarda.
- Las MAC pasan a `02:00:00:00:xx:yy`, también de forma consistente, incluidas las del PCAP de P2.
  Las etiquetas VLAN se conservan.
- Un barrido final no encuentra ninguna IP ni MAC fuera de esas reglas.

## Qué NO se comparte y qué conclusión queda sin revisión independiente

| Fichero (en Sensor1, sha256 en `pruebas/<ID>/SHA256SUMS`) | Por qué | Conclusión sin revisión independiente |
|---|---|---|
| `capturas/<ID>/pcap/*.pcap*` (anillo del SPAN) | Tráfico de terceros del laboratorio | La cobertura completa (C7), las copias de la población y de gestión (`calidad_copias`) y la extracción de ventanas (`extraer`, `verificar`). Se puede revisar el **resultado** con las entradas, pero no rehacerlo desde la captura. La excepción es P2, rehecho con su extracto |
| `capturas/<ID>/eve/eve-<ID>.json` | Metadatos de aplicación de terceros (DNS, SNI, URL), aunque se sustituyan las IP | El contraste del EVE en la cobertura (tipos, `tx_id`, código HTTP). Para P2 sí está el EVE de las 6 conexiones |
| `pruebas/<ID>/registros/extremo-<ID>.pcap` (srv-dmz) y `dns-<ID>.pcap` (DC1) | Tráfico del laboratorio. El de DNS de E3 ya está saneado en `dns-entradas/` | La comparación con el extremo (`calidad_extremo`) y el contraste DNS de VD2–VD4 se publican como resultado, sin poder rehacerse |
| Correspondencia de IP y MAC ajenas | Identificaría a terceros | Ninguna: no interviene en el dictamen |
