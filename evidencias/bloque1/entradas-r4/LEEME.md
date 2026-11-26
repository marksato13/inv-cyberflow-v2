# Entradas y extractos publicables de VD2, VD3, VD4 y VD6 (Bloque 1, revisión 4)

Sustituyen a `../extractos-539c48e/entradas-*`. Esas entradas se generaron, pero `.gitignore` las
excluía (`pruebas/`, `capturas/`, `*.pcap`, `eve*.json`), así que **nunca llegaron a publicarse**.
Además, su saneado sustituía también las direcciones de red del laboratorio. Las de aquí se generaron
de nuevo, desde las mismas fuentes del laboratorio: las entradas y los extractos con el código
**58d2cef** y `inicio-captura.json` con **c926338** (los dos desplegados y verificados por hash):

| Ejecución | Fuente en Sensor1 | Dictamen del laboratorio |
|---|---|---|
| V2-VD2-20261126T090705Z | `reanalisis/5d4d51f/` | indeterminada |
| V2-VD3-20261126T104230Z | `reanalisis/5d4d51f/` | no_aprobada (se conserva como fallida) |
| V2-VD4-20261126T141333Z | `reanalisis/3e0c73e/` | aprobada (tras el reanálisis; el original indeterminada sigue en Sensor1) |
| V2-VD6-20261126T151456Z | `pruebas/` (sin reanálisis) | aprobada (verificación dirigida) |

## Qué hay y dónde

Cada ejecución tiene su carpeta `<ID>/`. El texto está en este repositorio y el paquete completo,
texto y capturas, está en la release
[`bloque1-r4-2026-11-26`](https://github.com/marksato13/inv-cyberflow-v2/releases/tag/bloque1-r4-2026-11-26).

| Ruta | Contenido | Dónde |
|---|---|---|
| `pruebas/<ID>/`, `capturas/<ID>/*.json*` | Entradas de texto saneadas: lo que leen `revisar_criterios`, `estado_global`, `dictamen_casos` y los resultados del laboratorio (cobertura, calidad, extracción) | repo y release |
| `referencia/` | Lo que dio el laboratorio: `resultado-global.json`, `criterios-revisados.json` y `dictamen-casos.json` (los ocho casos, calculados con `dictamen_casos.py` sobre la ejecución **original**) | repo y release |
| `informes-filtrado/` | Recuento del filtrado por fichero y motivo; `inicio-captura.json` | repo y release |
| `capturas/<ID>/pcap/live-*.pcap.gz` | Anillo de Sensor1 (SPAN), filtrado al tráfico experimental | release |
| `capturas/<ID>/eve/eve-<ID>.json` | EVE filtrado al tráfico experimental | release |
| `pruebas/<ID>/registros/extremo-<ID>.pcap` | Referencia de srv-dmz | release |
| `pruebas/<ID>/registros/dns-<ID>.pcap` | PCAP de DC1 | release |
| `MANIFIESTO-PAQUETE.sha256` | sha256 de cada fichero del paquete | repo y release |
| `SHA256SUMS-bloque1-r4.txt` (aquí) | sha256 de los cuatro `.tgz` de la release | repo |

## Saneamiento y filtrado: qué se modificó

- **Texto** (`operacion/extracto_saneado.py`):
  - se conservan las IP del experimento, la población 10.10.20.21–26, los servidores 10.10.30.10 y
    10.10.10.20, el bastión y Sensor1;
  - se conservan las puertas de enlace del laboratorio (10.10.{10,20,30,60,99}.1) y las direcciones
    de red 10.10.X.0. Esto es **nuevo en r4**: antes se sustituían, y `calidad_copias` dejaba de ser
    comparable;
  - cualquier otra IPv4 pasa, de forma consistente, a 198.51.100.0/24 o 203.0.113.0/24;
  - las MAC pasan a 02:00:00:00:xx:yy.
- **PCAP** (`captura/extracto_experimento.py`):
  - se conserva una trama IPv4 si un extremo es de la población y el otro es de la población o un
    servidor del experimento. Todo lo demás se descarta: gestión, equipos ajenos, ARP, STP/CDP e
    IPv6, contado por motivo en `informes-filtrado/`;
  - **sin modificar**: marcas de tiempo (misma precisión), longitud capturada y original, etiquetas
    802.1Q, cabeceras IP, TCP y UDP (TTL, IP ID, secuencia, sumas) y carga;
  - **única modificación**: las MAC, sustituidas por 02:xx:xx:xx:xx:xx = HMAC-SHA256(clave, MAC)[:5].
    El seudónimo es el mismo en Sensor1, srv-dmz y DC1, y la clave es privada (no se publica);
  - el nombre de cada fichero del anillo se conserva (`.pcap.gz`, gzip con mtime 0), porque el
    inventario y el manifiesto lo nombran.
- **EVE:** solo eventos con el mismo criterio de IP, y sin el campo `ether`. Barrido final: los
  únicos nombres son `cf-v2.lab` y `10.10.30.10`.
- **Dato añadido** (`informes-filtrado/inicio-captura.json`): el instante del primer paquete IPv4 o
  evento EVE de la captura **original**, calculado en el laboratorio con las funciones de
  `extraer_v2.py`. El extractor fija con él el arranque y las marcas de las primeras ventanas, y ese
  paquete suele ser tráfico no experimental que el extracto no lleva.

Barridos de la publicación:

- en el texto, ninguna IP ni MAC fuera de la regla;
- en las 161 494 tramas de los extractos, todas las IP de cabecera son del experimento, todas las
  MAC son seudónimos 02:… y las VLAN son la 10, la 20 y la 30.

## Qué se reproduce desde aquí

`docs/BLOQUE1-REVISION-4-2026-11-26.md` §3 da los comandos. La comprobación desde una carpeta vacía **sigue pendiente**: el primer intento falló por la longitud de las rutas en Windows
(`REPRODUCCION-CLON-LIMPIO-intento1-fallido.txt`). Lo de abajo se comprobó en Sensor1 y en la copia de
trabajo del portátil.

1. **El dictamen desde resultados intermedios** (`operacion/reproducir_dictamen.py`): dictamen,
   estados, motivos, C7 y C9–C13, pendientes y los ocho casos coinciden en las cuatro ejecuciones.
2. **El recálculo desde PCAP/EVE** (`operacion/recalcular_desde_capturas.py`): cobertura (C7),
   extremo, contraste DNS, copias del espejo y extracción de las 645–674 ventanas (C11, todas las
   columnas) coinciden en las cuatro ejecuciones, salvo los campos que cuentan tráfico no experimental,
   listados abajo. P2 (`--p2`) da 45/45 transacciones iguales en todos sus campos.

## Lo que NO se publica y qué conclusión no puede reproducirse

| Fichero (en Sensor1) | Por qué no | Qué no se puede rehacer desde aquí |
|---|---|---|
| Anillo completo `capturas/<ID>/pcap/` (unas 890 000 tramas por ejecución) | Tráfico de gestión y de equipos ajenos al experimento | Los campos que cuentan todo el anillo: denominadores totales, bytes por VLAN, tasas y picos por segundo y por 10 ms, `sensor/paquetes` del extremo, reordenaciones del extractor (`orden_pcap`, `orden_eve`), copias de espejo y paquetes descartados fuera de la población, `inventario_ips`. **Ninguno interviene en el dictamen**: se publica el valor del laboratorio, sin comprobación independiente. Tampoco el análisis de la pérdida de gestión (VD3, REVISION-2 §9), que trata precisamente ese tráfico |
| EVE completo `capturas/<ID>/eve/` | Metadatos de aplicación de terceros (DNS, SNI, URL), aunque se sustituyan las IP | Los eventos ajenos a la población. No intervienen en el dictamen |
| Correspondencia de IP sustituidas y clave HMAC de las MAC | Revertirían el saneamiento | Identificar los equipos ajenos; no interviene en ninguna conclusión |
| T1–E3 y anteriores (`../reanalisis/`) | No se generaron extractos de captura para ellas | Solo sus resultados publicados en `../reanalisis/` |
