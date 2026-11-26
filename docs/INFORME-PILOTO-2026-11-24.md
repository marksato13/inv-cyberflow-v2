# Informe del piloto de 30 min (24-nov-2026)

> **Corrección (5.ª revisión, 26-nov):** lo que aquí se dice de que Suricata `kernel_drops` «no es medible» es falso. `stats.log` omite los contadores que valen 0, y la EVE dedicada `v2/eve.json` lo da: 0 en VD2–VD6. Ver `BLOQUE1-REVISION-5-2026-11-26.md` §2.

**Ejecución:** `V2-PILOTO-20261124T224340Z`. Programa `programas/piloto-30min.json`
(sha256 `16661aec…1c45136`), lanzado con `bash lanzar_v2.sh piloto-30min.json PILOTO 2` y
cerrado con `bash cerrar_v2.sh V2-PILOTO-20261124T224340Z`.

| Hito | UTC |
|---|---|
| Lanzamiento (exclusión V1, preflight, relojes, contadores, DNS, archivador) | 22:43:40 |
| Inicio del generador (150 s de captura previa) | 22:46:10 |
| Fin de los seis perfiles | 23:16:13 |
| Fin del archivador (margen de 120 s) | 23:19:20 |
| Primer cierre y análisis | 23:19–23:31 |
| Reanálisis con la extracción corregida | 23:45–23:57 |

Criterios fijados antes de lanzarlo: `PROTOCOLO.md` §10, versión 2 (commit `793cf0a`). C11b se
añadió durante el piloto, antes de cerrarlo, a petición de Mark (commit `2d9cbca`). Evaluación
automática: `operacion/evaluar_piloto.py` → `pruebas/<ID>/criterios.json`.

Las 42 h **no** se han iniciado.

## 1. Matriz de criterios

| # | Criterio | Resultado | Valor medido |
|---|---|---|---|
| C1 | Seis perfiles terminan solos | **Aprobado** | 6 × `perfil_terminado` código 0; manifiesto del generador `completa` |
| C2 | Fases y pausa | **Aprobado** | 0 transacciones en [900, 1080); 6 fases × 6 perfiles en orden |
| C3 | Pulsos y periodo activo | **Aprobado** (2.º evaluador, ver §2.2) | A1 112 tx, P1 103 tx, ráfagas de erratico 163 tx; 0 pulsos mal asignados; 0 factores distintos del programa |
| C4 | Resiembra | **Aprobado** | B1 y B2 en los seis perfiles, semillas iguales a las del programa |
| C5 | Clasificación del cliente | **Aprobado** | 2 602 tx: 2 404 ok, 185 error intencional, 13 variación del servidor, 0 fallo inesperado |
| C6 | Conciliación con srv-dmz y DC1 | **Aprobado** | 2 404 correcto, 185 error intencional, 13 variación; 0 fallo imprevisto; 0 no verificable; 0 errores de lectura |
| C7 | Cobertura de la captura | **Aprobado** | 657 884 689 B vistos de 657 884 689 (1,0) en total, en cada acción comparable y en cada perfil; conexión, petición y respuesta 100 %; 0 no verificables; 0 huecos; 0 retransmisiones; 615 no comparables por diseño (DNS, ping, abandono) |
| C8 | Archivado | **Aprobado** | manifiesto `completa`, motivo `fin_programado`; 427 PCAP; 0 huecos PCAP; 0 huecos EVE; 0 líneas corruptas |
| C9 | Pérdidas en la cadena | **Aprobado** | Δ output drops: Gi2/0/19 = 0 (214 318 → 214 318), Gi1/0/23 = 0, Gi2/0/23 = 0; tcpdump 0 descartados por el kernel; `rx_missed_errors` 0; softnet 0. `rx_dropped` +29 678 (protocolos no manejados, ya conocido). Suricata no publica `kernel_drops` en `stats.log` (ver §4) |
| C10 | Relojes | **Aprobado** | NTP sincronizado al inicio y al final en Sensor1, Clientes, srv-dmz y DC1 (desfases 0,7–1,7 ms); desfase aparente cliente↔captura: mediana 0,27 ms, máximo 4,7 ms |
| C11 | Extracción y verificación | **Aprobado en el 2.º análisis** (1.º falló, ver §2.1) | 1 095 ventanas; verificación 40/40, `sin_futuro` y `paridad_motor` OK; 0 tardías (PCAP y EVE); 3 constantes justificadas; 149 IP inventariadas, todas con regla |
| C11b | Trazabilidad de ventanas | **Aprobado** | `trazabilidad_ok`; 1 095 ventanas 1:1; `entradas_if.csv` = `ventana_id` + 28; 0 obligatorios vacíos; 89 excluidas (E1 36, E3 30, E5 24) |
| C12 | Volumen | **Aprobado** | PCAP comprimido 72,4 MB y EVE 14,0 MB en 37 min; proyección a 42 h: 6,6 GB (central) a 9,1 GB (cota); disponible 23 GB − 4 GB de reserva |
| C13 | Aislamiento de V1 | **Aprobado** | regla `*@2026-11-24T18:15/2026-11-26T00:00` cubre la ejecución; srv-dmz 0 limitados y 0 bloqueados, agente sin `--aplicar`, DC1 0 reglas nft, al inicio y al final |

## 2. Intentos fallidos (conservados)

### 2.1 Primer análisis: verificación 38/40 (C11 falló)

- `verificar_v2` devolvió rc 1: `sin_futuro_ok` y `paridad_motor_ok` falsos.
- Fallaron 2 de 40 filas, ambas de 10.10.20.24 (aplicacion), bloque B1, cierres 22:54:50 y 22:59:30.
- Columnas afectadas: `unique_dst_ip_ratio_30s`, `unique_dst_port_ratio_30s` y `flow_duration_mean_30s`.
- **Causa.** La extracción guardaba el primer paquete de cada flujo desde el inicio del bloque, sin límite de antigüedad.
  - El motor en operación solo conserva `--history-seconds` (230 s) de paquetes (`motor_decision.py:551` y `:801`).
  - Un flujo de aplicacion vivo más de 230 s daba en la extracción una duración media de 222,9 s y 321,6 s.
  - El motor, en las mismas ventanas, ve 1,6 s y 0,96 s.
- La comprobación con la referencia sin límite reprodujo exactamente los valores de la extracción, así que la causa es ese horizonte y no otra.
- **Corrección** (commit `641fc52`):
  - el estado de flujos y de secuencias TCP guarda todos los paquetes de los últimos 230 s, se poda en cada ancla, y cada ventana usa el primero dentro de su horizonte;
  - el horizonte queda como parámetro (`--horizonte-motor-s`) y se escribe en `resumen.json`;
  - prueba nueva `test_flujo_largo_usa_el_horizonte_del_motor`: falla con el código anterior y pasa con el nuevo.
- Se reanalizó la **misma** captura; el piloto no se repitió.
- El primer resultado queda en `pruebas/<ID>/extraccion-intento1-156b5e8/` y su SHA256SUMS en `registros/SHA256SUMS-cierre-156b5e8`.
- **Hallazgo para V1, solo documentado:** la extracción fuera de línea de V1 tampoco acota la edad del flujo, así que en V1 el entrenamiento y la operación difieren en flujos largos. No se cambia nada de V1.

### 2.2 Primer evaluador: C3 falso por un error del evaluador

- El evaluador no aplicaba el factor de ráfaga (×6,0 del perfil erratico).
- Marcó 163 transacciones con 5,4 frente a 0,9, cuando 5,4 = 0,9 × 6,0 es lo programado. El generador no cambió.
- El primer resultado está en `registros/criterios-evaluador-156b5e8.json`; el evaluador corregido es el commit `ea7bfbe`.

## 3. Volumen por fase

| Fase | Factor | PCAP en el anillo (sin comprimir) | PCAP archivado (gz) | EVE |
|---|---|---|---|---|
| F1 alta | 1,0 | 3,77 GB/h | 0,153 GB/h | 0,029 GB/h |
| F2 | 0,55 | 2,73 GB/h | 0,106 GB/h | 0,024 GB/h |
| F3 media | 0,9 | 2,94 GB/h | 0,185 GB/h | 0,030 GB/h |
| F4 parada | 0 | 0,96 GB/h | 0,043 GB/h (fondo del SPAN) | 0,017 GB/h |
| F5 reducida + A1 + P1 | 0,3 | 2,15 GB/h | 0,105 GB/h | 0,021 GB/h |
| F6 alta | 1,0 | 4,49 GB/h | 0,180 GB/h | 0,032 GB/h |

El programa de 42 h tiene una carga media de 0,653 frente a 0,645 del piloto, y el piloto lleva ×1,25 en dos perfiles. Proyección:

- **Central:** 0,1325 GB/h × 42 h ≈ 5,6 GB de PCAP + 0,95 GB de EVE ≈ **6,6 GB**.
- **Cota:** todas las horas a la fase más pesada ≈ **9,1 GB**.
- **Disponible:** Sensor1 tiene 23 GB libres y el archivador para con 4 GB.
- **Supuesto que hay que vigilar:** el fondo del SPAN de noche (otros equipos) no se midió. `volumen.jsonl` lo registra minuto a minuto y la parada por espacio corta a tiempo.

## 4. Lo que el piloto no prueba y sigue pendiente

**BLOQUEANTE nuevo (25-nov, 00:16 UTC, después del piloto).**
- El enlace del espejo Gi2/0/19 ↔ `vmnic2` (Intel I210, esxi-hv-siem) se cayó dos veces y volvió a **100 Mbit/s**.
- El preflight detuvo la prueba de parada `V2-PARADA-ESPACIO-20261125T002106Z` antes de arrancar el generador (`span_destino_velocidad` y `vmnic2_velocidad` en fallo).
- El `shutdown`/`no shutdown` que en T7 había subido el enlace a 1000 esta vez no funcionó. Con `speed 1000` el enlace **no sube**: un par del cable o un conector está mal.
- Se volvió a la negociación automática (`no speed`): enlace a 100 Full, espejo funcionando. Ningún cambio de velocidad quedó guardado.
- Hace falta revisar o cambiar el cable. Sin 1000 Mbit/s no se lanzan las pruebas de parada ni las 42 h.

**Aplicado el 25-nov por Mark:**
- salida EVE dedicada en `/var/log/suricata/v2/eve.json`, que crece igual que `eve.json` e incluye `kernel_drops` en `stats`; el lanzador la usa desde `48c2faf`;
- `write memory` en CORE-STACK, con `mtu 9198` en la startup y respaldo en `flash:startup-antes-v2-20261124.cfg`.

| Elemento | Estado | Qué falta |
|---|---|---|
| Rotación diaria del EVE (copytruncate) | Recuperación de la copia rotada en flujo y reintentada 120 s (`cfa58f9`), probada en la prueba de rotación. Siguen pudiendo perderse 1–2 líneas por rotación sin poder detectarlo | Salida EVE dedicada en `/var/log/suricata/v2/` (sudo de Mark; propuesta en Sensor1 `~/suricata-v2/suricata.yaml.propuesta`). La primera noche de las 42 h cruza las 00:00 UTC |
| MTU 9198 de Gi2/0/19 | Solo en la running-config | `write memory` en CORE-STACK (Mark). Si el switch se reinicia sin guardar, C7 vuelve a fallar |
| Descartes de Suricata | `stats.log` no publica `capture.kernel_drops`; `kernel_packets` sí avanza | Se acepta tcpdump (0) + Δ drops del switch (0) + C7 (100 %) como prueba de cadena. Si se quiere el contador, hay que activarlo en la configuración (sudo) |
| Parada coordinada por espacio, por archivador muerto y por vigía muerto | **Hecha el 25-nov** con `operacion/prueba_parada.sh` (ver §6) | — |
| Etiquetado de ataques | Reglas v1 escritas (`docs/ETIQUETADO-ATAQUES.md`) | Programa que las calcule y lista de familias con sus parámetros, antes de la primera campaña |
| Copias del SPAN (dos orígenes, Gi1/0/23 y Gi2/0/23, y dos VLAN) | Se quitan bien: 818 244 copias en el piloto, 0 diferencias en la verificación | Decisión de Mark si se reduce: afecta a VM-SURICATA |

**Cable cambiado por Mark (25-nov, ~02:35 UTC).** `vmnic2` volvió a 1000 Full y el preflight pasó.
El primer intento de prueba de parada (`V2-PARADA-ESPACIO-20261125T002106Z`, 00:21 UTC) se canceló en
el preflight por la velocidad del enlace, como debía.

## 6. Pruebas de parada coordinada (25-nov), con la prueba corta de 240 s

| Caso | Ejecución | Provocado (UTC) | Generador | Archivador |
|---|---|---|---|---|
| Espacio (`SIMULAR_LIBRE_GB=2`) | `V2-PARADA-ESPACIO-20261125T025649Z` | 03:00:25 | se detiene a las 03:00:29 (+4 s): `incompleta`, `archivador_fallo_espacio` | detecta el problema a las 03:00:27 (+2 s): `fallo`/`espacio`, manifiesto `incompleta`, 0 huecos |
| Archivador muerto (`kill -9`) | `V2-PARADA-ARCHIVADOR-20261125T030053Z` | 03:04:26 (último latido 03:04:25) | el vigía detecta `latido_viejo` a las 03:05:36 (+71 s; tolerancia `--latido-max-s 60`) y los seis perfiles terminan con código 3 a las 03:05:37 | sin manifiesto (`kill -9` no lo deja cerrar). Por eso la ejecución se clasifica `incompleta` |
| Vigía muerto (`kill -9`) | `V2-PARADA-VIGIA-20261125T030610Z` | 03:09:42 (última renovación 03:09:37) | el permiso caduca y el generador para solo a las 03:11:07 (+90 s): `incompleta`, `sin_permiso_captura` | sigue hasta su fin programado: `completa`, 0 huecos |

En los tres casos el generador se detiene sin intervención y el motivo queda escrito.
Ventana máxima de tráfico sin archivar: unos 70 s cuando el archivador muere. Esa ejecución se
declara incompleta y no se usa.

## 5. Evidencia

| Ubicación | Contenido |
|---|---|
| Sensor1 `/home/m4rk/cyberflow-v2/capturas/V2-PILOTO-20261124T224340Z/` | PCAP gz, EVE, inventario, huecos, volumen, relojes y manifiesto (84 MB) |
| Sensor1 `/home/m4rk/cyberflow-v2/pruebas/V2-PILOTO-20261124T224340Z/` | generador, registros, conciliación, cobertura, extracción, trazabilidad y criterios (18 MB) |
| Portátil `C:\Users\markp\Downloads\CYBERFLOW-V2-PREPARACION-2026-11-24\capturas\` y `…\pruebas\` | Copia verificada: 506/506 hashes; `SHA256SUMS` con sha256 `4c58e800…51db87` |

En Sensor1 no se ha borrado nada.
