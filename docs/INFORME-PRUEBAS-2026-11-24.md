# Informe de pruebas técnicas cortas: preparación de V2 (24-nov-2026)

Son pruebas de **preparación**. Ninguna es el piloto de 30 min ni una captura definitiva, y ninguna se usa en métricas. Sus ventanas están excluidas del aprendizaje de V1 (ACLARACIONES §2.2).

**Evidencia.** Hay una copia privada con los PCAP, el EVE, los registros JSONL, los inventarios y la salida de `cobertura_v2.py`. Los originales están en:

- Sensor1: `~/cyberflow-v2/capturas/` y `~/cyberflow-v2/pruebas/`
- Clientes: `~/cyberflow-v2/ejecuciones/`

Hashes de los paquetes de la copia:

- `v2-evidencia-sensor1.tgz`: `4f71d6bc75a34ac9aae863b8f03ee59d68ce37e4d79eac63e2f16fc31ed4f6dd`
- `v2-evidencia-clientes.tgz`: `3799f29790cb24d404b5547f5b78baa88f3529bc6be0c55577fe0a55a870a37c`

## 0. Cambios previos en el laboratorio

| Cambio | Dónde | Reversión |
|---|---|---|
| Zona DNS `cf-v2.lab` con seis registros A a 10.10.30.10 | DC1 (`samba-tool dns zonecreate/add`) | `samba-tool dns zonedelete 127.0.0.1 cf-v2.lab -P` |
| Exclusiones en `excluir_ventanas` (las 11 filas y las pruebas V2) | Sensor1 `cyberflow.local.toml`, con 3 respaldos | Restaurar un respaldo |
| Código V2 en `~/cyberflow-v2/codigo` | Clientes y Sensor1 (sin servicios ni sudo) | Borrar el directorio |
| TSO/GSO desactivados unos 60 s en srv-dmz `ens35` (T3) | srv-dmz | Restaurados a `on` (comprobado) |

## 1. Preflight (Clientes, 05:59 y 06:02 UTC)

Resultado: **OK** en 20 de 20 comprobaciones:

- 6 alias;
- ningún generador en marcha;
- NTP sincronizado;
- 7,7 GB libres;
- sondas `api_ok` 200, `https` 200, `api_auth` 401, `api_404` 404 y `api_500` 500;
- `dns` con rcode 0 y A=10.10.30.10;
- `dns_inexistente` con rcode 3 (NXDOMAIN);
- `puerto_cerrado` con RST;
- `ping` con eco respondido;
- no cruza las 00:00 UTC.

## 2. T0: archivador solo, sin generador (05:57–06:02 UTC)

`V2-PRUEBA-20261124T055719Z` en Sensor1:

- 70 PCAP, 10,8 MB;
- EVE de 0,91 MB;
- fin programado limpio.

**Incidente de procedimiento.** La orden que lanzaba el archivador usaba `cd … && setsid … &`: el `&` se aplicaba a toda la cadena, la sesión SSH quedó retenida y el generador de esa ejecución arrancó tarde, a las 06:02:47, cuando el archivador T0 ya había terminado.

- Ese generador se registró con el identificador `…055719Z`.
- El archivador `V2-PRUEBA-20261124T060306Z`, que empezó a cubrir desde las 06:02:40, lo capturó entero.
- La relación entre los dos identificadores queda documentada aquí. No se renombró ninguna evidencia.

Corrección: `cd …; setsid nohup … &` (en `docs/COMANDOS.md`).

## 3. T1: prueba corta completa, 240 s, seis perfiles (06:02:47–06:06:48 UTC)

Ejecución `V2-PRUEBA-20261124T055719Z`, capturada por `V2-PRUEBA-20261124T060306Z`. Programa `prueba-corta.json`, sha256 `0715c658…`.

| Comprobación | Resultado |
|---|---|
| Fin propio | Seis perfiles con `fin` en t = 240,000–240,003 s y código 0; ninguna transacción después del fin |
| Transacciones | 395: ok 369, error_intencional 24, variacion_servidor 2 (POST → 500), **fallo_inesperado 0**, timeouts 0, excepciones 0 |
| Pausa F2 (60–90 s) | 0 transacciones; 6 eventos `pausa` |
| Fases y bloques | 24 eventos `fase` (4 × 6) y 12 eventos `bloque` (resiembra a los 120 s) |
| HTTP | 200 en web, https, api_ok y api_lento; 201 o 500 en api_post; 500 en api_500; 404 en api_404; 9 abandonos con cabeceras recibidas y corte |
| DNS | 62 `dns` con rcode 0 y A=10.10.30.10; 3 `dns_inexistente` con rcode 3 |
| TLS | 55 de 55 TLSv1.3 |
| Cobertura de peticiones (PCAP) | **395 de 395 (100 %)**: SYN, consulta DNS o eco |
| Respuestas | SYN-ACK en todas las TCP; RST en los 4 puertos cerrados; respuesta en las 65 consultas DNS y en los 11 ecos |
| Copias en el espejo | 321 SYN con 2 copias (VLAN 20 y 30), 6 con 1 y 2 con 4 (puerto reutilizado) |
| Desfase aparente (SYN − `inicio_utc`) | Mediana −0,03 ms; rango −0,52 a +0,25 ms (n = 384) |
| EVE | 478 `http` (468 con el mismo código que el registro, 2 distintos, 8 de las sondas del preflight), 224 `dns` (8 NXDOMAIN), 104 `tls` (todos TLS 1.3), 677 `flow` |
| Archivador | 67 PCAP, 17,07 MB, sin huecos de rotación; Δ`rx_dropped` 4 300 de 109 925 paquetes |
| **Carga útil servidor → clientes** | Registro: 93 313 423 B. PCAP sin copias: 283 036 B. **Fracción: 0,30 %** |

## 4. T2: corte forzado y parada controlada (06:09:38–06:10:52 UTC)

Ejecución y archivador `V2-PRUEBA-20261124T060910Z`. El archivador empezó 23 s antes que el generador.

| Paso | Resultado |
|---|---|
| `kill -9` a ligero (t ≈ 40 s) | El supervisor registró `perfil_terminado` con código −9 y clasificación `interrupcion`. **No hubo reinicio**: al final quedaban 0 procesos `clientes_lab_v2` |
| `v2ctl parar` (t ≈ 71 s) | SIGTERM reenviado. Los otros cinco terminaron en menos de 1 s con código 3 (`parado`) y evento `fin` (estado `interrumpida`, motivo SIGTERM, recuento de transacciones igual al registro) |
| Transacciones | 96: ok 89, error_intencional 7, fallo_inesperado 0 |
| Cobertura | 96 de 96 (100 %). Desfase mediano +0,30 ms; rango +0,12 a +0,47 ms |
| Carga útil | Registro: 18 899 522 B. PCAP: 63 702 B. **Fracción: 0,34 %** |
| Archivador | 52 PCAP, 8,86 MB. Δ`rx_dropped` 3 256 de 53 177 |

## 5. T3–T4: diagnóstico de la carga útil ausente (06:15–06:17 UTC)

**T3.** Un GET de 4 MB y un POST de 8 000 B con TSO/GSO activos en srv-dmz y otro par con TSO/GSO desactivados.

- En los dos casos el PCAP muestra 0,00 MB del servidor al cliente.
- **Descartada** la hipótesis de los segmentos TSO del servidor. TSO/GSO se restauraron a `on`.

**T4.** Un GET de 4 MB desde 10.10.20.24.

- `ens37` recibió en total 448 433 B y 3 972 paquetes de todo el espejo. Δ`rx_dropped` = 196.
- Del flujo solo se ven 10 tramas del servidor: SYN-ACK, ACK y cabeceras.

**Tamaños de trama en el espejo** (36 ficheros del anillo):

| Tamaño (bytes) | Tramas |
|---|---:|
| ≤ 128 | 32 733 |
| 129–512 | 11 639 |
| 513–1000 | 2 072 |
| 1001–1200 | 382 |
| 1201–1400 | 162 |
| 1401–1518 | 6 082 |
| > 1518 | 0 |

**Máximo: 1 496 bytes.** No aparece ninguna trama con un paquete IP de 1 500 bytes; etiquetada 802.1Q, esa trama mide 1 518 bytes.

**Conclusión (comprobada):** las tramas de tamaño completo no llegan a la VM del sensor. Tampoco cuentan como `rx_dropped` en la misma proporción, ni las cuentan los contadores del driver vmxnet3.

- `ens37` tiene MTU 1500 y el espejo entrega las tramas con etiqueta VLAN (troncal).
- **No está comprobado** si la trama se descarta en el vNIC (falta de margen para la etiqueta) o en el vSwitch o en el puerto de espejo de ESXi.
- **Afecta a V1:** las características de bytes de la línea base de V1 se calcularon sin la carga útil de las transferencias grandes. Hay que comunicarlo antes de reutilizar cualquier conclusión de V1 sobre bytes.

**Corrección propuesta.** Necesita sudo en Sensor1 y la decisión de Mark, porque también cambia lo que ve el motor V1 en sombra. Comandos en `docs/COMANDOS.md` §0:

1. MTU 9000 en `ens37`, de forma temporal, y repetir T4.
2. Si C7 sigue fallando, revisar en ESXi el grupo de puertos del sensor: MTU del vSwitch y longitud de paquete reflejado si es un vDS.
3. Hacer el cambio persistente con un drop-in de `cyberflow-capture-nic.service` y reiniciar `ppi-motor-capture` y `suricata` para que dimensionen sus búferes.

### T5: repetición de T4 con `ens37` a MTU 9000 (Mark, sudo, temporal)

Mark aplicó `ip link set dev ens37 mtu 9000` y comprobé que quedó activo. Repetí el GET de 4 MB desde 10.10.20.24:

- Δ `rx_bytes` de `ens37`: 488 145 B. Δ paquetes: 4 462. Δ `rx_dropped`: 196.
- Del flujo solo se ven 10 tramas del servidor; la mayor mide 966 B. Carga útil: 0,00 MB.
- tcpdump y Suricata siguen con 0 descartes y los servicios siguen activos.

**Conclusión:** el MTU del invitado **no** era la causa. Las tramas grandes no llegan a la VM: se pierden antes, en ESXi (vSwitch, grupo de puertos o sesión de espejo) o en el camino de reenvío.

Hay que revisarlo en el host, fuera del alcance de las VM:

- el MTU del vSwitch o vDS;
- si es un vDS, la sesión de espejo: «Mirrored packet length» y el puerto de destino;
- la seguridad del grupo de puertos del sensor (VLAN 4095, promiscuo);
- los offloads (LRO/TSO) del vNIC de pfSense, que reenvía entre la VLAN 30 y la 20 y podría generar supertramas.

El MTU 9000 no era persistente. **Revertido** por Mark a 1500 el 24-nov; `ppi-motor-capture`, `suricata` y `ppi-motor` siguieron activos (comprobado). `ens37` vuelve a su estado anterior.

### T6: camino del espejo en ESXi y en el switch físico

**Camino comprobado:**

- Sensor1 está en `esxi-hv-siem` y srv-dmz en `esxi-hv-servicios`, de modo que el tráfico entre ellos cruza la red física.
- El espejo es una sesión SPAN del switch físico. Según CDP, el puerto `GigabitEthernet1/0/23` de `CORE-STACK` (Cisco C9300L-24T-4G, 10.10.99.10) entra por `vmnic2` (I210-T1) en `vSwitch2`, y de ahí al grupo de puertos `PG-CYBERFLOW-SPAN` (VLAN 4095).
- Clientes de `PG-CYBERFLOW-SPAN`: SENSOR1, SENSOR2 y VM-SURICATA (todos de CyberFlow).

**Prueba.** Con `vSwitch2` y `vmnic2` a MTU 9000, una descarga de 4 MB hizo crecer en solo 756 162 B los bytes recibidos por **la propia NIC física** `vmnic2`, igual que `ens37`. `vmnic2` no tiene errores de recepción: 0 descartes, 0 errores de longitud, 0 CRC.

**Conclusión:** el switch físico no entrega las tramas grandes al puerto de destino del SPAN. Ni ESXi ni el sensor las descartan. El MTU de `vSwitch2` se devolvió a 1500 y el CDP a `listen`, sus valores anteriores.

**Dato relevante:** `vmnic2` negocia **100 Mbit/s** (full duplex) con un puerto gigabit. Una sesión SPAN de fuentes de 1 Gbit/s hacia un destino de 100 Mbit/s pierde las ráfagas. Esas ráfagas son justamente las tramas de datos de tamaño completo, mientras que los ACK y SYN, pequeños y espaciados, sobreviven. Es la hipótesis principal y se comprueba con los contadores de descartes de salida de Gi1/0/23 (COMANDOS §0).

## 6. Pruebas sin red del repositorio

`python -m unittest discover -s tests` da 20 de 20 en Windows (Python 3.14.3). Cubren:

- programas: contiguos, presupuesto 24/9/9, semillas únicas, rechazo de huecos, solapes y acciones desconocidas, regeneración byte a byte;
- generador: duración finita, pausa, resiembra, reproducibilidad, parada controlada, esperas que no cruzan fases, piso de 0,05 s sobre la media;
- clasificación: NOERROR sin la A esperada es un fallo; NXDOMAIN intencional; POST 500 es variación del servidor; timeout y puerto abierto son fallos.

## 7. Qué queda probado y qué no

- **Probado:**
  - el generador con duración finita;
  - el registro por transacción;
  - las fases, la pausa, los bloques y las semillas;
  - la parada controlada sin reinicio;
  - la detección de interrupciones;
  - el DNS controlado con NXDOMAIN real;
  - la cobertura de peticiones y respuestas;
  - el archivado de PCAP y EVE fuera del anillo, con hashes;
  - la medida del desfase de relojes.
- **No probado:**
  - el piloto de 30 min (preparado, no iniciado);
  - los pulsos del piloto y los periodos activos (solo pruebas unitarias y el pulso de la prueba corta);
  - el volumen por hora con carga sostenida;
  - el truncado del EVE a las 00:00 UTC;
  - la condición de parada por espacio.
- **Bloqueado:** reconstruir las características de bytes a partir de los originales (C7), por el espejo.
