# Estado de cada elemento (24-nov-2026)

**Leyenda:**

- **Comprobado:** hay una prueba o evidencia en el laboratorio.
- **Implementado sin verificar:** el código o el cambio existe, pero no se ha ejercitado en el laboratorio.
- **Pendiente:** falta hacerlo o decidirlo.

Preparar una prueba no es pasarla, y pasarla no cierra una observación de los revisores (ver `MATRIZ-OBSERVACIONES.md`).

## Tabla

| # | Elemento | Estado | Evidencia o lo que falta |
|---|---|---|---|
| 1 | 11 filas del 24-nov: respaldo, causa (añadidas, no modificadas) y exclusión del aprendizaje V1 | Comprobado | ACLARACIONES §2.1–2.2; 11 de 11 excluidas con las funciones del propio programa |
| 2 | Exclusión V1 de las pruebas V2 del 24-nov | Comprobado | Regla `*@05:59/06:25`, con respaldos |
| 3 | Espera exponencial: piso sobre la media | Comprobado | Prueba unitaria; T1 tuvo 18 esperas < 0,05 s |
| 4 | Cifras del 58 % y las 38 IP con fichero y denominador | Comprobado | ACLARACIONES §2.6 (sha256 `bdf6f641…`) |
| 5 | `--history-seconds 230` frente a 10/30/60 s | Comprobado | ACLARACIONES §2.5 |
| 6 | Generador V2: duración, IDs, semillas, programa monotónico, parada, sin reinicio | Comprobado | T1, T2 y 20 pruebas unitarias |
| 7 | Programas J1–J7, P0 y prueba corta | Implementado sin verificar (J1–J7, P0); comprobado (prueba corta) | J1–J7 validados por esquema y pruebas unitarias; nunca ejecutados |
| 8 | Zona DNS controlada `cf-v2.lab` y NXDOMAIN real | Comprobado | Preflight; T1: 3 de 3 NXDOMAIN en el registro y en el EVE |
| 9 | Registro por transacción con lo esperado frente a lo observado | Comprobado | T1: 395 transacciones, 0 fallos inesperados |
| 10 | Archivado de PCAP y EVE fuera del anillo, con hashes | Comprobado | T1 y T2: manifiesto e inventario |
| 11 | Proceso que borra el anillo | Comprobado | `cyberflow-limpieza.timer`: `find … -mmin +15 -delete`, cada 5 min |
| 12 | **Espejo sin tramas de tamaño completo** (carga útil al 0,3 %) | **Comprobado (corregido en running-config)** | T7: `mtu 9198` en CORE-STACK `Gi2/0/19` (destino del SPAN) y enlace a 1 Gbit/s. A ≤ 10 MB/s llegan las dos copias completas; en ráfagas a velocidad de línea el destino satura. Falta `write memory` (Mark) |
| 12b | Cambio de distribución de bytes en V1 en sombra al llegar la carga útil completa | Pendiente (decisión de Mark) | Desde el 24-nov ~18:40 UTC; valorar excluir del aprendizaje V1 o pausar sus timers |
| 12c | Carga útil en descargas a velocidad de línea | Comprobado (limitación) | T8: 85,96 % del servidor. La saturación del destino del SPAN con dos copias está en `web_grande`; aceptar, limitar o espejar un sentido es decisión de Mark |
| 13 | Configuración del SPAN (orígenes, destino, VLAN, camino en ESXi) | Comprobado | T6/T7: SPAN 1 de CORE-STACK, Gi1/0/23 y Gi2/0/23 (both) → Gi2/0/19 → vmnic2 → vSwitch2 → PG-CYBERFLOW-SPAN (VLAN 4095); estándar, sin vDS; VLAN 20 y 30 observadas |
| 14 | Discrepancia de `rx_dropped` | Comprobado | T9: son tramas sin protocolo manejado (2,74 % frente a 2,90 % en el PCAP) y se entregan antes a tcpdump; no es pérdida |
| 15 | Truncado del EVE por copytruncate a las 00:00 UTC | Implementado sin verificar | El archivador lo registra; programar las jornadas sin cruzar las 00:00 UTC |
| 16 | Volumen GB/h con carga sostenida y destino del almacenamiento privado | Pendiente (**bloqueante para las 42 h**) | T8: 0,78 GB/h con la prueba corta, que da ~33 GB para 42 h, y Sensor1 tiene 23 GB libres. Hay que medirlo con el programa del piloto y decidir el disco destino (Mark) |
| 17 | Condición de parada por espacio | Implementado sin verificar | `--libre-minimo-gb 4` |
| 18 | Relojes: desfase entre Clientes y Sensor1 | Comprobado | \|desfase\| ≤ 0,52 ms en T1 y T2 |
| 19 | Reloj de srv-dmz y DC1 frente a Sensor1 | Comprobado (puntual) | T10: srv-dmz −0,15 ms, DC1 +2,7 ms, Clientes −0,23 ms frente a NTP. Falta automatizar la medida antes y después de cada jornada |
| 20 | Eventos TLS | Comprobado (perfiles) | T1: 104 eventos TLS 1.3; T8, con el espejo corregido: 112 TLS 1.3. Queda pendiente por qué desde el bastión salió 0 de 13 (anterior al arreglo; repetir) |
| 21 | Extracción V2: filtro por paquete de las entidades excluidas, deduplicación del espejo, paridad, márgenes, constantes | Pendiente | `extraccion/`: incorporar `extract_multilayer_v3` con procedencia y pruebas |
| 22 | Población: inventario de las IP observadas con su regla | Pendiente | Tras el piloto |
| 23 | Piloto de 30 min | Pendiente (preparado, no iniciado) | PROTOCOLO §10; el punto 12 está resuelto, así que C7 ya puede medirse |
| 24 | Decisión de Mark: acumulador y aprendizaje V1 durante las jornadas | Pendiente | Exclusión por ventana: hecha, incluidas T5–T8, y también excluye todo V1 del 24-nov a las 18:15 al 26-nov a las 00:00 por la deriva del punto 12b; o parar los timers (sudo) |
| 25 | Decisión de Mark: multiplicadores definitivos (×1,25, ×1,5, ×4, periodos activos) | Pendiente | Validar en el piloto; no ajustar con métricas |
| 26 | E1–E3 (18 h tras el congelado), ataques y campañas A/B | Pendiente (fuera de esta preparación) | No iniciados, según lo pedido |
| 27 | Scripts de procesamiento, entrenamiento y evaluación | Pendiente | Se incorporarán después, con su procedencia |
| 28 | Código público de V1 con nombres de otro dominio en `clientes_lab.py` | Pendiente | Anotado; no se ha tocado V1 |
