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
| 12 | **Espejo sin tramas de tamaño completo** (carga útil al 0,3 %) | **Pendiente (bloqueante)** | MTU 9000 en `ens37` probado el 24-nov (T5) **sin efecto**: las tramas no llegan a la VM. Hay que revisarlo en ESXi (espejo, vSwitch, offloads de pfSense); es acceso de Mark |
| 13 | Configuración del SPAN en ESXi (grupo de puertos, VLAN 4095, MTU, vDS) | Pendiente | No es visible desde las VM; acceso de Mark al host |
| 14 | Discrepancia de `rx_dropped` | Pendiente | Δ del 4–6 % en las pruebas; unida al punto 12 |
| 15 | Truncado del EVE por copytruncate a las 00:00 UTC | Implementado sin verificar | El archivador lo registra; programar las jornadas sin cruzar las 00:00 UTC |
| 16 | Volumen GB/h con carga sostenida y destino del almacenamiento privado | Pendiente | Medir en el piloto (tras el punto 12). Sensor1 tiene 24 GB libres; decidir el disco destino |
| 17 | Condición de parada por espacio | Implementado sin verificar | `--libre-minimo-gb 4` |
| 18 | Relojes: desfase entre Clientes y Sensor1 | Comprobado | \|desfase\| ≤ 0,52 ms en T1 y T2 |
| 19 | Reloj de srv-dmz y DC1 frente a Sensor1 | Pendiente | Añadir sondas al archivador o medir con el SYN-ACK |
| 20 | Eventos TLS | Comprobado (perfiles) | T1: 104 eventos TLS 1.3; queda pendiente por qué desde el bastión salió 0 de 13 |
| 21 | Extracción V2: filtro por paquete de las entidades excluidas, deduplicación del espejo, paridad, márgenes, constantes | Pendiente | `extraccion/`: incorporar `extract_multilayer_v3` con procedencia y pruebas |
| 22 | Población: inventario de las IP observadas con su regla | Pendiente | Tras el piloto |
| 23 | Piloto de 30 min | Pendiente (preparado, no iniciado) | PROTOCOLO §10; C7 fallaría hasta resolver el punto 12 |
| 24 | Decisión de Mark: acumulador y aprendizaje V1 durante las jornadas | Pendiente | Exclusión por ventana (hecha) o parar los timers (sudo) |
| 25 | Decisión de Mark: multiplicadores definitivos (×1,25, ×1,5, ×4, periodos activos) | Pendiente | Validar en el piloto; no ajustar con métricas |
| 26 | E1–E3 (18 h tras el congelado), ataques y campañas A/B | Pendiente (fuera de esta preparación) | No iniciados, según lo pedido |
| 27 | Scripts de procesamiento, entrenamiento y evaluación | Pendiente | Se incorporarán después, con su procedencia |
| 28 | Código público de V1 con nombres de otro dominio en `clientes_lab.py` | Pendiente | Anotado; no se ha tocado V1 |
