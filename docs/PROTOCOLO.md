# Protocolo de recolección de CyberFlow V2

Versión 0.1, 24-nov-2026. **Preparación**: aún no se ha iniciado ni el piloto de 30 min ni ninguna captura definitiva.

CyberFlow V2 es un **estudio nuevo**:

- Se capturan de nuevo los conjuntos de datos, el escalador, el Isolation Forest (IF), la calibración y los umbrales.
- De V1 se reutiliza código, siempre con su procedencia (`docs/PROCEDENCIA.md`).
- **No** se reutilizan datos, modelo, umbral ni resultados de V1.

## 1. Alcance y equipos

Solo la arquitectura de CyberFlow:

- **Clientes** (seis alias: 10.10.20.21–26)
- **srv-dmz** (10.10.30.10: HTTP en el 80, HTTPS en el 443)
- **DC1** (10.10.10.20, solo DNS)
- **Sensor1** (`ens37`, espejo en troncal 802.1Q)
- **Bastión** (acceso)

Fuera de alcance: Wazuh, Zabbix, VM-BACKUP y los equipos de otros proyectos.

## 2. Presupuesto y calendario

- **Captura legítima de desarrollo:** 42 h brutas en siete jornadas de 6 h. Cada jornada tiene dos bloques de 3 h. Reparto nominal: 24 h de entrenamiento, 9 de calibración y 9 de desarrollo (`programas/`).
- **Tras congelar:** 18 h nuevas de control legítimo independiente (E1–E3, todavía por definir). Los ataques y las campañas A/B van aparte, con su propio presupuesto.
- **Horas útiles.** Se publican tres cifras: horas brutas, utilizables y excluidas (con su motivo). No se fijan de antemano.
- **Qué representan.** Las jornadas son sesiones sintéticas parciales, no una semana de 168 h.
- **Asignación de particiones (hoja Calendario del plan):**
  - J1: entrenamiento / entrenamiento;
  - J2, J4, J6: entrenamiento / calibración;
  - J3, J5, J7: entrenamiento / desarrollo.

## 3. Generador

`generador/clientes_lab_v2.py`. Cada parámetro de los programas indica su procedencia: V1, PLAN o NUEVA.

- **Duración finita.** Se lanza un proceso por perfil y se lleva un registro JSONL por transacción y otro de eventos.
- **Semillas.** Hay una por perfil y bloque, fijada antes de capturar.
- **Programa por tiempo transcurrido.** Se mide con reloj monotónico y sustituye al factor horario y al de fin de semana de V1.
- **Espera** (V1): `expovariate(1/max(ritmo/factor, 0.05))`. El piso de 0,05 s se aplica a la media, no a cada espera. Cambio documentado: si una espera cruza un cambio de fase, se corta en el borde y se vuelve a sortear.
- **Ráfagas de errático** (V1): probabilidad 0,02 por iteración, 20–90 s, ×6. No equivale a un 2 % del tiempo.
- **Parada controlada** con SIGTERM: termina y registra la acción en curso. **Sin reinicio automático.**
- **Cuándo se modifica.** Las acciones, los pesos, los ritmos, las rutas y los tamaños son los de V1. Solo pueden cambiarse por una decisión registrada en `docs/PENDIENTES.md`, nunca a partir de métricas del detector.

## 4. Programas de las siete jornadas

Ver `programas/README.md`. Los multiplicadores del plan (×1,25, pulsos ×1,5, ×0,30) son **propuestas a validar** en el piloto, no estándares. No se ajustan con métricas del detector.

## 5. Servicios y registro por transacción

**Preflight** (`operacion/v2ctl.py preflight`). Comprueba:

- los alias de cada perfil;
- que no haya otro generador en marcha;
- la sincronización NTP y el espacio libre;
- una sonda de cada servicio: HTTP 200, HTTPS 200, 401, 404, 500, DNS existente con la IP correcta, NXDOMAIN, puerto cerrado e ICMP;
- que la jornada no cruce las 00:00 UTC (rotación del EVE).

**DNS.** Zona controlada `cf-v2.lab` en DC1, creada el 24-nov. Seis nombres (`portal`, `intranet`, `correo`, `wiki`, `erp`, `archivos`) con registro A a 10.10.30.10.

- Cualquier otro nombre de la zona devuelve NXDOMAIN (comprobado).
- Un NOERROR **no** cuenta como éxito si la respuesta no contiene la A esperada.

**Registro.** Cada transacción guarda:

- ejecución, jornada, perfil, bloque, fase, pulsos y ráfaga;
- id de transacción y acción;
- origen (IP:puerto) y destino (IP:puerto);
- inicio y fin en UTC, duración monotónica, bytes de aplicación enviados y recibidos;
- código HTTP o rcode DNS con sus registros A, versión TLS;
- excepción, timeout e «incompleta»;
- resultado esperado, resultado observado, si coinciden y la clase.

**Clases:**

- `ok`;
- `error_intencional` (401, 404 y 500 provocados, NXDOMAIN, puerto cerrado, abandono);
- `variacion_servidor` (POST con 500: el servidor de V1 responde 500 al 10 % de los POST);
- `fallo_inesperado` (todo lo demás).

**Aleatoriedad del servidor** (`servidor_lab.py`, sin cambios):

- POST → 500 con probabilidad 0,1;
- `/api/lento` espera entre 1,5 y 4 s.

El servidor no lleva registro propio; el resultado real lo registra el cliente.

## 6. Captura y conservación

**El anillo de V1 no se toca:**

- tcpdump con `-G 5` en `/var/lib/ppi-motor-capture`;
- lo poda `cyberflow-limpieza.timer` (borra los ficheros con más de 15 min).

**`captura/archivar_v2.py`** (sin privilegios):

- Copia cada PCAP cerrado a `~/cyberflow-v2/capturas/<ejecución>/pcap/` y guarda su sha256 en `inventario.jsonl`.
- Sigue `eve.json` por desplazamiento y registra los truncados (copytruncate).
- Detecta huecos de rotación de más de 6 s.
- Anota los contadores de `ens37`, softnet, tcpdump, Suricata y el reloj al principio y al final.
- Para si el espacio libre baja de 4 GB.
- Al terminar escribe `manifiesto.json`.

**Márgenes:**

- Arrancar el archivador **≥ 2 min antes** del generador: el EVE empieza en el desplazamiento del arranque.
- Pararlo **≥ 10 min después**, para recoger los eventos `flow` que Suricata emite al expirar.

**Volumen y destino:**

- El volumen por hora se mide en el piloto.
- Sensor1 tiene unos 24 GB libres en `/`. Las capturas completas se sacan de Sensor1 al terminar cada jornada, hacia un almacenamiento privado (destino pendiente: ver PENDIENTES).
- En el repositorio solo se publican los manifiestos y los hashes.

**Bloqueante hallado el 24-nov.** El espejo no entrega a `ens37` las tramas de tamaño completo (802.1Q de 1518 bytes): falta casi toda la carga útil de las descargas (T3/T4 del informe). Hasta corregirlo no se pueden reconstruir las características de bytes a partir de los originales. Ver `docs/INFORME-PRUEBAS-2026-11-24.md` §4.

## 7. Población y extracción

**Población principal:** los seis perfiles.

- Toda otra IP observada se inventaría con su regla y su motivo:
  - infraestructura de CyberFlow: srv-dmz, DC1, Sensor1, bastión;
  - tráfico de gestión;
  - otros.
- Se publica la cadena de conteos PCAP → eventos → filas → deduplicación → exclusión → guarda → particiones.

**Fuga demostrada en V1.** `--excluir` no impide que el tráfico de la entidad excluida entre en las características de otras entidades (§2.1 de ACLARACIONES).

- En V2 el tráfico de gestión (bastión, SSH, sensor) se filtra **por paquete** antes de calcular las características.
- Hay que decidir y documentar cómo se tratan las respuestas del servidor: la entidad servidor no es población principal.

**Antes de la captura definitiva hay que verificar** (implementado en `extraccion/`; comprobado en T11 y en el piloto):

- paso de 10 s;
- historias de 10, 30 y 60 s;
- denominadores, cero frente a ausente, columnas constantes, inactividad;
- arranque en frío (margen de 60 s) y bordes de partición;
- deduplicación del espejo: cada paquete aparece dos veces, en la VLAN 20 y en la VLAN 30 (comprobado en T1);
- paridad entre entrenamiento y operación;
- que no haya fugas de futuro.

**Trazabilidad de cada ventana (implementada el 24-nov, `extraccion/metadatos_v2.py`).**
Las 28 entradas del IF y los metadatos van en ficheros distintos, unidos solo por `ventana_id`
(`<ejecución>|<IP>|<cierre UTC>`):

| Fichero | Contenido |
|---|---|
| `extraccion/entradas_if.csv` | `ventana_id` + las 28 columnas del contrato, en su orden. Nada más |
| `extraccion/ventanas_meta.csv` | ejecución, entidad, perfil, regla de población, inicio y cierre UTC, t del programa, bloque, partición, segmento, fase (y si la ventana cruza fase), pulsos, marca de la extracción, PCAP de la ventana y primero/último de la historia de 60 s, EVE y su sha256, transacciones en la ventana, estado de cobertura, estado de conciliación, hueco de captura, `excluir_entrenamiento` y sus motivos |
| `extraccion/trazabilidad.json` | comprobación: ids únicos, relación 1:1 en el mismo orden, cabecera de entradas = las 28, ningún metadato entre las 28, campos obligatorios llenos; conteos por partición, bloque, perfil, cobertura, conciliación y regla de exclusión |

Las fronteras de bloque salen del programa y del evento `inicio` de cada perfil
(`metadatos_v2.py fronteras`) y se pasan a la extracción y a la verificación, así que ninguna
historia cruza un bloque. Primera prueba con datos reales (T11, 155 ventanas): trazabilidad
correcta, 0 obligatorios vacíos, desfase de arranque entre perfiles 18 ms.

**Reglas de exclusión del entrenamiento** (una ventana excluida se conserva y se cuenta; no se borra):

| Regla | Motivo |
|---|---|
| E1 | marca de arranque o de frontera de bloque: la historia de 60 s está incompleta |
| E2 | hueco de captura PCAP o EVE que toca [cierre − 60 s, cierre] |
| E3 | alguna transacción del perfil en la ventana con cobertura incompleta o no verificable |
| E4 | alguna transacción del perfil en la ventana conciliada como `fallo_imprevisto` o no verificable |
| E5 | ventana fuera del programa (márgenes de captura previo y final) |

Las pausas programadas no excluyen: son inactividad legítima. Las etiquetas de ataque, cuando
las haya, irán en `ventanas_meta.csv` con las reglas de `docs/ETIQUETADO-ATAQUES.md`.

**TLS.** En T1 Suricata registró eventos TLS 1.3 para el tráfico de los perfiles: 104 eventos para 55 transacciones HTTPS. Desde el bastión había 0 de 13. No se fuerza ninguna versión.

## 8. Relojes, contadores e interrupciones

**Relojes:**

- Clientes se sincroniza con ntp.ubuntu.com; Sensor1, con 10.10.60.1.
- Desfase aparente medido con el SYN en el espejo frente al `inicio_utc` del cliente: mediana −0,03 ms (T1) y +0,30 ms (T2), rango −0,52 a +0,47 ms. Incluye la latencia de la pila.
- Para las duraciones se usa reloj monotónico; para correlacionar, UTC.

**Contadores, al inicio y al final de cada ejecución:**

- `ens37` (paquetes, bytes, `rx_dropped`);
- softnet;
- estadística de tcpdump (cada 30 s, con SIGUSR1);
- `capture.kernel_*` de Suricata.

**Discrepancia de `rx_dropped`.** tcpdump y Suricata pierden 0 paquetes y `rx_dropped` sube entre un 4 y un 6 % durante las pruebas. No basta para explicar las tramas grandes ausentes, que no llegan a la NIC. Sigue abierta y unida al bloqueante del MTU.

**Interrupciones.** El supervisor clasifica cada perfil:

| Código | Clasificación |
|---|---|
| 0 | completo |
| 3 | parado (SIGTERM) |
| otro | interrupción |

**Reglas fijadas antes de capturar:**

- Una interrupción no se reanuda en la misma ejecución. La jornada se repite completa, con un identificador nuevo y el mismo programa congelado (las mismas semillas), solo si la causa es técnica: pérdida de captura, caída de un servicio de CyberFlow o fallo del generador.
- Máximo **una repetición por jornada**. La ejecución fallida se conserva con su motivo.
- No se repite ninguna jornada por sus resultados.

## 9. Aislamiento de V1

Durante las ejecuciones V2, el motor V1 sigue en sombra: srv-dmz sin `--aplicar` (comprobado) y DC1 sin tablas nft (comprobado).

Para que V2 no entre en el aprendizaje de V1, cada ejecución añade a `excluir_ventanas` una regla `*@inicio/fin`, con respaldo, igual que se hizo con las pruebas del 24-nov. La alternativa de parar `cyberflow-acumular.timer` y `cyberflow-aprendizaje.timer` durante las jornadas necesita sudo y es decisión de Mark.

**Congelado:** al terminar el desarrollo se congelan el modelo, α, las reglas, la vía rápida y las versiones, antes de E1–E3.

## 10. Piloto de 30 min

Programa `programas/piloto-30min.json` (sha256 en el manifiesto): seis perfiles, dos bloques (resiembra a los 900 s) y estas fases:

| Fase | Tramo | Factor | Notas |
|---|---|---|---|
| F1 | 0–300 s | ×1,00 | |
| F2 | 300–600 s | ×0,55 | |
| F3 | 600–900 s | ×0,90 | |
| F4 | 900–1080 s | ×0 | parada total |
| F5 | 1080–1500 s | ×0,30 | periodo activo A1 en 1200–1260 s; pulso P1 ×1,5 en 1320–1440 s |
| F6 | 1500–1800 s | ×1,00 | |

Ofimática y navegación van a ×1,25. **No se usa en métricas.** Comandos en `docs/COMANDOS.md`.

### Comprobaciones del piloto y criterio de aceptación (versión 2, fijada el 24-nov a las 22:45 UTC, antes de lanzarlo)

Sustituye a la versión 1 (C7 «hoy fallaría», C8 «sin cruzar las 00:00»). Se lanza con
`bash lanzar_v2.sh piloto-30min.json PILOTO 2` y se cierra con `bash cerrar_v2.sh <ID>`.
Un criterio que falle no se corrige repitiendo el piloto hasta que pase: se documenta la causa,
se corrige y se registra el intento fallido. Ningún criterio mira resultados del detector.

| # | Comprobación | Criterio de aceptación | Fuente |
|---|---|---|---|
| C1 | Los seis perfiles terminan solos | Seis `perfil_terminado` con código 0; `manifiesto-fin` estado `completa` | `supervisor.jsonl`, `manifiesto-fin.json` |
| C2 | Fases y pausa | Ninguna transacción con `inicio_t_s` en [900, 1080); un evento `fase` por fase y perfil (6 × 6) | `transacciones-*`, `eventos-*` |
| C3 | Pulsos y periodo activo | Transacciones con `pulsos` que incluyen P1 solo en [1320, 1440) y A1 solo en [1200, 1260); su factor coincide con el programa | `transacciones-*` frente a `programa.json` |
| C4 | Resiembra | Dos eventos `bloque` por perfil, con las semillas del programa | `eventos-*` |
| C5 | Clasificación del cliente | 0 `fallo_inesperado` | `transacciones-*` |
| C6 | Conciliación con el registro independiente | 0 `fallo_imprevisto` y 0 `incompleta_no_verificable` entre cliente y srv-dmz/DC1 | `conciliacion/` |
| C7 | Cobertura de la captura | Fases: conexión, petición y respuesta vistas en el 100 % de lo que aplica; bytes de respuesta vistos / bytes TCP recibidos ≥ 95 % **en el total, en cada acción comparable y en cada perfil**; 0 `no verificable` | `cobertura/` |
| C8 | Archivado | Manifiesto del archivador `completa`: 0 huecos PCAP, 0 huecos EVE, 0 líneas corruptas | `capturas/<ID>/manifiesto.json` |
| C9 | Pérdidas en toda la cadena | Δ output drops de Gi2/0/19 y de los orígenes, Δ`rx_missed_errors`/softnet y descartes de tcpdump/Suricata registrados antes y después. Se acepta Δdrops = 0; si no, se cuantifica y C7 decide | `contadores-lab-*.txt` |
| C10 | Relojes | NTP sincronizado en los cuatro equipos al principio y al final; \|desfase aparente\| mediano ≤ 5 ms | `relojes-*`, `cobertura/` |
| C11 | Extracción | `extraer_v2` y `verificar_v2` con rc 0; verificación 40/40 sin diferencias (historia del motor 230 s); inventario con todas las IP y su regla; constantes justificadas; tardías descartadas = 0 | `extraccion/` |
| C11b | Trazabilidad de ventanas (añadido a las 23:05 UTC, durante el piloto y antes de cerrarlo, a petición de Mark) | `trazabilidad_ok`: cada ventana con ejecución, entidad, perfil, cierre, bloque, partición, fase, PCAP/EVE, cobertura, conciliación y exclusión; 1:1 con `entradas_if.csv`, que tiene exactamente las 28 columnas | `extraccion/trazabilidad.json` |
| C12 | Volumen | GB/h de PCAP comprimido, EVE y registros por fase medidos; se recalcula la estimación de 42 h con estos valores | `volumen.jsonl` |
| C13 | Aislamiento de V1 | Regla `*@` que cubre la ejecución; sets de srv-dmz vacíos, DC1 sin reglas y agente sin `--aplicar` al principio y al final | `preflight-lab.jsonl`, `contadores-lab-*.txt` |

Lo que el piloto no puede mostrar se prueba aparte: rotación y sustitución del EVE, PCAP borrado
antes de copiarse y línea partida o corrupta (`captura/prueba_rotacion_lab.py`); parada por
espacio y por caída del archivador (prueba de parada coordinada); cruce de las 00:00 UTC (la
rotación real ocurre en la primera noche de las 42 h y se clasifica con `eve/huecos.jsonl`).
