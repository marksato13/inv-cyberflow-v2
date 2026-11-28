# Protocolo de recolección de CyberFlow V2

Versión 0.2, 27-nov-2026. **Preparación**: aún no se ha iniciado ni el piloto final ni la captura definitiva. El contrato vigente de perfiles y calendario es `CONTRATO-GENERADOR-49H.md` v3; los resultados históricos de V1 y de las pruebas cortas conservan su propia versión.

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

- **Captura legítima de desarrollo:** 49 h brutas continuas en siete jornadas de 7 h. Cada jornada tiene dos bloques de 3,5 h. Reparto nominal: 28 h de entrenamiento, 10,5 h de calibración y 10,5 h de desarrollo (`programas/captura-49h.json`). El programa está definido, no ejecutado.
- **Tras congelar:** 18 h nuevas de control legítimo independiente (E1–E3, todavía por definir). Los ataques y las campañas A/B van aparte, con su propio presupuesto.
- **Horas útiles.** Se publican tres cifras: horas brutas, utilizables y excluidas (con su motivo). No se fijan de antemano.
- **Qué representan.** Las jornadas son sesiones sintéticas parciales, no una semana de 168 h.
- **Asignación de particiones (hoja «3 Jornadas» del Excel):**
  - J1: entrenamiento / entrenamiento;
  - J2, J4, J6: entrenamiento / calibración;
  - J3, J5, J7: entrenamiento / desarrollo.

## 3. Generador

`generador/clientes_lab_v2.py` v3. El contrato y la procedencia de cada parámetro están en `CONTRATO-GENERADOR-49H.md` y en `programas/captura-49h.json`.

- **Duración finita.** Se lanza un proceso por perfil y se lleva un registro JSONL por transacción y otro de eventos.
- **Semillas.** Hay tres flujos independientes (`espera`, `contenido`, `red`) por perfil y bloque, derivados por SHA-256 de la semilla maestra, el programa, el bloque, el perfil y el flujo; se registran al entrar en cada bloque.
- **Programa por tiempo transcurrido.** Se mide con reloj monotónico y sustituye al factor horario y al de fin de semana de V1.
- **Espera** (v3): exponencial de media `media_base/factor`, sorteada tras terminar la acción. Se corta y resortea al cambiar nivel, bloque, jornada u ON/OFF. El parsing de P2 conserva media 0,13 s y no se escala.
- **P6** (v3): ON 60 s y OFF 120 s; durante OFF no comienza una acción nueva. Una acción iniciada en ON puede terminar en OFF y se registra el cruce.
- **Parada controlada** con SIGTERM: termina y registra la acción en curso. **Sin reinicio automático.**
- **Cuándo se modifica.** Los perfiles v3 sustituyen las acciones de V1. Toda modificación requiere una decisión registrada antes de capturar y un programa con nuevo hash; nunca se elige mirando métricas del detector.

## 4. Programas de las siete jornadas

Ver `programas/README.md` y el contrato §7. Los niveles son `reducido` (factor 1/3), `base` (1) y `aumentado` (2), aplicados a las pausas de interacción. J1 y J5 son base; J2 aumenta P1/P2; J3 aumenta P3/P4; J4 tiene siete ráfagas de cinco minutos de P1/P2/P4; J6 tiene cuatro periodos de 15 minutos en base sobre fondo reducido; J7 tiene seis ráfagas de tres minutos en base sobre fondo reducido. Cada bloque tiene semillas distintas. Son contrastes sintéticos del diseño, no medias de usuarios reales.

## 5. Servicios y registro por transacción

**Preflight** (`operacion/v2ctl.py preflight`). Comprueba:

- los alias de cada perfil;
- que no haya otro generador en marcha;
- la sincronización NTP y el espacio libre;
- una sonda de cada servicio: HTTP 200, HTTPS 200, 401, 404, 500, DNS existente con la IP correcta, NXDOMAIN, puerto cerrado e ICMP;
- que la jornada no cruce las 00:00 UTC (rotación del EVE). *(Superado: en el `v2ctl.py` actual esta comprobación es informativa y cruzar las 00:00 UTC está permitido; ver `BLOQUE1-CIERRE.md` §12.)*

**DNS.** Zona controlada `cf-v2.lab` en DC1, creada el 24-nov. Seis nombres (`portal`, `intranet`, `correo`, `wiki`, `erp`, `archivos`) con registro A a 10.10.30.10.

- Cualquier otro nombre de la zona devuelve NXDOMAIN (comprobado).
- Un NOERROR **no** cuenta como éxito si la respuesta no contiene la A esperada.
- El generador v3 consulta directamente a DC1 por UDP antes de cada ciclo; no usa caché local. P2 consulta una vez por página y P4 una vez por secuencia. Las sondas del preflight quedan separadas del periodo útil.

**Registro.** Cada transacción guarda:

- ejecución, jornada, perfil, bloque, partición y nivel;
- id de transacción y acción;
- origen (IP:puerto) y destino (IP:puerto);
- inicio y fin en UTC, duración monotónica, bytes de aplicación enviados y recibidos;
- código HTTP o rcode DNS con sus registros A, versión TLS;
- excepción, timeout e «incompleta»;
- resultado esperado, resultado observado, si coinciden y la clase.

**Clases:**

- `ok`;
- `error_intencional` (401, 404 y 500 provocados, NXDOMAIN, puerto cerrado, abandono);
- `variacion_servidor` solo para registros históricos de V1; el POST normal de v3 no sortea errores;
- `fallo_inesperado` (todo lo demás).

**Servidor v3** (`servidor/servidor_lab_v2.py`): `GET /contenido/<n>` devuelve 200 y exactamente `n` bytes con límite de 5 MB/s por conexión; `GET /app/consulta?ref=<k>` devuelve 200 y 512 bytes; `POST /app/envio` devuelve 201 con longitud y SHA-256 recibidos. Las rutas inválidas generan 400 solo en pruebas dirigidas. Las rutas V1 se conservan para compatibilidad, fuera del programa v3. El servidor registra cada petición y su resultado; se concilia con el registro del cliente. El contrato §3 detalla tamaños, límites y respuestas.

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

- El volumen por hora y por nivel se mide en el piloto integrado; el C12 de 49 h exige la medición prolongada.
- La revisión de preparación del 28-nov (`BLOQUE4-PREPARACION-2026-11-28.md`) encontró 16,22 GB libres en Sensor1 y una proyección conservadora provisional de ≈ 50 GB para 49 h, más 4 GB de reserva local. La capacidad local y el destino privado de las capturas siguen sin resolver; no se inicia la captura definitiva antes de probar una solución.
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
- arranque en frío y bordes de partición con horizonte de estado de 230 s, además de las ventanas de 10/30/60 s;
- deduplicación del espejo: cada paquete aparece dos veces, en la VLAN 20 y en la VLAN 30 (comprobado en T1). Desde el Bloque 3 (27-nov) se usa `deduplicar_v2`: clave con `ack` y `flags`, 20 ms, (VLAN, TTL) único por grupo y 2 copias en difusión (`extraccion/README.md`);
- paridad entre entrenamiento y operación. La deduplicación es el mismo módulo, byte a byte, en el extractor y en el motor del producto, que lo usa con `--deduplicacion v2`. Operar un modelo entrenado con V2 exige esa opción; la omisión `v1` es la del modelo actual;
- que no haya fugas de futuro.

**Trazabilidad de cada ventana (implementada el 24-nov, `extraccion/metadatos_v2.py`).**
Las 28 entradas del IF y los metadatos van en ficheros distintos, unidos solo por `ventana_id`
(`<ejecución>|<IP>|<cierre UTC>`):

| Fichero | Contenido |
|---|---|
| `extraccion/entradas_if.csv` | `ventana_id` + las 28 columnas del contrato, en su orden. Nada más |
| `extraccion/ventanas_meta.csv` | ejecución, entidad, perfil, regla de población, inicio y cierre UTC, t del programa, bloque, partición, jornada, nivel y cruce de nivel, P6 ON, marca de la extracción, PCAP de la ventana e historia, EVE y su sha256, transacciones en la ventana, cobertura, conciliación, hueco de captura, `excluir_entrenamiento` y sus motivos |
| `extraccion/trazabilidad.json` | comprobación: ids únicos, relación 1:1 en el mismo orden, cabecera de entradas = las 28, ningún metadato entre las 28, campos obligatorios llenos; conteos por partición, bloque, perfil, cobertura, conciliación y regla de exclusión |

Las fronteras de bloque salen del programa y del evento `inicio` de cada perfil
(`metadatos_v2.py fronteras`) y se pasan a la extracción y a la verificación, así que ninguna
historia cruza un bloque. Primera prueba con datos reales (T11, 155 ventanas): trazabilidad
correcta, 0 obligatorios vacíos, desfase de arranque entre perfiles 18 ms.

**Reglas de exclusión del entrenamiento** (una ventana excluida se conserva y se cuenta; no se borra):

| Regla | Motivo |
|---|---|
| E1 | marca de arranque o de frontera de bloque: el horizonte de estado de 230 s está incompleto |
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

**Actualización del 26-nov (cierre del Bloque 1):** cerrada. Δ`rx_dropped` es exactamente el número de tramas 802.3/SNAP etiquetadas (PVST+/CDP), que el kernel entrega a los sockets de paquetes y luego descarta por falta de manejador (`BLOQUE1-CIERRE.md` §5.1). Los indicadores de pérdida son tcpdump `dropped by kernel`, vmxnet3, el sondeo del destino del SPAN y, sobre todo, el comprobador de copias de cada cierre, porque el espejo puede perder copias sin que el contador del switch suba (§5.2).

**Sondeo del destino del SPAN.** `lanzar_v2.sh` arranca `sondeo_span.py` (cada 2 s, con reconexión) antes del archivador. `cerrar_v2.sh` lo detiene y lo clasifica (`calidad-espejo-sondeo.json`), y `estado_global` añade el estado `espejo`: sin sondeo o con huecos es `falta`, y con descartes es fallo.

**Norma de operación.** Durante una captura no se transfiere nada grande a través del cortafuegos (copias, `scp`, lecturas de registros de más de unos KB). 160 Mb/s no es un límite seguro.

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

Programa `programas/piloto-30min.json`: **1800 s (30 min de programa)**, siete jornadas abreviadas: J1 de 360 s y J2–J7 de 240 s, con catorce bloques (dos de 180 s y doce de 120 s). J1 contiene los dos minutos adicionales de referencia base; las ventanas abreviadas J2–J7 no cambiaron. El programa prueba niveles, cambios y resiembra; no sustituye la captura de 49 h ni valida sus duraciones. Los niveles y ventanas exactos están en el JSON y en `CONTRATO-GENERADOR-49H.md` §7. No se ha iniciado el piloto final.

### Comprobaciones del piloto y criterio de aceptación (versión 3, actualizada el 28-nov antes del piloto final)

Sustituye la tabla de fases de V1. Su actualización precede al piloto final V3, aún no iniciado. Se lanzará con
`CF_TIPO_EJECUCION=piloto_final bash lanzar_v2.sh piloto-30min.json PILOTO 2` y se cerrará con `bash cerrar_v2.sh <ID>`.
Un criterio que falle no se corrige repitiendo el piloto hasta que pase: se documenta la causa,
se corrige y se registra el intento fallido. Ningún criterio mira resultados del detector.

| # | Comprobación | Criterio de aceptación | Fuente |
|---|---|---|---|
| C1 | Los seis perfiles terminan solos | Seis `perfil_terminado` con código 0; `manifiesto-fin` estado `completa` | `supervisor.jsonl`, `manifiesto-fin.json` |
| C2 | Niveles y pausas | Cada transacción se asigna al nivel y factor vigentes en su `inicio_t_s`; las pausas se cortan en bordes y P6 no inicia en OFF; los eventos `nivel` y `on/off` concuerdan con el programa | `transacciones-*`, `eventos-*`, `programa.json` |
| C3 | Patrones abreviados J1–J7 | Se observan las siete jornadas, las ventanas de énfasis J2/J3, dos ráfagas J4, dos periodos J6 y dos ráfagas J7 exactamente donde el programa abreviado las define; las acciones en curso pueden cruzar bordes y conservan el nivel de inicio | `transacciones-*` frente a `programa.json` |
| C4 | Resiembra | Catorce eventos `bloque` por perfil, con las tres semillas del bloque correspondiente | `eventos-*`, `programa.json` |
| C5 | Clasificación del cliente | 0 `fallo_inesperado` | `transacciones-*` |
| C6 | Conciliación con el registro independiente | 0 `fallo_imprevisto` y 0 `incompleta_no_verificable` entre cliente y srv-dmz/DC1 | `conciliacion/` |
| C7 | Cobertura de la captura | Fases: conexión, petición y respuesta vistas en el 100 % de lo que aplica; bytes de respuesta vistos / bytes TCP recibidos ≥ 95 % **en el total, en cada acción comparable y en cada perfil**; 0 `no verificable` | `cobertura/` |
| C8 | Archivado | Manifiesto del archivador `completa`: 0 huecos PCAP, 0 huecos EVE, 0 líneas corruptas | `capturas/<ID>/manifiesto.json` |
| C9 | Pérdidas en toda la cadena | Δ output drops de Gi2/0/19 y de los orígenes, Δ`rx_missed_errors`/softnet y descartes de tcpdump registrados antes y después: se acepta Δ = 0; si no, se cuantifica y C7 decide, porque C7 mide en el PCAP del anillo si esas pérdidas tocaron al tráfico experimental. **Suricata** (`capture.kernel_drops`, eventos `stats` de la EVE dedicada), por intervalos entre muestras consecutivas. Un aumento en un intervalo **dentro** del periodo del archivador es pérdida demostrada y **fallo**, aunque además falte evidencia (huecos, `uptime`); un reinicio también es fallo. Un aumento solo en intervalos que **cruzan** un borde no se atribuye al periodo ni se descarta: falta evidencia. Se aprueba solo un periodo acotado (muestra en o antes del inicio y en o después del fin), con huecos ≤ 16 s, `uptime` en todas las muestras y continuo, y Δ 0. C7 no decide Suricata (revisiones 6 y 7) | `contadores-lab-*.txt`, `capturas/<ID>/eve`, `registros/suricata-stats-ventana-<ID>.jsonl` |
| C10 | Relojes | NTP sincronizado en los cuatro equipos al principio y al final; \|desfase aparente\| mediano ≤ 5 ms | `relojes-*`, `cobertura/` |
| C11 | Extracción | `extraer_v2` y `verificar_v2` con rc 0; verificación 40/40 sin diferencias (historia del motor 230 s); inventario con todas las IP y su regla; constantes justificadas; tardías descartadas = 0. Pendiente de otra comprobación mientras el motor de referencia no use la misma deduplicación (`verificacion.json` → `deduplicacion.motor_misma_funcion`) | `extraccion/` |
| C11b | Trazabilidad de ventanas | `trazabilidad_ok`: cada ventana con ejecución, entidad, perfil, cierre, bloque, partición, jornada, nivel, PCAP/EVE, cobertura, conciliación y exclusión; relación 1:1 con `entradas_if.csv`, que tiene exactamente las 28 columnas | `extraccion/trazabilidad.json` |
| C12 | Volumen | GB/h de PCAP comprimido, EVE y registros por nivel medidos; se recalcula el presupuesto de 49 h con estos valores y el destino disponible | `volumen.jsonl` |
| C13 | Aislamiento de V1 | Regla `*@` que cubre la ejecución; sets de srv-dmz vacíos, DC1 sin reglas y agente sin `--aplicar` al principio y al final | `preflight-lab.jsonl`, `contadores-lab-*.txt` |

Lo que el piloto no puede mostrar se prueba aparte: rotación y sustitución del EVE, PCAP borrado
antes de copiarse y línea partida o corrupta (`captura/prueba_rotacion_lab.py`); parada por
espacio y por caída del archivador (prueba de parada coordinada); cruce de las 00:00 UTC (la
rotación real puede ocurrir durante las 49 h y se clasifica con `eve/huecos.jsonl`).

## Tiempos, fin dinámico y condiciones de parada/invalidación

El margen previo de 150 s empieza en la confirmación `estado=ok` del archivador,
no al emitir el comando remoto. `RETRASO_PRUEBA_S` puede posponer el inicio para
la prueba de arranque tardío y queda en `lanzamiento.json`. El bloque
`planificado` contiene el inicio y fin estimados, captura y tope; `real` se
completa al cierre con las marcas de paquetes y del supervisor. Nunca se infiere
una marca real a partir de una planificación.

El archivador arranca con `hasta_epoch=0`, relee `HASTA_EPOCH` en cada pasada y
solo acepta aumentos. Cuando termina el generador, el vigía escribe atómicamente
`fin_generador_real + margen_fin_s`. El archivador sigue hasta cubrir esa marca
y copiar el PCAP final (con 15 s de gracia para la siguiente rotación). El tope
inicial conservador se ajusta en `HASTA_MAX_EPOCH` al confirmar el archivador,
usando el fin previsto desde esa confirmación más el margen y una hora de
holgura. El tope de seguridad cierra `incompleta` con motivo
`tope_sin_fin_generador` si nunca llega un fin válido. La exclusión de V1 se
instala al arranque hasta el tope con 600 s adicionales y se comprueba o amplía
al cierre con el mínimo y máximo de las marcas reales, también con 600 s.

El vigía supervisa cada 300 s. La primera muestra fija la línea base de
contadores; una subida invalida el intervalo entre muestras. Cada registro de
`invalidaciones.jsonl` incluye `desde_epoch`, `hasta_epoch` y categoría.
`supervision.jsonl` conserva mediciones y errores de lectura.

| Tipo | Condición | Acción y clasificación |
|---|---|---|
| PARADA | Archivador distinto de `ok`; latido mayor que 60 s; estado inaccesible tres veces seguidas | Parar generador |
| PARADA | Gi2/0/19 con protocolo caído o distinto de 1000Mb/s Full | Parar generador |
| PARADA | Libre en Sensor1 menor que 4 GB | Parar generador |
| INVALIDACIÓN | Aumentan `output drops` de Gi2/0/19 | `perdida_antes_sensor`; continuar |
| INVALIDACIÓN | Aumentan `capture.kernel_drops` en la EVE dedicada, Suricata se reinicia o su `uptime` no avanza como el reloj (`reinicio_suricata`), o aumentan los huecos EVE/PCAP del archivador. Una lectura de stats ausente, fallida, obsoleta (más de 20 s) o sin `uptime` no es «0»; sin `uptime`, un aumento sí invalida: deja la supervisión `sin_datos` | `perdida_en_sensor`; continuar. Toda invalidación da `supervision: con_invalidaciones` y el dictamen `no_aprobada`. Lo que ocurra tras la última supervisión periódica lo detecta C9, que cubre hasta la muestra posterior al fin |
| INVALIDACIÓN | Desfase de Sensor1 o Clientes frente al bastión mayor que 1 s | `desfase_reloj`; continuar |

`resultado-global.json` separa generador, archivador, vigía, supervisión,
análisis y exclusión V1. Solo se aprueba con todas las evidencias y C1–C13
(incluido C11b) evaluados en verdadero. Una prueba incompleta, parada,
invalidación o criterio falso produce `no_aprobada`; evidencia ausente o
criterio sin evaluar produce `indeterminada`.
