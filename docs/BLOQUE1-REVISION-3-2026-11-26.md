# Bloque 1 — 3.ª revisión (26-nov-2026)

> **Corrección (5.ª revisión, 26-nov):** lo que aquí se dice de que Suricata `kernel_drops` «no es medible» es falso. `stats.log` omite los contadores que valen 0, y la EVE dedicada `v2/eve.json` lo da: 0 en VD2–VD6. Ver `BLOQUE1-REVISION-5-2026-11-26.md` §2.

Esto **no es el piloto final ni las 49 h**: ninguna de las dos se ha iniciado. No se ha tocado el
SPAN ni los búferes compartidos. En el switch y en el ESXi solo se leyó.

Código desplegado al terminar: **7c1ecf8**. Sucesivamente se desplegaron 5d4d51f, 45344c5, 3e0c73e,
539c48e, 9196712 y 7c1ecf8. En cada despliegue el hash se verificó: 0 diferencias en el bastión,
Sensor1 y Clientes, y `registro_dns_v2.py` de DC1 coincide (`f4d17e4d…`). VD6 corrió con 9196712;
7c1ecf8 solo cambia el extractor de evidencias.

| Punto | Estado |
|---|---|
| 1. C7 y C9–C13 | Corregido: estaban **pendientes de revisión**, no «sin valor por ser corta». `revisar_criterios.py` los evalúa con evidencia; lo de duración prolongada queda aparte (§1) |
| 2. Cobertura de P2 en conexiones persistentes | Corregida (`cobertura_v2` v2), 12 pruebas; VD2/VD3 reanalizadas sin borrar nada (§2) |
| 3. Coordinación de copias | `transferir.py` (candado + registro) en `lanzar`/`cerrar`; VD3 sigue `no_aprobada` (§3) |
| 4. Vigilancia de las referencias | `vigilar_referencias.py` en `lanzar`/`cerrar`; parada coordinada o `referencia_incompleta` (§4) |
| 5. Extractos y entradas mínimas | VD2/VD3/VD4/VD6 y P2 **reproducen en el portátil**; lo no compartible está identificado con su conclusión (§5) |
| 6. ESXi y switch | Conclusión acotada; causa interna pendiente; pares ajenos saneados (§6) |
| 7. Verificación dirigida sin transferencias | VD4 `indeterminada` (falso positivo de la vigilancia, corregido); VD5 sin captura (defecto de la guarda, del lado seguro); **VD6 `aprobada`** en lo aplicable, con las comprobaciones prolongadas aparte (§7) |
| 8. Matriz, pendientes, versiones | `PENDIENTES.md` 43, 51–59, `MATRIZ-OBSERVACIONES.md` R1.2 y R1.6 |

## 1. C7 y C9–C13: pendientes de revisión, no «sin valor»

La 2.ª revisión (§8) decía que estos criterios no tenían valor con 24 min de programa. **Era
falso.** `evaluar_piloto.py` los extrae con `ok: None, revisar: True`, es decir, deja la revisión
para una persona. `operacion/revisar_criterios.py` hace ahora esa revisión con las reglas de
PROTOCOLO §10 y la evidencia de la propia ejecución. Cada criterio separa cuatro cosas:

- `comprobaciones`: lo comprobable en esa ejecución, con su valor y su fuente;
- `falta_evidencia`: lo que debería estar registrado y no lo está (deja `ok = None`);
- `requiere_duracion_prolongada`: lo que solo una captura larga puede comprobar. **No cuenta** en
  una verificación corta y se conserva aparte (`pendientes_duracion_prolongada` del dictamen). En
  una ejecución de ≥ 24 h sigue siendo obligatorio (`falta:prolongada:Cx`);
- `pendiente_otra_comprobacion`: defectos conocidos que tienen su propio bloque.

| Criterio | Qué se comprueba en una ejecución corta | Qué requiere duración prolongada |
|---|---|---|
| C7 cobertura | conexión, petición y respuesta en el 100 % de lo que aplica; bytes ≥ 95 % en total, por acción y por perfil; 0 no verificables; cobertura v2 | cobertura a través de la rotación del EVE (00:00 UTC) |
| C9 pérdidas | Δ output drops de Gi2/0/19, Gi1/0/23 y Gi2/0/23; Δ `rx_missed`/errores/softnet; tcpdump del anillo y de srv-dmz; sondeo del destino. Δ ≠ 0 se cuantifica y **decide C7** (§10); segundos sin sondeo = falta | contadores durante 49 h |
| C10 relojes | NTP al inicio (preflight) y al final en los 4 equipos; mediana del desfase aparente ≤ 5 ms | deriva durante 49 h |
| C11 extracción | `extraer`/`verificar` rc 0; 40/40 filas sin diferencias; historia de 230 s sin futuro; paridad con el motor; constantes justificadas; 0 tardías EVE/PCAP; todas las IP del inventario con regla | orden del EVE a través de su rotación |
| C12 volumen | volumen por minuto y por fase (previa, generación, margen final); GB/h de esta ejecución | volumen real de 49 h frente a la proyección |
| C13 aislamiento V1 | al inicio y al final: exclusión `*@`, sets de srv-dmz vacíos, agente sin `--aplicar`, DC1 sin reglas | aislamiento mantenido durante 49 h |

Pendientes de otra comprobación que se informan sin cambiar el resultado:

- **C9:** Suricata no publica `kernel_drops` en `stats.log`.
- **C10:** DC1 va unos 6,5–7 ms por detrás (bloque 4).
- **C11:** deduplicación del extractor (bloque 3).

**Reanálisis de VD2 y VD3** (Sensor1 `~/cyberflow-v2/reanalisis/5d4d51f/<ID>/`). Es una copia
de la carpeta de la ejecución; los resultados anteriores se movieron a `anterior/`. Los originales
de `~/cyberflow-v2/pruebas/<ID>/` no se tocaron. Publicado en
`evidencias/bloque1/reanalisis-5d4d51f/`.

| | C7 | C9 | C10 | C11 | C12 | C13 | Dictamen anterior | Dictamen reanalizado |
|---|---|---|---|---|---|---|---|---|
| VD2 | ✔ | sin decidir: 30,5 s sin sondeo | sin decidir: no se registró el NTP final de Sensor1 | ✔ | ✔ | ✔ | `indeterminada` (8 faltas) | **`indeterminada`**: `falta:espejo`, `falta:criterio:C9`, `falta:criterio:C10` |
| VD3 | ✔ | ✔: Δ77 drops en Gi2/0/19 cuantificados; C7 ✔ | sin decidir: igual que VD2 | ✔ | ✔ | ✔ | `no_aprobada` | **`no_aprobada`**: `espejo:con_descartes` (**se conserva**), `falta:criterio:C10` |

C10 no se decide en VD2 ni VD3 porque el cierre solo leía el reloj final de srv-dmz y DC1. Desde
5d4d51f lee también los de Sensor1 y Clientes. El resto de C10 cumple: NTP al inicio en los 4
equipos, NTP al final en srv-dmz, DC1 y Clientes, y mediana del desfase aparente de 0,67 ms (VD2)
y 0,92 ms (VD3).

En VD3, C9 pasa por la regla del protocolo: los 77 descartes se cuantifican y la cobertura de la
población está completa. La **política de calidad del espejo** es más estricta y la decide aparte:
VD3 sigue **`no_aprobada`**. El criterio no se relajó.

## 2. Cobertura de P2 en conexiones persistentes (bloque 3, PENDIENTES 52)

**Causa del defecto anterior.** En una conexión reutilizada solo la primera transacción veía el
SYN. Las siguientes no tenían el número de secuencia inicial: los huecos quedaban sin calcular y
la transferencia salía `incompleta`. Además, los paquetes se asignaban a la transacción más
cercana en el tiempo. Por eso VD2 tenía 152 transacciones de P2 «incompletas» y 23 ventanas
excluidas por E3. Era un defecto de la herramienta, no una pérdida.

**Corrección** (`captura/cobertura_v2.py`, `version: 2`).

- Las transacciones persistentes del generador se agrupan por conexión. Una conexión se
  identifica por `persistente`, `conexion_n` y `peticion_en_conexion`, y tiene un solo SYN y un
  solo número de secuencia inicial por sentido.
- El flujo de cada sentido se reparte por **posición**. Se usan los contadores de bytes del socket
  del cliente (`bytes_tcp_enviados` y `bytes_tcp_recibidos`, medidos al empezar y al terminar cada
  transacción), en orden de petición. La última transacción queda abierta hasta el último byte
  visto.
- Cada segmento y su copia, retransmisión o hueco cuentan en la transacción a cuyo tramo
  pertenecen, no en la más cercana en el tiempo.
- El SYN solo cuenta en la primera transacción.
- Sin contadores de bytes no hay reparto: la transacción sale `sin_reparto`, es decir, «no
  comparable», y nunca «completa».
- En el EVE, los eventos `http` y `fileinfo` van a su transacción por `tx_id`. Los de flujo y TLS
  van a todas las de la conexión.

**Pruebas nuevas** (`tests/test_cobertura_persistente.py`, 12, de las que 10 fallan con la v1):

- varias transacciones con respuestas de distintos tamaños;
- una respuesta que llega después del inicio de la siguiente petición;
- un hueco solo en su propia transacción;
- falta el final de la última;
- copias del espejo y reordenación;
- una retransmisión contada en su transacción;
- sin SYN, la transferencia sale incompleta;
- sin contadores de bytes, sale no comparable;
- un puerto reutilizado por otra conexión;
- HTTPS con registros TLS y `close_notify`;
- eventos del EVE por `tx_id`;
- un cliente que lee en trozos.

**Límites del contraste en HTTPS.** Lo que se compara son bytes TCP de registros TLS. El tramo de
cada petición depende de los contadores del cliente, que cuentan bytes cifrados (cabeceras y
relleno TLS incluidos). Ni la captura ni el EVE ven el código HTTP ni el cuerpo: para una petición
HTTPS solo se afirma que los bytes del tramo esperado se vieron, no que el contenido fuera el
esperado. Esta nota va en `parametros.limites_https` de cada `cobertura.json`.

**VD2/VD3 reanalizadas:**

- 598 transacciones;
- 416 TCP, todas con conexión vista y completas;
- 151 reutilizadas;
- bytes vistos / esperados: 1,00003 en total y 1,00024 en P2;
- 0 no verificables;
- 182 DNS no comparables por bytes, que es lo que corresponde.

Antes la v1 daba en P2 1,0067 (VD2) y 1,0017 (VD3), sumando por proximidad. Las exclusiones E3 del
reanálisis están en §7.

## 3. Coordinación de las copias de evidencia

`operacion/transferir.py`, en el bastión:

- **Candado** `~/cyberflow-v2/CAPTURA_EN_CURSO`, creado de forma atómica (`O_EXCL`). Lo crea
  `lanzar_v2.sh` **antes de todo** (preflight, srv-dmz, sondeo, archivador). Antes de arrancar,
  espera 60 s tras el fin de la última copia registrada, porque el archivador recoge también el
  anillo de los 30–35 s anteriores. Lo quita `cerrar_v2.sh` cuando el archivador, srv-dmz y DC1
  ya están parados.
- **Copias** solo con `transferir.py copiar -- <scp>`, o `externa-inicio`/`externa-fin` para
  copias desde el portátil. Con candado o con un proceso de captura vivo en Sensor1 o en srv-dmz,
  la copia se **rechaza** y queda registrada. Un equipo que no responde no se da por libre.
- **Registro** `~/cyberflow-v2/transferencias.jsonl` (inicio, fin, rc y rechazos). El cierre
  escribe `transferencias.json` con las copias que tocan el intervalo de captura, desde el arranque
  del archivador menos 40 s hasta la parada de las referencias. Una copia sin fin cuenta como
  abierta.
- **Dictamen:** si `lanzamiento.json` declara la coordinación, `transferencias` es obligatoria.
  `copias_durante_captura` da `no_aprobada` y la falta del registro da `indeterminada`. Las
  ejecuciones anteriores no lo declaran y no cambian.

Pruebas en `tests/test_coordinacion_referencias.py`:

- rechazo con candado;
- rechazo con un proceso vivo;
- equipo sin respuesta;
- espera de la holgura;
- copia sin terminar;
- segundo candado;
- solapes;
- copias externas;
- orden en los guiones.

VD3 **se conserva como `no_aprobada`**: el descarte lo causó la copia del operador.

## 4. Vigilancia de las referencias (srv-dmz y DC1)

`operacion/vigilar_referencias.py vigilar` se ejecuta desde el bastión cada 20 s, desde que el
archivador está confirmado hasta el cierre. Comprueba:

- **proceso:** el tcpdump de srv-dmz y `cf-v2-dns-<id>` en DC1 siguen vivos;
- **progreso:** el PCAP de srv-dmz y el JSONL de DC1 crecen durante la generación (180 s sin
  crecer es un incidente);
- **espacio:** con menos de 1 GB libre **detiene** de forma ordenada la captura de esa referencia
  (SIGINT o `systemctl stop`) y lo declara como `espacio_bajo`;
- **supervisión:** 90 s sin poder leer un equipo es `sin_supervision`.

El cierre la para antes de parar las referencias, porque esa parada es la prevista, y `analizar`
escribe `calidad-referencias.json`, con `completo`, `incompleta` y sus motivos, o `sin_datos`. En
el dictamen, una referencia incompleta da `falta:referencias`, es decir, `indeterminada`, nunca
`aprobada`. Se comprobó en vivo antes de VD4 que las dos lecturas funcionan con `sudo -n`.

## 5. Extractos saneados y entradas mínimas

Están en `evidencias/bloque1/extractos-539c48e/`, con LEEME. Las herramientas son
`operacion/extracto_saneado.py` y `captura/sanear_pcap_tcp.py`, cada una con sus pruebas.

- **Entradas mínimas de VD2, VD3, VD4 y VD6.** Son todos los ficheros de texto que leen
  `evaluar_piloto`, `revisar_criterios`, `estado_global` y `dictamen_casos`, sin PCAP ni el EVE
  completo.
  - Las IP ajenas se sustituyen de forma consistente por direcciones de documentación y las MAC por
    `02:00:00:00:xx:yy`.
  - Un barrido final no encuentra ninguna IP ni MAC fuera de las reglas.
  - `operacion/reproducir_dictamen.py` las reproduce **en el portátil, fuera del laboratorio**: los
    cuatro dan el mismo dictamen, los mismos motivos, los mismos C7 y C9–C13 y los mismos 8 casos
    del dictamen que en el laboratorio.
- **Extracto de P2 (VD2).** Son 6 conexiones persistentes, 3 HTTP y 3 HTTPS, con 4 a 14
  transacciones cada una.
  - Incluye un PCAP saneado (VLAN conservada, MAC seudonimizadas), el EVE de esas 6 conexiones y sus
    45 transacciones.
  - `cobertura_v2.py` sobre el extracto, en el portátil, da **0 diferencias** con la cobertura del
    laboratorio: 45/45 completas, 39 sobre conexión reutilizada.
- **No compartible y conclusión que queda sin revisión independiente** (detalle en el LEEME):
  - el anillo del SPAN (PCAP): cobertura completa, copias de población y de gestión, extracción.
    Se publica el resultado, pero no se puede rehacer desde la captura, salvo el extracto de P2;
  - el EVE completo, que lleva metadatos de aplicación de terceros: el contraste del EVE en la
    cobertura;
  - los PCAP de srv-dmz y de DC1 de VD2–VD6: `calidad_extremo` y el contraste DNS de esas
    ejecuciones. El DNS de E3 sí está saneado (`dns-entradas/`);
  - la correspondencia de las IP y MAC ajenas, que no interviene en el dictamen.
- **El EVE se retiró después de generar los extractos.** La primera versión incluía el EVE completo
  con las IP sustituidas, y lo detecté antes de publicar: los nombres DNS, el SNI y las URL de
  terceros siguen ahí. Se quitó, `extracto_saneado.py` lo excluye desde 7c1ecf8 y la reproducción se
  repitió sin él.

## 6. ESXi y switch: conclusión acotada

Corregido en la 2.ª revisión, §9. Las lecturas del switch y del ESXi no son simultáneas, así que la
diferencia por tramo entre lo que sale de Gi2/0/19 y lo que recibe `vmnic2` va de −302 a +465
paquetes, también en los fondos. En toda la prueba la diferencia es de 174 paquetes de 157 523
(0,11 %).

- **ESXi:** no puede explicar las 17 593 copias que faltan, unas 38 veces la mayor diferencia de un
  tramo, y no cuenta ningún descarte. **No se descarta** una pérdida menor que la resolución
  (unos cientos de paquetes por tramo).
- **Switch:** las copias que faltan no salen por Gi2/0/19 ni se cuentan como descartes de la cola.
  Se pierden en el switch antes de la cola de salida del destino. El balance QoS es 25,3 + 17,3 ≈
  42,6 MB frente a unos 40 MB estimados.
- **Pendiente:** la causa interna (replicación del SPAN, microrráfagas u otra). Hace falta un
  contador del ASIC (PENDIENTES 50).
- **Saneado:** en `verificacion-VD3/gestion/resumen-descarte-gestion.json` los pares
  `bastion->10.10.60.10` y `bastion->10.10.60.45` (equipos ajenos de la VLAN 60) pasan a
  `equipo_ajeno_A/B`. SHA256SUMS se recalculó. En `gestion-esxi-r1/` no hay pares; la única IP es la
  de gestión del switch, en un mensaje de cierre de sesión.

## 7. VD4: verificación dirigida sin transferencias de gestión

Se usó el mismo programa corto de 24 min, con el candado y la vigilancia activos, sin ninguna copia
de evidencia durante la captura. Hubo tres intentos:

| | Código | Qué pasó | Dictamen |
|---|---|---|---|
| **VD4** (V2-VD4-20261126T141333Z) | 45344c5 | Captura completa. La vigilancia marcó `srvdmz:sin_progreso` a los 14 s de empezar la generación, porque el reloj contaba desde la fase de sondas, sin tráfico. El PCAP creció en todas las muestras siguientes. Además, C9 vio Δ72 output drops en Gi2/0/19, leídos **después** de la copia del PCAP de srv-dmz del cierre; el sondeo vio 0 durante toda la captura | Original **`indeterminada`** (`falta:referencias`), conservado. Reanalizado con la regla corregida (3e0c73e, `--recalcular-progreso`, carpeta aparte): `aprobada` en los requisitos de una verificación corta |
| **VD5** (V2-VD5-20261126T150955Z) | 539c48e | **No llegó a capturar.** El candado esperaba indefinidamente una copia «abierta». `externa-fin` registraba el inicio con 6 decimales y no casaba con el registro de inicio, así que la guarda falló del lado seguro. Lo paré, quité su candado y añadí al registro un cierre de reparación explícito | Sin ejecución |
| **VD6** (V2-VD6-20261126T151456Z) | 9196712 | Todo corregido. Ver abajo | **`aprobada`** directamente, sin reanálisis |

**VD6, requisitos aplicables a una verificación corta.** Evidencia en
`evidencias/bloque1/verificacion-VD6/` y `extractos-539c48e/entradas-V2-VD6-…`.

| Requisito | Resultado |
|---|---|
| Espejo (sondeo cada 2 s en toda la captura) | `sin_descartes`: 1 852,5 s sin descartes, 0 con descartes, 0 indeterminados |
| Copias de la población, extremo, DNS, sonda | `completo` en los cuatro |
| Referencias (vigilancia) | `completo`: 88 muestras por equipo, 68 durante la generación; procesos vivos en todas; espacio mínimo 10,2 GB (srv-dmz) y 35,3 GB (DC1) |
| Transferencias | `sin_copias`, 0 rechazadas. Registro con 6 copias, todas cerradas y todas fuera de las capturas |
| Exclusiones | 674 ventanas, 381 excluidas: todas por guardas planificadas (E1 369, E5 32); **0 por incidente**, sin E3 de P2 |
| C7 | 416/416 TCP con conexión y completas; petición y respuesta 598/598; bytes 1,00003 (P2: 1,00024); 0 no verificables |
| C9 | Δ = 0 en Gi2/0/19, Gi1/0/23, Gi2/0/23, `rx_missed`, errores, softnet, tcpdump del anillo y de srv-dmz. El contador de fin ya se lee antes de las copias del cierre |
| C10 | NTP sincronizado al inicio y al final en los 4 equipos; mediana del desfase aparente 1,95 ms |
| C11 | `extraer`/`verificar` rc 0; 40/40 filas sin diferencias; 0 tardías; inventario completo |
| C12 | 31 min de volumen por minuto. Por fase: previa 19,0 MB de PCAP + 0,7 MB de EVE, generación 124,3 + 5,5 MB, margen final 9,1 + 0,4 MB; 0,29 GB/h |
| C13 | Aislamiento V1 al inicio y al final (sets vacíos, agente sin `--aplicar`, DC1 sin reglas, exclusión `*@` que cubre la ejecución) |

**Comprobaciones de duración prolongada, conservadas aparte.** El dictamen las lista en
`pendientes_duracion_prolongada` y **no** las da por cumplidas:

- C7, cobertura a través de la rotación del EVE;
- C9, contadores durante 49 h;
- C10, deriva de los relojes;
- C11, orden del EVE tras la rotación;
- C12, volumen real de 49 h frente a la proyección (esta ejecución da 0,29 GB/h con el programa
  corto, que no es el de 49 h);
- C13, aislamiento mantenido.

`aprobada` aquí significa exactamente esto: «cumple todos los requisitos aplicables a una
verificación corta». **No** significa que el piloto final o las 49 h estén validados.

**Límite de la verificación.** Las lecturas de supervisión no son transferencias de evidencia y
pasan por la gestión: el sondeo del vigía desde el bastión y la vigilancia de las referencias cada
20 s. Son unos pocos KB y el espejo no vio ningún descarte en VD6.

## 8. Pendientes que siguen abiertos

- **Deduplicación del extractor** (bloque 3, PENDIENTES 37).
- **Relojes**: DC1 va unos 6,5–7 ms por detrás, y falta medir la deriva durante 49 h (bloque 4,
  PENDIENTES 38).
- **Rotación del EVE y supervisión prolongada** (bloque 4, PENDIENTES 44 y 59).
- **Causa interna de la pérdida de gestión en el switch** (PENDIENTES 50).
- **Suricata `kernel_drops`**, que no se puede medir.
- **Decisiones de Mark**: la política de calidad (fila 32) y el filtro VLAN o el softmax (fila 33).
- **Lo no compartible** (§5) sigue sin revisión independiente.
- El piloto final y las 49 h **siguen sin iniciar y sin autorización**.
