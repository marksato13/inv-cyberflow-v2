# Bloque 1: respuesta a la revisión del 26-nov-2026

> **Corregido por `BLOQUE1-REVISION-2-2026-11-26.md`.** En particular: el §2 explicaba la sonda
> solo por id y prefijo (ahora hace falta la sonda registrada con clave e instante); las «23
> ventanas por sonda» se cuentan ahora como ventanas distintas y dejan T1–E3 en `no_aprobada`; la
> fracción máxima de exclusión del §3 desaparece (criterio conservador); el PCAP de DC1 del §1 no
> estaba en el repositorio (`.gitignore`); el §6 (rx_dropped) y el §8 (ESXi) están hechos; el
> código de esta revisión ya está desplegado (§8 de la segunda).

La revisión reprodujo los conteos de copias y el contraste HTTP/HTTPS. Esos resultados **se
conservan tal cual** y no se repitieron. Este documento responde a los siete puntos pendientes.

**No se han iniciado** el piloto final ni las 49 h. No se ha modificado el SPAN, los búferes del
switch ni nada del ESXi. En el laboratorio solo se **leyó**: los PCAP y registros de las cinco
ejecuciones, en Sensor1. Todo lo nuevo se escribió en carpetas aparte (`~/cyberflow-v2/bloque1/`),
sin tocar ningún original ni ningún `resultado-global.json`. **El código nuevo no se ha desplegado
en el laboratorio**: está en `main` y se desplegará antes de la siguiente captura.

## Estado del Bloque 1

**El Bloque 1 no está cerrado.** Este es su estado:

| Parte | Estado |
|---|---|
| Herramientas de calidad (copias, extremo, DNS, sondeo) y su integración en el dictamen | **Hechas y probadas** |
| DNS con las tres fuentes en E3 | **Hecho y reproducible desde lo publicado** (§1) |
| Eventos DNS sin transacción | **Explicados** con evidencia; tratamiento temporal definido (§2) |
| Política de calidad | **Integrada** en el dictamen. Le faltan **tres decisiones de Mark**: la fracción máxima de exclusión, la captura en srv-dmz durante las 49 h y el tratamiento definitivo de la sonda (§3) |
| Lugar de la pérdida silenciosa de gestión (switch o ESXi) | **Abierto**: necesita los accesos del §8 |
| Deduplicación, relojes, rotación y supervisión prolongada | **Pendientes de los bloques 3 y 4** (§7). No forman parte de este cierre |

## 1. DNS: E3 contrastado con el PCAP de DC1

**Qué estaba mal.** El resultado publicado de E3 (`reanalisis/dns-V2-E3-….json`) tenía
`pcap_dc1: false`. `operacion/reanalisis_bloque1.sh` llamaba a `contraste_dns.py` **sin**
`--pcap`. El cierre de E3 en el laboratorio sí lo había usado (`pcap_dc1: true`, en Sensor1), pero
ese fichero no se publicó. El CIERRE §4 afirmaba la tercera fuente apoyándose en un resultado que
no la contenía.

**Corregido:**

- `reanalisis_bloque1.sh` pasa `--pcap` siempre que exista `registros/dns-<ID>.pcap`.
- El dictamen trata como indeterminado un contraste que no usa un PCAP que el registrador declaró
  (`falta_pcap_dc1`, POLITICA §4).

**Evidencia publicada** en `evidencias/bloque1/dns-entradas/`:

| Fichero | Contenido |
|---|---|
| `dns-e3-pcap/dns-dc1-V2-E3-20261125T230032Z.saneado.pcap` | PCAP de DC1 de E3: 366 tramas |
| `dns-e3-pcap/saneado-V2-E3-….json` | Informe del saneado, con el sha256 de la entrada y de la salida, los descartes por motivo y la lista id/nombre de cada trama |
| `dns-e3-pcap/dns-V2-E3-…-pcap-saneado.json` / `.csv` | Contraste de E3 con el PCAP de DC1 |
| `V2-*/generador/V2-*/transacciones-P*.jsonl`, `V2-*/registros/dns-V2-*.jsonl` | Entradas del contraste de las cinco ejecuciones: transacciones del generador y registro de DC1 |
| `reproduccion/` | La reproducción desde lo publicado (abajo) |

**El saneado** se hizo con `captura/sanear_pcap_dns.py`. Conserva solo IPv4/UDP/53 entre la
población y 10.10.10.20.

- El PCAP de DC1 **ya solo contenía** tramas de la población, porque el registrador filtra: 366 de
  366 conservadas, 0 descartadas, y el mismo sha256 en la entrada y la salida (`c95b92ef…`).
- Una búsqueda de direcciones en todo `dns-entradas/` solo encuentra la población, DC1
  (10.10.10.20) y srv-dmz (10.10.30.10).

**El contraste ejecutado.** En Sensor1 (m4rk), con el código desplegado 1cb6cbf:

    python3 captura/contraste_dns.py --transacciones generador/$ID/transacciones-*.jsonl \
      --dc1 registros/dns-$ID.jsonl --capturas ~/cyberflow-v2/capturas/$ID \
      --pcap <original | saneado> --salida dns-$ID-pcap-<original|saneado>.json

El resultado es 182/182 transacciones comprobadas y 0 discrepancias, con `pcap_dc1: true`. El
original y el saneado dan **el mismo JSON byte a byte** (sha256 `dffa7920…`). Hay 8 eventos sin
transacción: los 6 del §2 más las 2 tramas de la misma sonda en el PCAP de DC1.

**Reproducido desde lo publicado** (portátil, sin laboratorio). Se usa el paquete del release
`bloque1-cierre-2026-11-26` (sha256 `cc21f054…`) más `dns-entradas/`:

    python operacion/reproducir_dns.py --paquete <paquete/> --salida evidencias/bloque1/dns-entradas/reproduccion

| Ejecución | PCAP DC1 | Transacciones | Sin transacción | Igual al laboratorio |
|---|---|---|---|---|
| T1 | no (no existía) | 32/32 | 10 | sí |
| T2 | no (no existía) | 182/182 | 6 | sí |
| E1 | no (no existía) | 32/32 | 6 | sí |
| E2 | no (no existía) | 182/182 | 6 | sí |
| E3 | no | 182/182 | 6 | sí |
| E3 | **sí** | 182/182 | 8 | sí |

«Igual» significa que el JSON coincide en todo salvo `parametros` (rutas) y los dos campos nuevos
de esta revisión.

**Encontrado al reproducir.** Sobre el extracto, el contraste daba unas 100 000 «tramas
ilegibles» que no estaban en el laboratorio. Eran las tramas de gestión que el extracto recorta a
96 B. Se corrigió como dice POLITICA §4, con 4 pruebas en `tests/test_contraste_dns_recortadas.py`.
Ahora en el extracto da 0 ilegibles y entre 98 564 y 132 025 recortadas no DNS por ejecución, y en
el laboratorio el resultado no cambia.

## 2. Eventos DNS sin transacción: origen, pertenencia y tratamiento

**Origen, demostrado con evidencia.** Son la **sonda DNS del preflight de `operacion/v2ctl.py`**,
que `v2ctl.py iniciar` ejecuta justo antes de arrancar el generador (línea 213). El cliente de la
sonda se crea con `random.Random(1)` como generador de identificadores, así que su consulta lleva
**siempre el id 17611**. Sale del origen del primer perfil (10.10.20.21) y pregunta por
`portal.cf-v2.lab`. No escribe transacción.

| Ejecución | Clave (cliente, puerto, id) | Instante (Sensor1) | Tramas | Relación con el generador |
|---|---|---|---|---|
| T1 | 10.10.20.21:38742 / 17611 | 06:25:16,819 | Sensor1 4 (DC1 0: su registrador arrancó a las 06:25:48) | **Sin ejecución asociada**; ver abajo |
| T1 | 10.10.20.21:59565 / 17611 | 06:29:51,082 | DC1 2 + Sensor1 4 | `iniciar` de T1; generador a las 06:29:51,147 |
| T2 | 10.10.20.21:44578 / 17611 | 07:07:49,59 | DC1 2 + Sensor1 4 | `iniciar` de T2 |
| E1 | 10.10.20.21:48716 / 17611 | 18:56:16,64 | DC1 2 + Sensor1 4 | `iniciar`; generador a las 18:56:16,786 |
| E2 | 10.10.20.21:44833 / 17611 | 19:48:56,95 | DC1 2 + Sensor1 4 | `iniciar` de E2 |
| E3 | 10.10.20.21:53580 / 17611 | 23:03:33,021 | DC1 2 + PCAP DC1 2 + Sensor1 4 | `iniciar`; generador a las 23:03:33,042 |

**Cómo se comprobó:**

- El id se deriva del código: `random.Random(1).randint(0, 65535)` = 17611.
- El nombre y el origen se leyeron en las tramas del PCAP de DC1 y del extracto publicado.
- El `preflight_lab.sh` del lanzador **no** consulta DNS. Por eso en E1–E3 no hay una segunda
  sonda al lanzar, aunque la captura ya estuviera en marcha.

**La sonda de T1 a las 06:25:16 tiene un origen sin documentar.** Tiene la firma exacta (id, nombre
y origen) y es anterior al identificador de T1 (06:25:28). Ni el bastión ni Clientes registran
ninguna ejecución para ella. Lo compatible con la evidencia es una invocación de
`v2ctl.py preflight` o un `iniciar` fallido antes de T1. **No consta quién la lanzó.**

**Pertenencia.** Es **tráfico operativo** de la herramienta de lanzamiento, no del programa:

- no es una transacción del generador;
- no la provoca ningún perfil;
- no tiene etiqueta de nivel ni de bloque.

Aun así, sale de una IP de la población y cae dentro del periodo de ventanas.

**Tratamiento temporal:**

1. `contraste_dns.py` la clasifica como **explicada** (`sin_transaccion_clasificacion`), con una
   regla probada contra el propio `v2ctl.py` (`tests/test_contraste_dns_sonda.py`, 4 pruebas).
   Así deja de provocar el código de salida 1. Cualquier otro evento sin transacción sigue
   provocándolo, y el dictamen lo trata como indeterminación.
2. Las ventanas de 10.10.20.21 cuya historia de 230 s contiene la sonda deben excluirse. Lo calcula
   `operacion/ventanas_sonda.py`, con la regla del CIERRE §7.3. Son **23 ventanas por sonda en las
   cinco ejecuciones**. En T1 las dos sondas dan 23 cada una.
   - Resultados: `evidencias/bloque1/sonda-preflight/ventanas-sonda-*.json`.
   - Hoy se calculan pero **no se aplican solas**: falta que `cerrar_v2.sh` escriba esa exclusión
     en `invalidaciones.jsonl` (Bloque 3).
3. **Definitivo, pendiente (Bloque 3 o decisión de Mark):** que `v2ctl.py` registre la sonda
   (instante, puerto, id) y que el extractor la quite paquete a paquete en lugar de perder 23
   ventanas.

## 3. Política de calidad

Está en **`docs/BLOQUE1-POLITICA-CALIDAD.md`**:

- criterios de cobertura (§3 y §4);
- exclusión (§6);
- parada (§7);
- la distinción entre fallo, indeterminación y evento explicado (§2).

**No se ha elegido ningún umbral.** La tolerancia a la pérdida comprobada en la población es cero.
La fracción máxima de exclusión la fija Mark **antes** de las 49 h, y mientras no la fije, una
pérdida comprobada deja la ejecución en `no_aprobada`.

## 4. La política en el dictamen

`operacion/estado_global.py` tiene dos estados nuevos, `calidad_copias` y `calidad_dns`, que entran
en `fallos` y en `faltantes`. El comentario de `cerrar_v2.sh`, que decía que no entraban, se ha
corregido.

**Pruebas** (`tests/test_estado_global_calidad.py`, 16 propias):

| Caso | Estado esperado y comprobado |
|---|---|
| Pérdida de copia en la población (`falta_copia`, `vlan_incorrecta`) | `no_aprobada`, motivo `calidad_copias:perdida` |
| Captura dañada (entrada incompleta) | `no_aprobada` (`entrada_danada`) |
| Discrepancia DNS | `no_aprobada`, motivo `calidad_dns:discrepancia` |
| Contraste DNS con error de entrada | `no_aprobada` |
| Pérdida y, a la vez, falta de DNS | `no_aprobada`: la falta no tapa el fallo |
| Sin comprobador de copias / sin contraste DNS | `indeterminada`, motivos `falta:calidad_copias` / `falta:calidad_dns` |
| Copias ambiguas, clase desconocida o 0 eventos | `indeterminada` |
| PCAP de DC1 declarado y no usado (el caso de E3) | `indeterminada` (`falta_pcap_dc1`) |
| Registrador sin PCAP | no exige PCAP |
| Evento sin transacción no explicado / transacción no comprobada / 0 transacciones | `indeterminada` |
| Resultado DNS antiguo, sin clasificación, con eventos sueltos | `indeterminada` |
| Solo sondas explicadas | `aprobada` |

**Las cinco ejecuciones con la política nueva.** `operacion/redictaminar_bloque1.py`, en Sensor1,
sin escribir en las ejecuciones; resultado en `evidencias/bloque1/redictamen/redictamen.json`:

| Ejecución | Antes | Ahora | `calidad_copias` | `calidad_dns` | Motivos (sin C1–C13 manuales) |
|---|---|---|---|---|---|
| T1 | no_aprobada | no_aprobada | completo | completo | supervision:con_invalidaciones, falta:espejo |
| T2 | no_aprobada | no_aprobada | completo | completo | supervision:con_invalidaciones, falta:espejo |
| E1 | indeterminada | indeterminada | completo | completo | falta:espejo |
| E2 | indeterminada | indeterminada | completo | completo | falta:paso:verificar, falta:espejo, falta:analisis |
| E3 | indeterminada | indeterminada | completo | completo | falta:espejo (34 s iniciales sin sondeo, CIERRE §6) |

**Suite completa:** `python -m pytest -q tests`, con la entrada estándar cerrada, da **200 pasan**
y 29 subpruebas. Antes eran 156.

## 5. Alcance corregido del informe

**Correcciones en `BLOQUE1-CIERRE.md`**, con una nota al principio que remite aquí:

- **B1 no tiene eventos experimentales**, porque no tenía generador. El «0 faltantes» de B1 en la
  tabla del §3 y el «0 faltantes en las 6» del §13 eran vacíos, no resultados. Ahora dice «sin
  eventos (no aplica)», y la cifra experimental se da sobre **las cinco ejecuciones con
  generador**.
- Se distingue entre resultados reproducidos, resultados basados en fuentes privadas y pendientes
  (tabla abajo).
- La conclusión «cerrado en lo técnico» se sustituye por el estado del principio de este
  documento.

| Resultado | Clase | Cómo se revisa |
|---|---|---|
| Copias de la población (T1, T2, E1–E3) y de gestión de B1 (par bastión↔Sensor1) | **Reproducido** | Paquete del release + `copias_espejo.py` (CIERRE §10) |
| Contraste con el extremo (E1–E3) | **Reproducido** | Paquete del release + `comparar_extremo.py` |
| DNS de las cinco ejecuciones, E3 con PCAP de DC1 | **Reproducido** | `operacion/reproducir_dns.py` (§1) |
| Dictamen con la política nueva | Reproducible en parte | `redictamen.json`. Las entradas de supervisión y sondeo de E3 están publicadas; las de T1–E2 no |
| Desglose de 10 ms de todas las VLAN, composición de las ráfagas, `clases_tramas` retrospectiva | **Fuente privada** | Solo el JSON con su sha256: el PCAP completo tiene tráfico ajeno |
| Copias de gestión de B1 con todos los destinos | **Fuente privada** | `copias-V2-B1-…-gestion.json` en Sensor1, sha256 en `SHA256SUMS-privados.txt` |
| `rx_dropped` = SNAP/PVST+ (prueba de 120 s) | Fuente **perdida** a nivel de trama | §6 |
| Lugar de la pérdida silenciosa de gestión | **Pendiente** | §8 |

## 6. Evidencia que faltaba

| Qué | Estado |
|---|---|
| Entradas para reproducir DNS | **Publicadas**: `evidencias/bloque1/dns-entradas/` (§1) |
| Resultado de la prueba de `rx_dropped` | **Publicado**: `evidencias/bloque1/rx-dropped-r1.json`. Incluye los contadores, el reparto por clase, la serie por muestra y `/proc/net/ptype`. Se comprobó que no contiene direcciones IP ni MAC |
| Extracto saneado de las tramas de esa prueba | **No se puede entregar.** Faltan los PCAP del anillo de Sensor1 (`/var/lib/ppi-motor-capture/live-20261125222713.pcap` en adelante, unos 24 ficheros de 5 s, 25-nov 22:27–22:29 UTC). El anillo los rotó y no se archivaron |

**Qué conclusión no puede revisarse sin esos PCAP.** La igualdad a nivel de trama: que las 1 708
tramas SNAP sean exactamente 1 704 PVST+ (01000ccccccd, pid 010b) y 4 CDP. Lo que sí se puede
revisar es la igualdad de conteos, Δ`rx_dropped` = 1 708 = tramas 802.3/SNAP etiquetadas. También
la serie por muestra y que `ptype` no tenga manejador para esas tramas.

Para repetirla con evidencia publicable hay que correr de nuevo la prueba de 120 s **archivando**
el intervalo. Las tramas PVST+ y CDP llevan datos de la infraestructura (MAC de puente y, en CDP,
nombre, versión y direcciones del switch), así que se publicarían solo PVST+ con las MAC
seudonimizadas, y de CDP solo el conteo. **No se ha hecho, porque no se pidió una ejecución
nueva.**

## 7. Pendientes de los bloques 3 y 4 (no se declaran cerrados)

| Pendiente | Bloque | Estado |
|---|---|---|
| Deduplicación del extractor (los RST idénticos se funden; no empareja copias a más de 5 ms) | 3 | Abierto |
| Retirar la sonda paquete a paquete y aplicar su exclusión en el cierre | 3 | Abierto (§2) |
| Relojes: DC1 va unos 6,5–7 ms por detrás; falta medir el desfase entre equipos directamente | 4 | Abierto |
| Rotación del EVE a las 00:00 UTC en una captura real | 4 | Abierto (PENDIENTES 15) |
| Supervisión prolongada: el sondeo de 2 s durante horas y la caída del supervisor | 4 | Abierto |

## 8. Accesos necesarios para seguir con el ESXi

El objetivo es localizar la pérdida silenciosa de copias de gestión: en B1-R4 faltaron 111 copias
sin que subiera ningún contador. Las hipótesis son el SPAN entre miembros del stack o `vmnic2` /
vSwitch2. **Ninguno de estos accesos modifica nada**; todo es lectura.

| Equipo | Acceso | Para qué |
|---|---|---|
| ESXi `esxi-hv-siem` | SSH al host (servicio TSM-SSH activo) con una cuenta que pueda ejecutar `esxcli`. En ESXi eso suele ser rol de administrador; Mark decide si lo ejecuta él | `esxcli network nic stats get -n vmnic2` antes y después de una transferencia (descartes y errores de recepción de la NIC física) |
| ESXi | La misma sesión | `esxcli network vswitch standard list -v vSwitch2` y `esxcli network vswitch standard portgroup list` (configuración, solo lectura) |
| ESXi | La misma sesión, con `esxtop` en modo lote (`esxtop -b -n 30 -d 2`) | `%DRPRX` del puerto de la VM Sensor1 en `vSwitch2`: el descarte entre la NIC y la VM, que ningún contador del invitado ve |
| ESXi | La misma sesión, con `vsish` en lectura (`/net/portsets/vSwitch2/ports/<id>/clientStats`) | Descartes por puerto del vSwitch, si `esxtop` no basta |
| Switch `CORE-STACK` | La cuenta de solo lectura ya usada por el sondeo | `show platform hardware fed switch 2 qos queue stats interface Gi2/0/19` y `show interfaces Gi2/0/19 counters errors`, durante la misma transferencia. Para la hipótesis del stack: `show switch stack-ports summary` y los contadores de los puertos de stack |

**La prueba sería la misma de B1-R4.** Se hace con `scp -l 160000` fuera de cualquier captura
experimental, con los contadores del ESXi y del switch leídos antes y después.

- Esa transferencia pasa por el cortafuegos, así que **no puede coincidir con una captura**.
- Necesita la orden de Mark, porque es una ejecución nueva.
