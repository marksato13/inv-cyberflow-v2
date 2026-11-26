# Bloque 1, revisión 4: publicación y reproducción (26-nov-2026)

Esta revisión es **preparación**. No se repitió ninguna captura. El piloto final y las 49 h **no se
han iniciado**. VD3 se conserva como fallida, y VD6 y los resultados anteriores no se tocan. El
laboratorio queda detenido.

## 1. Qué faltaba y por qué

La 3.ª revisión decía «entradas publicadas», pero `.gitignore` excluía `pruebas/`, `capturas/`,
`*.pcap` y `eve*.json`. De `extractos-539c48e/` solo subieron 15 ficheros de resumen; las entradas de
VD2–VD6 y los PCAP/EVE del extracto de P2 se quedaron en el portátil. La afirmación de la 3.ª
revisión (PENDIENTES 58, MATRIZ R1.6) era falsa y se corrige.

**Cómo se publica ahora** (sin habilitar en general la publicación de capturas):

- **En git, con excepciones concretas al final de `.gitignore`:**
  - `evidencias/bloque1/entradas-r4/*/pruebas/` y `*/capturas/`, solo texto, porque los `*.pcap`,
    `*.pcap.gz` y `eve*.json` siguen excluidos;
  - el extracto completo de P2: sus 6 PCAP saneados y `eve-extracto.json`.
- **En la release `bloque1-r4-2026-11-26`:** un `.tgz` por ejecución con el texto, el anillo, el EVE,
  srv-dmz y DC1 filtrados al tráfico experimental, más `SHA256SUMS-bloque1-r4.txt`. El mismo
  manifiesto está versionado en `evidencias/bloque1/entradas-r4/`, y `verificar_paquetes.py` compara
  contra ese.

## 2. Extractos

Los detalles están en `evidencias/bloque1/entradas-r4/LEEME.md`.

| | VD2 | VD3 | VD4 | VD6 |
|---|---|---|---|---|
| Anillo: tramas originales → conservadas | 869 778 → 31 722 | 891 512 → 31 534 | 889 146 → 32 838 | 891 791 → 32 540 |
| srv-dmz | 7 599 (todas) | 7 509 (todas) | 8 269 (todas) | 8 019 (todas) |
| DC1 | 366 (todas) | 366 | 366 | 366 |
| EVE: eventos originales → conservados | 7 941 → 3 017 | 8 119 → 3 016 | 8 570 → 3 023 | 8 624 → 3 026 |
| Paquete `.tgz` | 26,2 MB | 26,2 MB | 26,0 MB | 26,0 MB |

**Sin modificar:** tiempos, longitudes, VLAN, cabeceras y carga.

**Modificado o añadido:**

- **MAC:** seudónimo HMAC con clave privada, consistente entre los tres puntos de captura.
- **Nombres de fichero:** los del inventario, sin cambios.
- **Dato añadido: `inicio-captura.json`.** Es el instante del primer paquete IPv4 o evento EVE de la
  captura original; sin él, el arranque de la extracción no coincide, porque ese primer paquete es
  tráfico no experimental. En VD3 el primer paquete del anillo ni siquiera es IPv4: está 31 ms antes
  del primer IPv4, que es el que usa el extractor. Por eso no sirve el inventario y el instante se
  calcula en el laboratorio con las mismas funciones del extractor.
- **Corrección del saneado de texto:** se conservan las redes 10.10.X.0 y las puertas de enlace del
  laboratorio, que antes se sustituían.

**Nada ajeno en la publicación.** En las 161 494 tramas publicadas todas las IP de cabecera son del
experimento y todas las MAC son seudónimos. Los únicos nombres del EVE son `cf-v2.lab` y
`10.10.30.10`.

## 3. Dos comprobaciones distintas, y comandos

Desde un clon nuevo, con Python 3.12 o posterior y solo la biblioteca estándar:

```
git clone https://github.com/marksato13/inv-cyberflow-v2.git
cd inv-cyberflow-v2
# descargar los 5 ficheros de la release en ./descargas (gh o navegador)
gh release download bloque1-r4-2026-11-26 -D descargas
python -X utf8 operacion/verificar_paquetes.py descargas
python -X utf8 operacion/reproducir_dictamen.py
python -X utf8 operacion/recalcular_desde_capturas.py evidencias/bloque1/entradas-r4 --p2 evidencias/bloque1/extractos-539c48e/p2-V2-VD2-20261126T090705Z
```

Cada guion termina con «GLOBAL SATISFACTORIO» y rc 0. Una entrada ausente, un programa que falla o
una diferencia no justificada dan «NO SATISFACTORIO» y rc 1.

| Comprobación | Qué recalcula | Qué compara | Resultado |
|---|---|---|---|
| **A. Dictamen desde resultados intermedios** (`reproducir_dictamen.py`) | `revisar_criterios`, `estado_global`, `dictamen_casos` a partir del texto | global, dictamen, código, motivos, alcance, los 9 estados (espejo, calidad_*, referencias, transferencias, análisis, exclusión V1), C7 y C9–C13, pendientes y los **ocho casos** (caso, global, código, calidad, motivos) frente a `referencia/` | **Reproducido** en VD2, VD3, VD4 y VD6 |
| **B. Recálculo desde PCAP/EVE** (`recalcular_desde_capturas.py`) | `cobertura_v2`, `comparar_extremo`, `contraste_dns`, `copias_espejo`, `extraer_v2` + `verificar_v2` + `metadatos_v2` | Cada campo del JSON y cada fila de los CSV (cobertura, filas, entradas_if, ventanas_meta) frente al resultado del laboratorio | **Reproducido** en las cuatro: cobertura, extremo, DNS, copias y extracción |
| B, P2 (`--p2`) | `cobertura_v2` sobre las 6 conexiones persistentes | Todos los campos de las 45 transacciones | **Reproducido**: 45/45 y 0 diferencias |

Las diferencias que B acepta, todas por tráfico que el extracto quitó a propósito, están enumeradas
en `DEPENDEN_DEL_TRAFICO_AJENO` con su motivo:

- denominadores totales;
- bytes por VLAN;
- tasas y picos del anillo completo;
- `sensor/paquetes`;
- reordenaciones y paquetes descartados fuera de la población;
- `inventario_ips`.

También acepta las rutas de fichero que solo cambian de carpeta. Ninguno de esos campos interviene en
el dictamen. Lo que queda sin revisión independiente está en el LEEME.

**Registro de la comprobación desde una carpeta vacía:** `evidencias/bloque1/entradas-r4/REPRODUCCION-CLON-LIMPIO.txt`.

## 4. Defectos encontrados y corregidos en esta revisión

| Defecto | Efecto | Corrección | Comprobaciones repetidas |
|---|---|---|---|
| Entradas excluidas por `.gitignore` | No publicadas, aunque el informe decía lo contrario | Excepciones al final de `.gitignore` (en git manda la última regla) y release | Publicación y clon limpio |
| `reproducir_dictamen.py` imprimía los casos sin compararlos; una entrada ausente rompía el guion en vez de dar un resultado | Podía dar «coincide» con casos distintos | Comparación completa frente a `referencia/`; ausencias y fallos dan NO SATISFACTORIO | A (las cuatro ejecuciones) |
| `extracto_saneado.py` sustituía 10.10.X.0 y las puertas de enlace del laboratorio | `calidad_copias` no comparable (rutas y configuración del espejo) | Se conservan; prueba nueva | Entradas regeneradas; A y B |
| El extracto no fijaba el arranque de la extracción | 3 ventanas de VD6 con marca «arranque» y metadatos de antecedentes distintos (características idénticas) | `inicio-captura.json` y `extraer_v2.py --inicio-captura-epoch` (sin él, el laboratorio no cambia) | B (extracción) |

El primer intento de extracto escribía `.pcap` sin comprimir, con otro nombre. Cobertura y copias
daban «PCAP ausente»; ahora se conservan los nombres. No llegó a publicarse.

`tests/test_sondeo_span.py::test_normal_mide_intervalo_real` falló una vez en el portátil por tiempo,
con la máquina cargada, y pasó en 3 repeticiones. Es una prueba sensible al tiempo que no toca esta
revisión, y queda anotada.

## 5. Alcance de VD6

VD6 es una **verificación dirigida** de 24 min. Su `aprobada` significa que cumple todos los requisitos
de ese tipo de ejecución, y solo eso:

- no valida el piloto final ni las 49 h;
- las comprobaciones de duración prolongada (C7 rotación, C9 contadores 49 h, C10 deriva, C11 orden
  del EVE tras la rotación, C12 volumen real, C13 aislamiento sostenido) siguen pendientes en
  `pendientes_duracion_prolongada`;
- las de otros bloques también siguen pendientes en `pendientes_otra_comprobacion`: C9
  `kernel_drops` de Suricata, C10 reloj de DC1 y C11 deduplicación.

## 6. Requisitos por tipo de ejecución

`estado_global.REQUISITOS` decide lo que exige el dictamen **por el tipo declarado** en
`lanzamiento.json` (`tipo_ejecucion`), no solo por la duración. `lanzar_v2.sh` se niega a empezar,
antes del candado, si `CF_TIPO_EJECUCION` no es uno de los tres tipos.

| Tipo | Común (todas) | Comprobaciones de otros bloques (`otra:`) | Prolongadas (`prolongada:`) | Uso |
|---|---|---|---|---|
| `verificacion_dirigida` | Obligatorio | Informadas aparte, no exigidas | Informadas aparte, no exigidas | VD2–VD6 y futuras pruebas de preparación |
| `piloto_final` | Obligatorio | **Exigidas**: si falta alguna, `indeterminada` | Informadas aparte | Piloto final (no iniciado) |
| `captura_definitiva` | Obligatorio | **Exigidas** | **Exigidas**, sea cual sea la duración | 49 h (no iniciadas) |

**Común** quiere decir: generador, archivador, vigía, supervisión, exclusión V1, espejo, `calidad_*`,
referencias, transferencias, análisis y criterios C1–C13.

**Tipo desconocido:** `falta:tipo_ejecucion` y se exige todo.

**Sin tipo declarado** (todos los lanzamientos anteriores a r4): se infiere de la duración
(≥ 24 h = `captura_definitiva`) y el dictamen lo indica con `tipo_inferido_por_duracion: true`. Por
eso VD2–VD6 dan exactamente el mismo dictamen que antes.

**Consecuencia hoy:** un piloto final daría `indeterminada` mientras sigan abiertas la deduplicación,
el reloj de DC1 y `kernel_drops`, que es **no medible**. Para este último hace falta una decisión:
medirlo de otra forma o aceptarlo expresamente como limitación.

## 7. Versiones

| Commit | Qué | Desplegado |
|---|---|---|
| 9f1344d | `extracto_experimento.py` | sí (sustituido por los siguientes) |
| 58d2cef | Recálculo, comparación completa del dictamen, saneado de redes, `--inicio-captura-epoch` | sí; con él se generaron entradas y extractos |
| c926338 | Arranque desde `inicio-captura.json`; campos del anillo completo como esperados | sí; con él se calculó `inicio-captura.json` y se hizo la comprobación previa en Sensor1 |
| (este commit) | Requisitos por tipo, `verificar_paquetes.py`, documentación y publicación | sí, verificado por hash tras el commit (ver el informe de cierre) |

Lo publicado en GitHub que **no** corre en el laboratorio: nada. Los guiones de reproducción también
están desplegados, aunque solo se usan fuera del laboratorio.

## 8. Pendientes que siguen abiertos

- **Deduplicación del extractor** (bloque 3, PENDIENTES 37).
- **Reloj de DC1, 6,5–7 ms** (bloque 4, PENDIENTES 38).
- **Rotación del EVE y supervisión prolongada** (bloque 4, PENDIENTES 44 y 59).
- **Causa interna de la pérdida de gestión en el switch** (PENDIENTES 50).
- **Suricata `kernel_drops`**, no medible: falta decidir cómo se trata para `piloto_final` (§6).
- **Decisiones de Mark:** la política de calidad (fila 32) y el filtro VLAN o el softmax (fila 33).
- **Sin revisión independiente:** los campos del anillo completo y el análisis de la pérdida de
  gestión (LEEME).
