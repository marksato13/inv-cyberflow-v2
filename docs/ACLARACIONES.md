# Aclaraciones previas a CyberFlow V2 (sección 2 del encargo)

Fecha: 24-nov-2026. Equipos: Clientes, Sensor1, srv-dmz, DC1 (solo su DNS) y el bastión como acceso.

Estado de cada punto: **comprobado** (con evidencia), **implementado** (cambio hecho) o **pendiente**.

## 2.1 «Solo lectura», las pruebas del 24-nov y las 11 filas

**Comprobado.**

- La inspección del piloto (`04-evidencias/cyberflow/V-piloto-v2-inspeccion-2026-11-24/INFORME-INSPECCION-V2.md`, commit `141b99d` del repositorio de evidencias) no cambió servicios, reglas ni configuración.
- Antes de esa inspección, el 24-nov entre las 00:09:05 y las 00:11:35 UTC, se hizo una prueba de diagnóstico de Suricata/TLS: 25 conexiones HTTPS desde el bastión (10.10.10.30) a 10.10.30.10:443. No fue «solo lectura» para los datos de V1. Ese tráfico entró en las características de la entidad **10.10.30.10**, el servidor, aunque el bastión está en `--excluir`.
- **Filas afectadas:** 11 filas de `artifacts/linea-base/multilayer-v3.csv`, de la entidad 10.10.30.10, con `window_end_utc` entre 00:09:10–00:10:00 y 00:11:30–00:12:10. El valor de `l2_frame_count_30s` llega a 159, cuando en las ventanas vecinas va de 11 a 49.
- **Las filas se añadieron; no se modificó ninguna.** `acumular_v3.py` solo añade claves nuevas al final del CSV. Las líneas 5 736 532 a 5 737 050 caen dentro de los rangos que añadieron dos pasadas de `cyberflow-acumular.timer`, que se ejecuta cada 10 min y tarda unos 115 s:
  - una pasada escribió las líneas 5 734 873 a 5 736 577 (2 filas afectadas);
  - la siguiente escribió las líneas 5 736 578 a 5 738 252 (9 filas afectadas).

  Ambas pasadas corresponden a las de hacia las 00:11:57 y 00:21:55 UTC.
- **Motivo de la contaminación.** `--excluir` solo elimina las filas cuya `entity_ip` está excluida. No quita los paquetes de esa IP de las filas de otras entidades: el tráfico del bastión sigue contando en las características del servidor. Ver §7 del protocolo.
- **Respaldo, en Sensor1 y en la copia privada:** `~/cyberflow-v2-evidencia/filas-24nov/`.
  - `filas-afectadas-11.csv` (sha256 `3554f9e3…7ac355`)
  - `candidatas-con-linea.tsv` (360 filas de contexto con su número de línea, `26d44136…2173`)
  - `cabecera.csv`

  El CSV de V1 **no se ha tocado**.
- **Otro incidente de la misma noche.** A las 00:17:15 UTC se mató por falta de memoria (OOM) un script de lectura que cargaba el CSV entero. Los servicios no se reiniciaron (NRestarts=0). Desde entonces el CSV se lee en flujo y con `ulimit -v`.

## 2.2 ¿Entran en el aprendizaje de V1? Exclusión reversible

**Implementado.**

**Cuándo entrarían.** `cyberflow-aprendizaje.timer` se ejecuta a diario a las 00:30 UTC: `cyberflow_aprendizaje.py --config configs/cyberflow.local.toml diario` (sha256 `add0abc6…`, el mismo que en `producto-main`).

- Cierra el lote del día anterior. El del 24-nov se cerraría el 25-nov a las 00:30 UTC.
- Entrena con la base y los lotes aceptados.
- La exclusión por tramos se aplica al entrenar (`excluir_ventanas`, líneas 706–719), tanto a la base como a los lotes.
- El lote del 23-nov se rechazó por PSI (2,05), pero un lote puede aceptarse a mano: no se puede contar con el PSI.

**Qué se cambió.** Se añadieron dos elementos a `reentrenamiento.excluir_ventanas` de `/home/m4rk/cyberflow/configs/cyberflow.local.toml`:

1. `10.10.30.10@2026-11-24T00:09:00+00:00/2026-11-24T00:12:20+00:00`: las 11 filas de la prueba TLS. Se comprobó con las propias funciones del programa (`tramos_excluidos` y `excluida`) que la regla las excluye: 11 de 11.
2. `*@2026-11-24T05:59:00+00:00/2026-11-24T06:25:00+00:00`: el preflight y las pruebas T0–T3 de V2, para todas las entidades. Hay que aislar V2 del aprendizaje de V1. La primera versión llegaba hasta las 06:14; se amplió a las 06:25 para cubrir T3.

**Respaldos:**

- `cyberflow.local.toml.antes-excluir-prueba-24nov-20261124T054556Z` (sha256 `5b157749…`);
- `cyberflow.local.toml.antes-excluir-pruebas-v2-20261124T061343Z`;
- `cyberflow.local.toml.antes-ampliar-pruebas-v2-20261124T061842Z`.

**Estado final del fichero:** sha256 `58f64dd3…`.

**Cómo revertirlo:** restaurar el respaldo, o borrar el elemento de la lista y su línea de comentario.

## 2.3 Descripción correcta de la espera exponencial

V1 (`clientes_lab.py:358`) duerme `random.expovariate(1.0 / max(ritmo / factor, 0.05))`.

- La función `max(…, 0.05)` actúa sobre la **media** de la distribución: la espera media nunca baja de 0,05 s.
- Cada espera individual sigue siendo exponencial y **puede ser menor que 0,05 s**.

**Comprobado:**

- La prueba `test_piso_de_005_sobre_la_media` da un mínimo inferior a 0,05 s, con una media de 0,05 ± 0,003.
- En T1, 18 de 389 esperas fueron menores que 0,05 s.

Además, la espera empieza cuando **termina** la acción. El intervalo entre inicios es, por tanto, la duración de la acción más la espera, y multiplicar el factor no multiplica el caudal en la misma proporción.

## 2.4 Continuidad del proceso, ausencia de errores y éxito de la transacción

Son tres afirmaciones distintas:

| Afirmación | Qué la prueba | V1 | V2 |
|---|---|---|---|
| El proceso siguió vivo | Journal de systemd (arranques, reinicios) | Sí: un arranque por perfil en septiembre; ofimática se reinició el 27-sep a las 06:59:02 | Supervisor sin reinicio automático: `supervisor.jsonl` registra el código de salida de cada perfil |
| No hubo mensajes de error | `StandardError=journal` | Sí, pero el generador **capturaba toda excepción** y solo contaba «fallidas», con `StandardOutput=null` | Cada excepción queda en su transacción (`excepcion`, `timeout`) |
| La transacción tuvo éxito | Resultado observado frente al esperado | **No se registraba**: no hay código HTTP ni rcode DNS por acción | `resultado_esperado`, `resultado_observado`, `coincide` y `clase` (`ok`, `error_intencional`, `variacion_servidor`, `fallo_inesperado`) |

La ausencia de errores en el journal de V1 **no** demuestra que las transacciones legítimas tuvieran éxito. Esto responde a R1.7.

## 2.5 `--history-seconds 230` frente a las historias de 10, 30 y 60 s

- Las 28 características usan ventanas de 10, 30 y 60 s (`maximum_history_seconds = 60` del esquema `multilayer-v2.json`).
- `--history-seconds 230` es un parámetro del **motor en vivo** (`motor_decision.py`), no del esquema. Fija cuántos segundos de EVE se guardan en memoria y qué horizonte del anillo de PCAP se lee para calcular cada ventana: `[A − history_seconds, A]`, líneas 551–577. Las características solo usan los últimos 60 s.
- El margen sobrante sirve para dos cosas:
  - reevaluar ventanas pendientes, con `limite_pendiente = history_seconds − 60 = 170 s`;
  - atribuir el iniciador de flujos largos.
- El valor viene de `cyberflow.local.toml` (`historia_segundos = 230`), cuyo comentario habla de un anillo de «16 × 15 s = 240 s».
- Ese comentario no describe la captura actual. tcpdump rota cada 5 s (`-G 5`) y `cyberflow-limpieza.timer` borra los ficheros con más de 15 min. El motor dispone de más historia que 230 s.
- No hay incoherencia con 10, 30 y 60 s: son magnitudes distintas.

## 2.6 Las 38 IP y el 58 %

**Comprobado.** Fichero de Sensor1 `/home/m4rk/cyberflow/artifacts/aprendizaje/base/particionado-nota-L.csv`: 49 543 704 bytes, del 11-oct 04:59, sha256 `bdf6f6419ec19e711c7add9e8b5f1440b896b32270c25d69b7e8267d4f9aba7a`. Se recontó en flujo el 24-nov (denominador: 337 980 filas):

| Grupo | Filas | % |
|---|---:|---:|
| Seis perfiles (10.10.20.21–26) | 139 892 | 41,39 |
| Otras 38 IP | 197 377 | 58,40 |
| Kali (10.10.20.30) | 711 | 0,21 |
| **Total (45 IP)** | **337 980** | 100 |

Esa proporción describe **solo** la línea base de V1, del 27-sep al 29-sep, y **no se traslada a V2**:

- En V2 la población principal son los seis perfiles.
- Toda otra IP observada se inventaría con una regla de inclusión o exclusión y su motivo (protocolo §7).
- La proporción de V2 se medirá de nuevo.
