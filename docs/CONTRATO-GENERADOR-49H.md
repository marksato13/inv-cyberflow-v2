# Contrato del generador V2 para la captura de 49 h (perfiles P1–P6)

Versión 3.0.0 · 2026-11-25. Sustituye a los perfiles de V1 (ofimática, navegación, descargas,
aplicación, ligero, errático) y al programa de 42 h. Fuente del encargo:
`CyberFlow_V2_Perfiles_y_Jornadas_49h.xlsx` (hojas «1 Fuentes», «2 Perfiles», «3 Jornadas»).

Este documento fija **todo** lo que el Excel dejaba abierto. Cada parámetro lleva su procedencia:

| Marca | Significado |
|---|---|
| **PUB** | valor publicado en la fuente citada, comprobado en la fuente (ver §1) |
| **ADAP** | adaptación propia de un valor publicado al laboratorio |
| **D1** | decisión propia del diseño experimental (Excel, fila D1) |
| **V1** | heredado del generador V1 sin cambios |
| **NUEVA** | decisión tomada en este contrato para cerrar un campo pendiente del Excel |

## 1. Fuentes comprobadas

| ID | Comprobación (25-nov-2026) | Resultado |
|---|---|---|
| S2 | `src/applications/model/three-gpp-http-variables.cc` de ns-3-dev, último commit que lo toca `c0010702ce7078614a80899f412b25cef86b6711` (2025-06-05). Generadores en `src/core/model/random-variable-stream.cc`, último commit `3c01828ecfa453a3542bb21f87a10cfa47842e79` (2026-06-29). Leídos en gitlab.com/nsnam/ns-3-dev | Medias y desviaciones de H1/H2, mínimos y máximos, Pareto (escala 2, forma 1,1, máximo 55), lectura 30 s, parsing 0,13 s: coinciden con el Excel. Algoritmos en §4 |
| S3 | Página de MathWorks «Generate and Visualize FTP Application Traffic Pattern» (R2026b) | Modelo FTP local: lognormal truncada μ = 14,45, σ = 0,35 (media ≈ 2 MB) y lectura exponencial de media 180 s. El ejemplo de la página **sobrescribe** esos valores (μ = 10, σ = 1, 5 MB, media 100 en ms): no se usan |
| S4 | SPECweb2009 Design §4.5 | Think time exponencial entre THINK_INTERVAL y THINK_MAX, media THINK_TIME. Los límites numéricos están en la configuración de cada carga, no en el documento |
| S5 | SPECweb2009 Run Rules §2.2.2 | THINK_TIME = 10 s en Banking y Ecommerce, 5 s en Support |
| S6 | IEEE 802.16j-06/013r2, tablas 7 y 8 (texto extraído del PDF) | Tabla 7 (HTTP DL) = mismos valores que ns-3, con «subtract k from generated random value» y regla de rechazo fuera del intervalo. Tabla 8 (FTP DL): lognormal truncada media 2 MB, desviación 0,722 MB, **máximo 5 MB**, σ = 0,35, μ = 14,45; lectura «Mean = 180 sec (TBD)». La tabla 7 también pide 30 % HTTP/1.0 y 70 % HTTP/1.1: **no se adopta** (todo es HTTP/1.1, ver §5) |

Comprobación cruzada: con las fórmulas de ns-3, H1 da σ = 1,366 y μ = 8,346, los mismos 1,37 y
8,35 que imprime la tabla 7 del IEEE. F1 da media e^(14,45+0,35²/2) = 2,00 MB y desviación
0,721 MB, los mismos de la tabla 8.

## 2. Perfiles

Una sola secuencia por IP (sin concurrencia dentro de un perfil, **D1** del Excel). Las pausas se
cuentan desde que termina la acción anterior. Toda acción empieza con una resolución DNS real
(§6) y se conecta a la IP resuelta.

| Perfil | IP | Ciclo | Pausa base | Contenido | Procedencia |
|---|---|---|---|---|---|
| P1 consulta web y DNS | 10.10.20.21 | DNS → GET HTTP de un objeto H1 (conexión nueva, `Connection: close`) → pausa | Exp(media 30 s) | H1 | pausa y H1 **PUB** S2; sin objetos secundarios **ADAP** |
| P2 navegación multirrecurso | 10.10.20.22 | DNS → una conexión persistente → GET principal H1 → parsing Exp(0,13 s) → N = H3 objetos secundarios H2 por la misma conexión, uno tras otro → cierre → lectura | lectura Exp(media 30 s) | H1, H2, H3 | **PUB** S2; protocolo alterno HTTP/HTTPS **NUEVA** (§5) |
| P3 transferencia de archivos | 10.10.20.23 | DNS → GET HTTP de un archivo F1 (conexión nueva) → pausa | Exp(media 180 s) | F1 | tamaño y pausa **PUB** S3/S6; transporte HTTP **ADAP** |
| P4 aplicación transaccional | 10.10.20.24 | DNS → GET consulta → pausa → POST envío → pausa → GET consulta → pausa (y vuelve a empezar) | Exp(media 10 s) entre operaciones, sin cota | §3 | 10 s **PUB** S5; exponencial sin cota y API **ADAP** (S4 la acota) |
| P5 actividad ligera | 10.10.20.25 | igual que P1 | Exp(media 90 s) | H1 | **D1** (P1 × 3) |
| P6 actividad intermitente | 10.10.20.26 | igual que P1, solo en ON | ON 60 s / OFF 120 s; en ON Exp(media 10 s) | H1 | **D1** |

Reglas comunes (**NUEVA** salvo indicación):

- **Arranque desfasado**: cada perfil empieza con una pausa sorteada (no actúan los seis en t = 0).
- **P6**: ciclo anclado al inicio del programa, ON = [180k, 180k + 60), OFF = [180k + 60, 180(k + 1)).
  En ON las llegadas son de Poisson: al empezar cada ON se sortea la primera pausa; una pausa que
  pase del fin de ON se corta y no se inicia nada en OFF. Una acción en curso al acabar ON termina
  y se registra con `cruza_borde_on = true`.
- **P4**: el paso en curso (consulta, envío o consulta) continúa a través de cambios de nivel y de
  bloque; la secuencia empieza de nuevo tras la segunda consulta. Si un paso falla, la secuencia
  se abandona y la siguiente empieza tras la pausa normal (no se reintenta).
- **Una acción pertenece** a la jornada, el bloque y el nivel en que **empieza**.

## 3. Endpoints del servidor (srv-dmz 10.10.30.10, `servidor_lab_v2.py` v3.0.0)

| Ruta | Método | Respuesta esperada | Uso |
|---|---|---|---|
| `/contenido/<n>` (1 ≤ n ≤ 5 000 000) | GET | 200, `Content-Length: n` exacto, cuerpo `application/octet-stream` determinista (bloque pseudoaleatorio fijo de 1 MiB, semilla `cyberflow-v2-contenido`, repetido y recortado) | P1, P2, P3, P5, P6 |
| `/contenido/<n>` con n fuera de rango o no entero | GET | 400 (error del cliente, nunca aleatorio) | ninguno; solo pruebas |
| `/app/consulta?ref=<k>` | GET | 200, JSON de exactamente 512 bytes (relleno con espacios) | P4 pasos 1 y 3 |
| `/app/envio` | POST | 201, JSON `{"recibido": <bytes>, "sha256": "..."}`; 400 si `Content-Length` no coincide con lo leído | P4 paso 2 |

- El cuerpo del POST mide U{200, …, 8000} bytes aleatorios (rango de V1, **V1**).
- El parámetro `?tipo=principal|secundario|archivo` de `/contenido` solo etiqueta el registro del
  servidor; no cambia la respuesta.
- **Velocidad**: `--limite-bps 5000000` por conexión en `/contenido` (el mismo límite medido en el
  piloto del 24-nov para `/estatico`, con 0 pérdidas en el espejo a 1000 Mbit/s). Un archivo de
  5 MB tarda ≥ 1 s. El límite cambia la carga ofrecida y queda registrado por petición.
- **Errores**: el servidor v3 ya no sortea 500 en ningún POST. Las rutas V1 (`/estatico`,
  `/api/*`) se conservan para compatibilidad, pero el generador v3 no las usa.
  **Consecuencia**: en las 49 h normales no habrá 4xx/5xx, NXDOMAIN, RST a puertos cerrados ni
  ICMP. Las columnas 6, 10, 12, 13, 23 y 28 serán casi siempre 0 en entrenamiento. Es lo que pide
  el Excel («no generar errores sin propósito definido»), pero cambia la base respecto a V1 y se
  anota en PENDIENTES.

## 4. Distribuciones y algoritmo

Generador: `random.Random` de Python (Mersenne Twister MT19937). Se registra la versión de Python
en el evento `inicio`.

| Clave | Algoritmo (idéntico a ns-3 salvo la fuente uniforme) | Entero |
|---|---|---|
| H1 | σ² = ln(1 + s²/m²), μ = ln m − σ²/2 con m = 10710, s = 25032. `v = int(lognormvariate(μ, σ))`; repetir mientras v < 100 o v ≥ 2 000 000 | truncado hacia 0, como `static_cast<uint32_t>` |
| H2 | igual con m = 7758, s = 126168; rechazo fuera de [50, 2 000 000) | truncado |
| H3 | `x = int(2 / u**(1/1.1))` con u en (0, 1]; repetir si x > 55 (cota de ParetoRandomVariable) o si x < 2 o x ≥ 55 (`GetNumOfEmbeddedObjects`); N = x − 2 ∈ [0, 52] | truncado |
| F1 | `v = int(lognormvariate(14.45, 0.35))`; repetir mientras v ≤ 0 o v ≥ 5 000 000 | truncado |
| Pausas | `expovariate(factor / media_base)`, sin cota; parsing `expovariate(1/0.13)` sin factor | real |

ns-3 genera la normal con el método polar de Box-Muller (`LogNormalRandomVariable`) y Python con
el método de Kinderman-Monahan (`lognormvariate`). Las distribuciones son iguales y las secuencias
no: no se pretende reproducir la secuencia de ns-3.

## 5. Protocolos, conexiones y tiempos de espera

- **HTTP/1.1** en todo. P1, P3, P4, P5 y P6 abren una conexión por petición (`Connection: close`,
  como V1). P2 usa una conexión persistente por página (`Connection: keep-alive`, cuerpos leídos
  por `Content-Length`) y la cierra al acabar la página.
- **P2 alterna** HTTP (puerto 80) y HTTPS (puerto 443, TLS con el certificado propio del
  laboratorio y sin verificación, como V1) por página: la página 0 de cada bloque es HTTP, la 1
  HTTPS, y así sucesivamente. Es 50/50 por construcción (**NUEVA**), no una media de navegación
  real. En HTTPS, EVE ve TLS pero no HTTP: queda registrado en `visibilidad_l7`.
- Tiempos de espera de red de V1: conexión 5 s, lectura HTTP 10 s sin datos, DNS 3 s sin
  reintento. Un fallo se registra y el perfil sigue con su pausa.

## 6. DNS

- El cliente consulta directamente a DC1 (10.10.10.20) por UDP sin pasar por el resolvedor del
  sistema: **no hay caché en el cliente**. Cada acción empieza con exactamente una consulta A real
  (P2: una por página, no por objeto; P4: una por secuencia de tres operaciones).
- Nombres: uno de `portal, intranet, correo, wiki, erp, archivos` en la zona `cf-v2.lab`, elegido
  al azar con el flujo `contenido`. Todos resuelven a 10.10.30.10. El TTL devuelto por DC1 se
  registra, pero no se usa.
- No hay consultas a nombres inexistentes.

## 7. Niveles y calendario

| Nivel | Factor sobre la frecuencia | Media de P1 | Afecta a | No afecta a |
|---|---|---|---|---|
| reducido | 1/3 | 90 s | pausas de interacción (P1–P6, incluida la lectura de P2 y la pausa en ON de P6) | tamaños, parsing, concurrencia, ON/OFF de P6 |
| base | 1 | 30 s | — | — |
| aumentado | 2 | 15 s | igual que reducido | igual que reducido |

Una pausa que cruza un cambio de nivel, un borde de bloque o un borde ON/OFF se corta en el borde y
se vuelve a sortear con el nivel nuevo. Con pausas exponenciales esto equivale a un proceso de
Poisson por tramos.

Calendario (`programas/captura-49h.json`): 176 400 s de tiempo transcurrido, medidos con un reloj
monotónico. Siete jornadas de 25 200 s y dos bloques de 12 600 s (3,5 h) cada una.

| Jornada | Patrón | Bloque 1 | Bloque 2 |
|---|---|---|---|
| J1 | todos en base | entrenamiento | entrenamiento |
| J2 | P1 y P2 aumentado, resto base | entrenamiento | calibración |
| J3 | P3 y P4 aumentado, resto base | entrenamiento | desarrollo |
| J4 | base; P1, P2 y P4 aumentado en [h·3600 − 300, h·3600) para h = 1…7 (siete ráfagas) | entrenamiento | calibración |
| J5 | patrón de J1 (las semillas son otras porque los bloques son otros) | entrenamiento | desarrollo |
| J6 | todos reducido; en cada bloque, todos en base en [30, 45) y [120, 135) min (cuatro periodos) | entrenamiento | calibración |
| J7 | todos reducido; en cada bloque, todos en base en [40, 43), [100, 103) y [160, 163) min (seis ráfagas) | entrenamiento | desarrollo |

Totales nominales: entrenamiento 28 h (8 bloques), calibración 10,5 h (3) y desarrollo 10,5 h (3).
Es un reparto aproximado, no un 60/20/20 exacto. La evaluación normal de 18 h y los ataques
quedan fuera. Este programa **sustituye** a `captura-42h.json` y `jornada-J*.json`, que se
retiran del árbol (siguen en el historial git, commit 5d87633).

## 8. Aleatoriedad

- Hay tres flujos independientes por bloque y perfil: `espera` (pausas y parsing), `contenido`
  (tamaños, H3, nombre DNS, cuerpo del POST) y `red` (identificador DNS).
- Semilla de cada flujo: los 12 primeros hex de `sha256("cyberflow-v2|49h|2026-11-25|<programa_id>|<bloque>|<perfil>|<flujo>")`.
- Al entrar en un bloque, los tres flujos se resiembran.
- Separar `contenido` de `espera` hace que un cambio de nivel no altere la secuencia de tamaños.
- La semilla maestra se fijó antes de capturar nada y no se elige mirando resultados del IF. Las
  semillas de cada bloque quedan en el programa y en el manifiesto de inicio.

## 9. Registro

Una línea JSONL por **intercambio atómico** (una consulta DNS, o una petición HTTP con su
respuesta), para que cada línea se concilie 1:1 con el registro del servidor o de DNS. Campos
nuevos de cada línea:

- `perfil`, `secuencia_id` (ciclo, página o secuencia P4) y `paso`;
- `accion` ∈ {`dns`, `obtener`, `consulta`, `envio`} y `tipo_objeto` ∈ {`principal`, `secundario`, `archivo`, `objeto`, `consulta`, `envio`};
- `bytes_solicitados`, `bytes_cuerpo_recibidos`, `conexion_n` y `peticion_en_conexion` (P2);
- `protocolo`, `nivel`, `factor`, `jornada_id`, `bloque_id`, `particion`;
- `en_on` y `cruza_borde_on` (P6);
- `dns_ttl`, `espera_previa_s` y la duración.

Eventos: `inicio`, `bloque`, `jornada`, `nivel`, `on`/`off` (P6), `pausa_cortada` y `fin`.

## 10. Qué no se afirma

- Que las medias publicadas representen usuarios actuales o reales.
- Que el factor 2 duplique las peticiones por segundo: las acciones también duran.
- Que P5 y P6 sean promedios de usuarios: son contrastes del diseño.
- Que las 49 h sean siete días naturales: son siete segmentos de una sola captura continua.
- Que una muestra corta (piloto, pruebas dirigidas) demuestre el ajuste de las distribuciones. El
  ajuste se prueba fuera de línea con n grande (tests) y se mide sobre la captura completa.
