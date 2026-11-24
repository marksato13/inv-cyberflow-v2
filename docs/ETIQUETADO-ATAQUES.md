# Reglas de etiquetado de ventanas con ataque (versión 1, 24-nov-2026)

Se fijan **antes** de ejecutar ningún ataque de V2. El piloto de 30 min y la captura de 42 h
son solo tráfico legítimo y no usan estas reglas. Si se cambian después de ver resultados del
detector, el cambio es una versión nueva, con su fecha y su motivo, y los resultados con la
versión anterior se conservan.

## 1. Verdad de terreno

La etiqueta sale **solo** del registro de ejecución del ataque, nunca de lo que diga el detector,
Suricata ET ni ninguna otra alarma.

Cada episodio queda registrado en `ataques/<ID>/episodios.jsonl` por el orquestador que lo lanza,
con una línea por episodio:

| Campo | Contenido |
|---|---|
| `episodio_id` | identificador único |
| `familia` | p. ej. `port_scan`, `dns_flood`, `http_flood`, `fuerza_bruta_ssh` |
| `herramienta` y `parametros` | comando exacto y su versión |
| `atacante_ip` | IP de origen del ataque |
| `objetivos` | IP y puertos de destino |
| `inicio_utc`, `fin_utc` | primer y último paquete **observado en el PCAP** para ese episodio (no la hora del comando) |
| `rc` | código de salida de la herramienta |

`inicio_utc` y `fin_utc` se recalculan desde el PCAP archivado con el filtro (atacante → objetivos)
y se guardan junto a los tiempos del comando. Si difieren más de 2 s, se anota.

## 2. Etiqueta de cada ventana

Una ventana es `(entidad, cierre)` y cubre `(cierre − 10 s, cierre]`; su historia llega a
`cierre − 60 s`. Para la entidad atacante de un episodio:

| Etiqueta | Regla |
|---|---|
| `ataque` | `(cierre − 10, cierre]` se solapa con `[inicio, fin]` del episodio **y** la ventana tiene al menos un paquete del atacante a un objetivo |
| `estela` | no cumple lo anterior, pero `[cierre − 60, cierre]` se solapa con el episodio: la historia todavía arrastra el ataque |
| `legitimo` | ninguna de las anteriores |

Para el resto de entidades (víctimas y terceros):

- la ventana de una víctima nunca es `ataque` por recibirlo;
- si su historia de 60 s contiene tráfico del episodio, se marca `afectada` y se informa aparte.

## 3. Uso en la evaluación

- Detección: positivos = ventanas `ataque`; negativos = ventanas `legitimo` de la misma ejecución.
- `estela` y `afectada` no cuentan como positivo ni como falso positivo. Se informan con su número
  y con lo que dijo el detector.
- Un episodio se cuenta como detectado si al menos una de sus ventanas `ataque` supera el umbral.
  La latencia se mide desde `inicio_utc` hasta el cierre de esa primera ventana.
- Las ventanas excluidas por E1–E5 (`PROTOCOLO.md` §7) no entran en ninguna métrica, sea cual
  sea su etiqueta. Se informa cuántas tenían cada etiqueta.
- Los episodios con `rc` distinto de 0, o sin paquetes en el PCAP, se declaran `fallidos`. No se
  etiquetan como ataque ni se repiten por lo que diga el detector.

## 4. Dónde va

La etiqueta, el `episodio_id` y la familia se añaden como columnas de `ventanas_meta.csv`.
**Nunca** entran en `entradas_if.csv`: las 28 entradas no cambian. El programa que las calcula
se escribe y se prueba con episodios sintéticos antes de la primera campaña, y su commit se cita
en el informe de esa campaña.

## 5. Pendiente de decidir con Mark antes de la primera campaña

- La lista de familias y sus parámetros.
- Si `estela` se evalúa aparte como «detección tardía» o solo se informa.
