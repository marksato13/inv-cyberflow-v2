# Procedencia del código

**Repositorio de V1:** `marksato13/inv-cyberflow-sistema`, commit `d2c97728916c2484f770a7a16a984c4c6bd42175` (fuente S1 del plan). Los ficheros instalados en el laboratorio el 24-nov tienen el mismo sha256 que en ese commit.

**Qué no se reutiliza de V1 como resultado de V2:** los datos, el modelo entrenado, el escalador, el umbral, α y los resultados.

## Fichero por fichero

| Fichero V2 | Origen V1 (en d2c9772) | sha256 V1 | Cambios |
|---|---|---|---|
| `generador/transacciones.py` | `scripts/laboratorio/clientes_lab.py` (clase `Cliente`) | `ae5134a7…` | Mismas acciones, rutas, tamaños, puertos y tiempos de espera de red. Cada acción rellena un registro en vez de callar las excepciones. HTTP se habla a mano para contar bytes y leer el código. DNS decodifica rcode y registros A. Los nombres salen de la zona `cf-v2.lab`, no del dominio de otro proyecto. Ping con `-n`. La aleatoriedad usa el generador con semilla |
| `generador/clientes_lab_v2.py` | `clientes_lab.py` (`main`, `factor_horario`) | `ae5134a7…` | Programa por tiempo monotónico en lugar de `datetime.now()` y del fin de semana. Duración finita, semillas, identificadores, registros JSONL y SIGTERM controlado. La espera exponencial es la de V1, pero se corta en cada cambio de fase. Las ráfagas de errático son las de V1, ahora sobre el reloj monotónico |
| `generador/programa.py` | — | — | Nuevo: validación del programa (sin huecos ni solapes) y factor por fase y pulso |
| `programas/generar_programas.py` | `clientes_lab.py` (`PERFILES`, `factor_horario`) | `ae5134a7…` | Ritmos, pesos, ráfagas y factores 1,0/0,55/0,9/0,3 de V1; bloques y particiones del plan; el resto es NUEVO (campo `procedencia` de cada JSON) |
| `operacion/v2ctl.py` | `scripts/laboratorio/clientes_config.py` | `9aa2e2e0…` | Sustituye las unidades systemd con `Restart=always` por un supervisor sin reinicio automático. Mismos alias (`--base 10.10.20.21` + índice). Añade preflight y manifiestos |
| `captura/archivar_v2.py` | — | — | Nuevo: copia los PCAP del anillo de V1 (sin tocarlo) y sigue el EVE |
| `captura/cobertura_v2.py` | — | — | Nuevo: cruza el registro con el PCAP y el EVE |
| (sin cambios, en el laboratorio) `servidor_lab.py` | `laboratorio/configuracion/srvdmz/servidor_lab.py` | `9e91d8b8…` | Ninguno. Su aleatoriedad (POST → 500 con p = 0,1; `/api/lento` de 1,5 a 4 s) está documentada en el protocolo |
| (pendiente) extracción | `scripts/features/extract_multilayer_v3.py`, `extract_multilayer_v2.py`, `acumular_v3.py`, `configs/features/multilayer-v2.json` | `5adbfbf4…`, `7130edae…`, `9c35b831…`, `1445ccd4…` | Se incorporarán a `extraccion/` con esta misma tabla. Cambios previstos: filtrar el tráfico excluido por paquete, deduplicar el espejo y no acumular en la línea base de V1 |


## Generador v3 (25-nov-2026)

El contrato CONTRATO-GENERADOR-49H.md sustituye la conducta V1/v2 descrita arriba.
Se conserva de V1 el transporte con sockets, medición de bytes TLS por BIO, consulta DNS
directa y tiempos de espera de red. generador/transacciones.py usa ahora /contenido/<n>,
/app/consulta y /app/envio, con P2 en conexión HTTP/1.1 persistente.
generador/distribuciones.py implementa H1, H2, H3 y F1 según §4.
generador/clientes_lab_v2.py usa tres flujos MT19937 por perfil y bloque; su reloj
monotónico, espera y ejecución siguen inyectables. El calendario y las semillas son
generados determinísticamente por programas/generar_programas.py. Las semillas se
derivan de la cadena maestra fijada en §8 del contrato; no dependen de resultados del IF.
Las herramientas de operación, conciliación, cobertura y evaluación aceptan las
acciones y los niveles v3. Los registros antiguos siguen documentados en esta sección
histórica y no definen el comportamiento de v3.
