# Prueba técnica sintética de 49 h

Esta carpeta **no es el conjunto de investigación ni evidencia de una captura V2 de 49 h**. La EVE técnica se generó en `/tmp` de Sensor1 con `tests/generar_eve_sintetica_49h.py`, tomando solo la forma de un evento stats publicado de VD6 y sustituyendo sus valores. Los eventos flow contienen exclusivamente relleno sintético. El archivo de 2 799 997 693 bytes no se incorpora al repositorio; `manifiesto-sintetico.json` contiene su SHA-256 y permite regenerarlo.

- `medicion-r8-fallida.json`: primera medición con el código anterior, que alcanzó 1 686 068 KiB de RSS, por encima de 256 MiB. El hash de salida fue correcto; el fallo fue de memoria. Se conserva como intento fallido.
- `medicion-integrada.json`: lectura, escritura, evaluación, RSS y duración del paso con el código corregido, incluido el caso de cuatro intentos y tres esperas reales de 6 s. Los hashes verifican la salida contra las 22 051 muestras del generador.
- `suite-resultados.tsv` y `suite-resumen.json`: registro completo de la suite local sobre el árbol de código integrado antes del commit. Los 38 subtests aparecen en el resumen de consola como subtests; el registro cuenta 388 resultados individuales aprobados.
- `clon-limpio-*`: salidas del dictamen, verificación de paquetes, recálculo y suite desde el clon remoto de `da9c62a`; se conserva el intento fallido del recálculo con un directorio de entrada equivocado.
- `laboratorio-parado*.jsonl`: comprobación final de solo lectura. Los dos primeros envíos del script tuvieron rc 127 por el `\r` final de PowerShell, aunque emitieron `parado: si`; el envío como bytes LF terminó rc 0. Se conservan los tres.

Comandos para regenerar en Sensor1 desde un clon del repositorio, con espacio suficiente en `/tmp`:

```sh
python3 tests/generar_eve_sintetica_49h.py --salida /tmp/cf-49h/eve.jsonl --manifiesto /tmp/cf-49h/manifiesto.json
python3 tests/medir_suricata_49h.py --eve /tmp/cf-49h/eve.jsonl --manifiesto /tmp/cf-49h/manifiesto.json --directorio /tmp/cf-49h/salidas --resumen /tmp/cf-49h/resumen.json
```

Los resultados, los criterios V4-b y los pasos aún pendientes del cierre real están en `docs/BLOQUE1-BLOQUE3-INTEGRACION-2026-11-27.md`.
