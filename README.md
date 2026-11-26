# CyberFlow V2: recolección de tráfico legítimo

Repositorio independiente de CyberFlow V2: la nueva evaluación pedida en la revisión mayor del artículo 20267855 (IJIES).

Los repositorios y las evidencias de V1 se mantienen intactos:

- `marksato13/inv-cyberflow-sistema`
- `marksato13/inv-cyberflow-tesis-evidencias-2026`

V2 vuelve a capturar los datos y vuelve a entrenar el escalador y el IF, a calibrar y a fijar los umbrales. El código que reutiliza de V1 indica su repositorio, su commit y los cambios hechos (`docs/PROCEDENCIA.md`). V2 no usa los datos, el modelo, el umbral ni los resultados de V1.

**Repositorio:** https://github.com/marksato13/inv-cyberflow-v2 · **Paquete reproducible del
Bloque 1:** https://github.com/marksato13/inv-cyberflow-v2/releases/tag/bloque1-cierre-2026-11-26
(`paquete-bloque1.tgz`, sha256 `cc21f054…`).

**Estado (26-nov-2026): Bloque 1 (calidad de captura) en revisión; preparación.**

- El piloto final y las 49 h definitivas, los ataques y las campañas A/B **no se han iniciado**.
- Estado del Bloque 1: `docs/BLOQUE1-REVISION-2-2026-11-26.md` (lo vigente), `docs/BLOQUE1-POLITICA-CALIDAD.md`
  (criterio del dictamen), `docs/PENDIENTES.md` y `docs/MATRIZ-OBSERVACIONES.md`.

| Carpeta | Contenido |
|---|---|
| `generador/` | Generador V2: un proceso por perfil, duración finita, semillas, programa por tiempo monotónico, registro por transacción |
| `programas/` | Programas JSON de las siete jornadas de 6 h, del piloto de 30 min y de la prueba corta, con su generador reproducible |
| `operacion/` | `v2ctl.py`: preflight, iniciar, estado y parar, con un supervisor sin reinicio automático |
| `captura/` | Archivador de PCAP y EVE fuera del anillo de V1 y cruce del registro con la captura |
| `extraccion/` | Pendiente: extracción V2 a partir de los originales |
| `tests/` | Pruebas sin red (`python -m unittest discover -s tests`) |
| `docs/` | Protocolo, aclaraciones, procedencia, comandos, informe de pruebas, pendientes y matriz de observaciones |
| `manifiestos/` | Versiones y sha256 del código, los programas y la evidencia privada |

**Capturas.** Los PCAP, el EVE y los registros de ejecución **no se publican**: contienen tráfico del laboratorio. Se conservan en almacenamiento privado, y aquí se publican sus manifiestos y hashes.

Solo se usa la biblioteca estándar de Python 3.12 o posterior, porque las VM del laboratorio no tienen dependencias instaladas.
