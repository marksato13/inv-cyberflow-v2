# CyberFlow V2: recolección de tráfico legítimo

Repositorio independiente de CyberFlow V2: la nueva evaluación pedida en la revisión mayor del artículo 20267855 (IJIES).

Los repositorios y las evidencias de V1 se mantienen intactos:

- `marksato13/inv-cyberflow-sistema`
- `marksato13/inv-cyberflow-tesis-evidencias-2026`

V2 vuelve a capturar los datos y vuelve a entrenar el escalador y el IF, a calibrar y a fijar los umbrales. El código que reutiliza de V1 indica su repositorio, su commit y los cambios hechos (`docs/PROCEDENCIA.md`). V2 no usa los datos, el modelo, el umbral ni los resultados de V1.

**Repositorio:** https://github.com/marksato13/inv-cyberflow-v2

**Paquetes reproducibles del Bloque 1:**

- revisión 4 (vigente):
  https://github.com/marksato13/inv-cyberflow-v2/releases/tag/bloque1-r4-2026-11-26. Contiene VD2,
  VD3, VD4 y VD6 con el anillo, el EVE, srv-dmz y DC1 filtrados al tráfico experimental. Sus sha256
  están en `evidencias/bloque1/entradas-r4/SHA256SUMS-bloque1-r4.txt`;
- anterior: https://github.com/marksato13/inv-cyberflow-v2/releases/tag/bloque1-cierre-2026-11-26.

**Estado (26-nov-2026): Bloque 1 (calidad de captura) en revisión; preparación.**

- El piloto final y las 49 h definitivas, los ataques y las campañas A/B **no se han iniciado**.
- Estado del Bloque 1:
  - `docs/BLOQUE1-REVISION-7-2026-11-26.md`: Suricata por intervalos (pérdida atribuible frente a no localizada, el fallo manda sobre la falta de evidencia), continuidad con `uptime` y paso de cierre comprobado (lo vigente);
  - `docs/BLOQUE1-REVISION-6-2026-11-26.md`: suficiencia temporal de Suricata (el periodo debe quedar acotado), C9 sin depender de C7, `dictamen_casos` sin copia recursiva, qué valores publicados deciden el dictamen, y dependencias;
  - `docs/BLOQUE1-REVISION-5-2026-11-26.md`: reproducción limpia, Suricata `kernel_drops` (sí se mide),
    conciliación de pendientes y **matriz final del Bloque 1**;
  - `docs/BLOQUE1-REVISION-4-2026-11-26.md`: publicación, reproducción y requisitos por tipo de ejecución;
  - `docs/BLOQUE1-REVISION-3-2026-11-26.md`: VD4/VD6 y C7/C9–C13;
  - `docs/BLOQUE1-REVISION-2-2026-11-26.md`;
  - `docs/BLOQUE1-POLITICA-CALIDAD.md`, `docs/PENDIENTES.md` y `docs/MATRIZ-OBSERVACIONES.md`.
- **VD6** (V2-VD6-20261126T151456Z, código 9196712) es una **verificación dirigida** `aprobada`. Lo
  está solo en los requisitos de ese tipo de ejecución: las comprobaciones de duración prolongada y
  las de otros bloques siguen pendientes aparte. VD3 se conserva como `no_aprobada`.
- **Siguen abiertos:**
  - del propio bloque: la causa interna de la pérdida en el switch;
  - del bloque 3: la deduplicación del extractor;
  - del bloque 4: el reloj de DC1, la rotación del EVE y la supervisión prolongada.

  Suricata `kernel_drops` se mide y vale 0: la afirmación anterior de «no medible» era falsa
  (REVISION-5 §2).

### Reproducir el Bloque 1 (desde un clon nuevo)

Los programas necesitan Python 3.12 o posterior, solo con la biblioteca estándar. Las pruebas necesitan además pytest (ver «Pruebas» abajo). Para descargar, `gh` o el
navegador. **En Windows**, clona en una carpeta de ruta corta (por ejemplo `C:\r4`) y con
`core.longpaths=true`: algunas rutas de `evidencias/` superan los 260 caracteres. Sin eso, el checkout
queda incompleto (primer intento, `evidencias/bloque1/entradas-r4/REPRODUCCION-CLON-LIMPIO-intento1-fallido.txt`).

```
git clone -c core.longpaths=true https://github.com/marksato13/inv-cyberflow-v2.git
cd inv-cyberflow-v2
gh release download bloque1-r4-2026-11-26 -D descargas
python -X utf8 operacion/verificar_paquetes.py descargas
python -X utf8 operacion/reproducir_dictamen.py
python -X utf8 operacion/recalcular_desde_capturas.py evidencias/bloque1/entradas-r4 --p2 evidencias/bloque1/extractos-539c48e/p2-V2-VD2-20261126T090705Z
```

Resultado esperado: cada guion termina en `GLOBAL SATISFACTORIO` (rc 0). `reproducir_dictamen.py` aplica por omisión los complementos `suricata-r5`, `suricata-r6` y `suricata-r7` (REVISION-7 §5).

### Pruebas

Además de lo anterior hace falta **pytest** (probado con Python 3.14.3 y pytest 9.0.3). `unittest discover` no recoge las pruebas escritas para pytest.

```
python -m pip install pytest
python -m pytest -q -p no:cacheprovider tests
```

Resultado esperado con el código de la 7.ª revisión: `335 passed, 38 subtests passed`. Las pruebas del fragmento de `cerrar_v2.sh` necesitan bash (en Windows, Git Bash); sin él se omiten. `test_sondeo_span` puede fallar alguna vez si la máquina va muy cargada (REVISION-7 §4).

- `verificar_paquetes.py` comprueba los sha256 frente al manifiesto versionado y extrae los paquetes.
- `reproducir_dictamen.py` rehace el dictamen desde los resultados intermedios: dictamen, motivos,
  criterios y los ocho casos de VD2, VD3, VD4 y VD6 frente a la referencia del laboratorio. Usa por
  omisión el complemento `evidencias/bloque1/suricata-r5/`: los eventos `stats` originales de Suricata y
  la referencia recalculada (revisión 5). Comprueba además el componente de Suricata de C9 y que cada
  lectura de la supervisión coincida con la EVE.
  Resultados esperados: VD2 `indeterminada`, VD3 `no_aprobada`, VD4 y VD6 `aprobada`.
- `recalcular_desde_capturas.py` rehace cobertura, extremo, DNS, copias y extracción desde los
  PCAP/EVE, y las 45 transacciones de P2.

Qué no puede rehacerse, y por qué, está en `evidencias/bloque1/entradas-r4/LEEME.md`. Comprobado desde una carpeta vacía con estos mismos comandos:

- `C:\r4` con r4: `evidencias/bloque1/entradas-r4/REPRODUCCION-CLON-LIMPIO-intento2.txt`;
- `C:\r5` con r5: `evidencias/bloque1/suricata-r5/REPRODUCCION-CLON-LIMPIO-intento3.txt`.

El primer intento falló por la longitud de las rutas, y su registro se conserva.

| Carpeta | Contenido |
|---|---|
| `generador/` | Generador V2: un proceso por perfil, duración finita, semillas, programa por tiempo monotónico, registro por transacción |
| `programas/` | Programas JSON de las siete jornadas de 6 h, del piloto de 30 min y de la prueba corta, con su generador reproducible |
| `operacion/` | `v2ctl.py`: preflight, iniciar, estado y parar, con un supervisor sin reinicio automático |
| `captura/` | Archivador de PCAP y EVE fuera del anillo de V1 y cruce del registro con la captura |
| `extraccion/` | Extracción V2 (`extraer_v2`, `verificar_v2`, `metadatos_v2`) a partir de los originales |
| `tests/` | Pruebas sin red (`python -m pytest -q -p no:cacheprovider tests`; necesita pytest) |
| `docs/` | Protocolo, aclaraciones, procedencia, comandos, informe de pruebas, pendientes y matriz de observaciones |
| `manifiestos/` | Versiones y sha256 del código, los programas y la evidencia privada |

**Capturas.** Los PCAP y el EVE **completos** no se publican: contienen tráfico de gestión y de
equipos ajenos, y metadatos de aplicación de terceros. Se conservan en almacenamiento privado, y aquí
se publican sus manifiestos y hashes.

Se publican, en la release, extractos filtrados al tráfico experimental. Solo cambian las MAC, que
pasan a un seudónimo. Para P2 se publica un extracto de 6 conexiones. El criterio está en
`evidencias/bloque1/entradas-r4/LEEME.md`.

Los programas solo usan la biblioteca estándar de Python 3.12 o posterior, porque las VM del laboratorio no tienen dependencias instaladas. Las pruebas, además, pytest.
