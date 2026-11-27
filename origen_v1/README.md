# Copia de referencia del código V1

Estos ficheros se copian **sin modificar**. Origen: https://github.com/marksato13/inv-cyberflow-sistema (clon local producto-main), commit `d2c97728916c2484f770a7a16a984c4c6bd42175`, salvo `motor_decision.py` y `deduplicar_v2.py`, que son del commit `5d849bf6e072a23b4763d5ab7392aafedb2d31a7` (27-nov, Bloque 3: opción `--deduplicacion v2` del motor, de 60a85ea; por omisión `v1`; `deduplicar_v2` versión 3). `deduplicar_v2.py` es idéntico a `extraccion/deduplicar_v2.py`, y `verificar_v2.py` lo comprueba.

Sirven como base de lo que V2 reutiliza:

- la extracción de xtraccion/;
- la comprobación de paridad con el motor;
- el servidor de servidor/.

Cada fichero de V2 que derive de uno de estos indica en su cabecera el fichero de origen y los cambios aplicados. **No se ejecutan desde aquí.**

| Fichero | sha256 |
|---|---|
| `scripts/features/extract_multilayer.py` | `950fe6c49c9eee21f939b2f1032fee1df2c1572923a642c18454fa7dd8205027` |
| `scripts/features/extract_multilayer_v2.py` | `7130edae65afefa2fd82a9314e20194adec684f4b2c3c35c2337880d8e636ccb` |
| `scripts/features/extract_multilayer_v3.py` | `5adbfbf4845554430a3e8b5a4c00eb1e45c2216cae73532da73d9d3f4898fa7f` |
| `scripts/features/acumular_v3.py` | `9c35b831453d2107769ca1fe610782b6821b2f164df1f369b3e6b3ef36c41dc8` |
| `scripts/engine/motor_decision.py` (60a85ea, sin cambios después) | `099d1d2a9856ee6bd0d3f6dc993a420a8607a20b3a8a721b0ad3fcb0cf103357` |
| `scripts/features/deduplicar_v2.py` (5d849bf) | `6ec71ab60e8604605436d5ea73ffcd0e41f1246dcd93b4adf72f523168d04b2d` |
| `scripts/laboratorio/servidor_lab.py` | `9e91d8b8203d0bd62509dbb4169af5fff2a3838b06cebed8ee1e6e15d27d580e` |
| `configs/features/multilayer-v2.json` | `1445ccd4f33f2269a73fb26f36519924525e6018910ebc22dc2005d7163be90d` |
