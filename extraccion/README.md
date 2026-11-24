# Extracción V2 (pendiente)

Aquí se incorporarán, con su procedencia, los scripts de procesamiento, entrenamiento y evaluación.

**Base prevista** (V1, `inv-cyberflow-sistema@d2c97728916c2484f770a7a16a984c4c6bd42175`):

- `scripts/features/extract_multilayer_v3.py` (sha256 `5adbfbf4…`)
- `scripts/features/extract_multilayer_v2.py` (`7130edae…`)
- `configs/features/multilayer-v2.json` (28 variables: 9 L3, 8 L4, 11 L7; paso de 10 s; historias de 10, 30 y 60 s)

**Cambios exigidos antes de usarlos con datos de V2:**

1. Leer los PCAP y el EVE archivados por ejecución (`captura/archivar_v2.py`), no el anillo de V1. No acumular en `artifacts/linea-base` de V1.
2. Filtrar **por paquete** el tráfico de las entidades excluidas (gestión, bastión, sensor) antes de calcular las características de otras entidades. `--excluir` en V1 solo quitaba filas (ACLARACIONES §2.1).
3. Deduplicar el espejo: cada paquete entre VLAN aparece dos veces (VLAN 20 y VLAN 30), comprobado en T1.
4. Etiquetar las particiones por bloque desde el programa y descartar las ventanas que mezclan bloques o caen en el arranque en frío (60 s).
5. Inventariar todas las IP observadas, con la regla de inclusión y el motivo.
6. Pruebas: denominadores, cero frente a ausente, columnas constantes, paridad entre entrenamiento y operación, sin fugas de futuro.

**Bloqueante:** sin las tramas de tamaño completo en el espejo (PENDIENTES #12), las variables de bytes no se pueden reconstruir a partir de los originales.
