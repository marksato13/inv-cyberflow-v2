# Matriz: cambios de V2 frente a las observaciones de los revisores

Los identificadores siguen el orden de los puntos de `comment-review-481.docx`: el revisor 1 tiene 7 y el revisor 2 tiene 5. Coinciden con la hoja «Revisores» del plan.

**Ninguna observación queda cerrada con esta preparación.** Una observación solo se cierra cuando la prueba nueva se ejecuta, se analiza y se responde en la carta.

| Observación | Cambio o artefacto de V2 | Estado |
|---|---|---|
| **R1.1** Evaluación independiente; cronología de α, detector y reglas | Particiones fijadas antes de capturar (24/9/9, en los programas); congelado antes de E1–E3 (PROTOCOLO §2 y §9) | Diseño hecho; captura pendiente |
| **R1.2** Conciliar totales, exclusiones y clases de entidades | Recuento de las 45 IP de V1 con fichero y denominador (ACLARACIONES §2.6); población V2 = seis perfiles con inventario y reglas; fuga de `--excluir` demostrada y filtro por paquete previsto (PROTOCOLO §7) | Parcial: falta la extracción V2. Exclusiones separadas en guardas planificadas e incidentes, sin porcentaje (`BLOQUE1-POLITICA-CALIDAD.md` §6). Las 23 ventanas E3 de P2 eran un defecto de la cobertura en conexiones persistentes, corregido: 0 E3 por incidente en VD4 (REVISION-3 §2) |
| **R1.3** Etiquetas independientes de los episodios | Registro por transacción del tráfico legítimo, con identificadores (base para etiquetar desde los registros, no desde el detector) | Solo la parte legítima; ataques pendientes |
| **R1.4** Mismos plazos; durante y después | UTC + reloj monotónico, márgenes del archivador y desfases medidos (PROTOCOLO §6 y §8) | Preparado |
| **R1.5** FPR sin redondeo e incertidumbre | Bloques de 3 h con semillas como unidad de remuestreo posible | Pendiente (análisis) |
| **R1.6** Reproducibilidad: esquema, entorno, parámetros, scripts | Repositorio V2: programas con sha256, semillas, procedencia por fichero, manifiestos, comandos exactos; hallazgo del espejo que afecta a la reconstrucción | Parcial: espejo corregido (PENDIENTES #12). Bloque 1 con copias, extremo y DNS reproducibles desde una descarga limpia del repositorio y del release (`BLOQUE1-REVISION-2-2026-11-26.md` §1 y §10); PCAP de DC1 y extracto de rx_dropped publicados; pérdida de gestión localizada en el switch y acotada por la precisión de las lecturas, con la causa interna pendiente (§9; REVISION-3 §6). 3.ª revisión (`BLOQUE1-REVISION-3-2026-11-26.md`): entradas mínimas saneadas de VD2–VD4 y extracto de P2 que **reproducen en el portátil** el dictamen, C7/C9–C13 y los casos (`extractos-539c48e/`); lo no compartible está identificado con la conclusión que queda sin revisión independiente. Sin cerrar: T1–E3 `no_aprobada` con el criterio nuevo; deduplicación, relojes, rotación y supervisión prolongada (bloques 3–4) |
| **R1.7** Definir la transacción fallida por perfil | Clases `ok` / `error_intencional` / `variacion_servidor` / `fallo_inesperado`, con lo esperado frente a lo observado; continuidad ≠ ausencia de errores ≠ éxito (ACLARACIONES §2.4) | Implementado y comprobado en T1 y T2. Los eventos DNS sin transacción son sondas del preflight, ahora registradas e identificadas por ejecución, clave completa e instante; las sondas se hacen antes del periodo útil (margen 240 s) y el preflight se registra aparte de la generación (`BLOQUE1-REVISION-2-2026-11-26.md` §2–§4). La consulta de T1 de las 06:25:16 queda incierta |
| **R2.1** Aporte del IF en datos intactos | Captura nueva y desarrollo separado | Pendiente |
| **R2.2** Todos los episodios como denominador | Reglas de interrupción y repetición fijadas antes de capturar (PROTOCOLO §8) | Reglas fijadas; episodios pendientes |
| **R2.3** Controles con la respuesta desactivada | Motor V1 en sombra comprobado; aislamiento de V1 | Pendiente (campaña B) |
| **R2.4** Posicionamiento frente a [11] y [26] | — | Pendiente (manuscrito) |
| **R2.5** Variación por perfil y periodo, carga legítima, deriva | Siete jornadas con patrones distintos (habitual, énfasis, pulsos, reducida), con fase y bloque en cada transacción | Diseño hecho; captura pendiente |
| **ED.3** Publicar el código | Este repositorio público; capturas privadas con hashes | En curso |
