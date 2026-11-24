# Programas de las jornadas

Los JSON se generan con `generar_programas.py`, y `--comprobar` verifica que regenerarlos produce exactamente los mismos bytes. Los sha256 están en `manifiestos/`.

**Común a J1–J7:**

- 21 600 s, en dos bloques de 3 h con su partición.
- En cada bloque: 60 min ×1,00, 60 min ×0,55 («pausa») y 60 min ×0,90.
- Perfiles, ritmos y pesos de V1; ráfagas de errático de V1 (p = 0,02 por iteración, 20–90 s, ×6).
- Destinos: 10.10.30.10 (80 y 443) y DNS en 10.10.10.20, zona `cf-v2.lab`.
- Semillas fijas, una por bloque y perfil, distintas en todo el calendario.

| Jornada | Patrón | Mezcla y multiplicadores | Pulsos | Particiones B1 / B2 | Procedencia |
|---|---|---|---|---|---|
| J1 | Habitual con pausas | Pesos V1, ×1 | — | entrenamiento / entrenamiento | V1 + PLAN |
| J2 | Más navegación y ofimática | Ofimática y navegación ×1,25 | — | entrenamiento / calibración | PLAN (×1,25 propuesto) |
| J3 | Más descargas y aplicación | Descargas y aplicación ×1,25 | — | entrenamiento / desarrollo | PLAN (×1,25 propuesto) |
| J4 | Habitual con ráfagas legítimas programadas | ×1 | Últimos 5 min de cada hora, ×1,5 en ofimática, navegación y aplicación | entrenamiento / calibración | PLAN (×1,5 propuesto) |
| J5 | Mezcla habitual con secuencias nuevas | Como J1, con otras semillas | — | entrenamiento / desarrollo | PLAN |
| J6 | Reducida con periodos activos | Fases ×0,30 | 4 periodos de 15 min (2 por bloque) a nivel base (×1/0,30) | entrenamiento / calibración | V1 (0,3) + PLAN + NUEVA |
| J7 | Reducida con ráfagas ocasionales | Fases ×0,30 | 6 pulsos de 3 min ×4 (3 por bloque) en perfiles alternos | entrenamiento / desarrollo | V1 (0,3) + PLAN + NUEVA |
| P0 | Piloto de 30 min | Ofimática y navegación ×1,25 | A1 (×1/0,30) y P1 (×1,5) | piloto | NUEVA (sin métricas) |
| PRUEBA | Prueba corta de 4 min | ×1 | P1 (×1,5) | prueba | NUEVA (sin métricas) |

**Fin de cada jornada:** al cumplirse `duracion_s` no se inician acciones nuevas; la acción en curso termina y se registra.

Los multiplicadores ×1,25, ×1,5 y ×4 y los periodos activos de J6 y J7 son **propuestas a validar** en el piloto (capacidad y composición). No se ajustan con métricas del detector.
