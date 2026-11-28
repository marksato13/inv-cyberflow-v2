# Bloque 2: contraste de perfiles y jornadas (28-nov-2026)

## Fuentes y criterio de paso

Fuente primaria: copia sin cambios de `CyberFlow_V2_Perfiles_y_Jornadas_49h.xlsx` (SHA-256 `3bdbc1f29c92578a38cacf75daf394f35e6a3f9026e70649c431b3f5952716e4`) en `evidencias/bloque2/`, hojas «1 Fuentes», «2 Perfiles» y «3 Jornadas». Se contrastó con `CONTRATO-GENERADOR-49H.md` v3.0.0, `programas/captura-49h.json`, el generador y servidor v3, las pruebas existentes y los registros T1/T2 publicados. El Excel plantea cargas sintéticas, **no** acredita ejecución ni realismo. Las fuentes S2–S6 respaldan parámetros o antecedentes específicos; P5/P6 y las 49 h son decisiones del diseño D1.

Para pasar la **preparación** de B2 se exigen: coincidencia de la configuración con el Excel o una adaptación documentada; regeneración y validación de los programas; pruebas dirigidas de comandos, respuestas, pausas, semillas, niveles y transiciones; y evidencia de ejecución corta del código vigente. Este paso no equivale a aprobar el piloto final ni las siete jornadas de 7 h.

Comandos ejecutados (sin generar tráfico nuevo):

```text
python -X utf8 tests/contrastar_excel_bloque2.py --salida evidencias/bloque2/contraste-excel-programa.json
python programas/generar_programas.py --comprobar
python -X utf8 generador/clientes_lab_v2.py --programa programas/captura-49h.json --validar
python -X utf8 tests/auditar_bloque2_publicado.py --salida evidencias/bloque2/auditoria-t1-t2.json
python -m pytest -q -p no:cacheprovider tests/test_distribuciones.py tests/test_generador_v3.py tests/test_servidor.py
```

El contraste Excel/programa dio **15 coincidencias**, sin diferencias. La regeneración byte a byte y la validación del programa de 176 400 s terminaron rc 0. Las pruebas de distribuciones, generador y servidor dieron 25 pruebas y 10 subpruebas aprobadas antes del ajuste del piloto. Tras el ajuste, `test_generador_v3.py` dio 13 aprobadas, incluido el nuevo caso que simula seis perfiles en 1800 s. Los registros completos se conservan en `evidencias/bloque2/`.

## Matriz requisito → configuración → evidencia → resultado → pendiente

| Requisito | Configuración vigente | Evidencia | Resultado | Pendiente |
|---|---|---|---|---|
| P1, consulta web y DNS | 10.10.20.21; DNS A a DC1, GET `/contenido/<n>` HTTP a srv-dmz; H1; pausa Exp(30 s), conexión nueva | Excel «2 Perfiles» fila 6; contrato §2–§6; `auditoria-t1-t2.json`; T1/T2 originales | Configuración coincide; 22/100 intercambios T1/T2 de P1, todos `ok` | Medir frecuencia y bytes en el piloto final y las 49 h |
| P2, navegación multirrecurso | 10.10.20.22; DNS por página, H1 principal, parsing Exp(0,13 s), H3 secundarios H2, una conexión persistente por página; HTTP/HTTPS alternos por bloque; lectura Exp(30 s) | Excel fila 7; contrato §2, §5; pruebas `test_p2_alterna_y_reutiliza`, cliente persistente; auditoría T1/T2 | Adaptación de protocolo declarada; 3/34 páginas T1/T2 con conexión y alternancia verificadas, 4/93 peticiones HTTP y 3/92 HTTPS | Visibilidad L7 y persistencia bajo la duración/carga del piloto final |
| P3, archivos | 10.10.20.23; GET HTTP `/contenido/<n>?tipo=archivo`; F1 lognormal μ 14,45, σ 0,35, 0<n<5 MB; pausa Exp(180 s) | Excel fila 8 y F1 fila 21; contrato §2–§4; prueba de tamaños exactos; T1/T2 | Configuración coincide; 2/8 intercambios cortos de P3 `ok`, tamaño y cuerpo verificados | La muestra corta no demuestra ajuste estadístico ni capacidad sostenida del SPAN |
| P4, aplicación | 10.10.20.24; DNS por secuencia, GET `/app/consulta?ref=`, POST `/app/envio`, GET consulta; pausas Exp(10 s); 200/201/200, consulta 512 B, POST 200–8000 B | Excel fila 9; contrato §3; pruebas de secuencia y respuestas; T1/T2 | Rutas y respuestas que el Excel dejaba abiertas están fijadas; 34/167 intercambios `ok` | Conciliación completa de una ejecución piloto final y distribución observada |
| P5, frecuencia baja | 10.10.20.25; acciones H1 de P1; pausa Exp(90 s) | Excel fila 10; contrato §2; T1/T2 | 6/14 intercambios `ok`; decisión experimental D1 registrada | Medir frecuencia en periodo largo; no representar como promedio real |
| P6, actividad intermitente | 10.10.20.26; H1; ON 60 s/OFF 120 s, Exp(10 s) en ON; acciones iniciadas en ON pueden acabar en OFF | Excel fila 11; contrato §2; prueba `test_p6_on_off_y_cruce`; auditoría T1/T2 | 10/90 intercambios `ok`; ningún DNS empezó en OFF, cruce probado en simulación | Medir periodos OFF y acciones que cruzan en piloto final |
| Destinos y respuestas | DC1 10.10.10.20:53, seis nombres `cf-v2.lab` → 10.10.30.10; HTTP 80, HTTPS 443; `/contenido` 200 y bytes exactos; `/app/consulta` 200/512 B; `/app/envio` 201/SHA-256 | Excel filas 27–30; contrato §3, §6; `test_servidor.py`; auditoría T1/T2 | Definido y probado en servidor local y registros cortos; preflight y conciliación histórica disponibles | Reconfirmar servicios y respuestas en preflight del piloto final |
| Pausas y distribuciones | H1/H2 lognormales aritméticas, H3 Pareto transformada, F1 lognormal de ln; pausas Exp(media/factor), parsing sin factor | Excel filas 18–21, 20–22; contrato §4 y §7; `test_distribuciones.py`, `test_media_pausas_por_nivel` | Parámetros y muestreo dirigidos aprobados | Evaluar ajuste y volumen observados con muestra suficiente; las muestras cortas no lo prueban |
| Semillas y reloj | Tres flujos por perfil/bloque (`espera`, `contenido`, `red`), SHA-256 de maestro/programa/bloque/perfil/flujo, tiempo monotónico; resiembra por bloque | Excel fila 31; contrato §8; `programa.py`; prueba de resiembra; auditoría de semillas en T1/T2 | Derivación, unicidad y hashes de programas dirigidos comprobados | Verificar las semillas registradas de los 14 bloques en el piloto y la captura futura |
| J1/J5 y J2/J3 | J1/J5 todos base; J2 P1/P2 aumentado; J3 P3/P4 aumentado; dos bloques por jornada | Excel «3 Jornadas» filas 6–8,10; contrato §7; prueba de ventanas exactas | Calendario configurado y probado sin ejecutarlo durante 7 h | Observar niveles, volumen y continuidad reales |
| J4 | Siete ráfagas de cinco min antes de cada hora; P1/P2/P4 aumentado | Excel fila 9; `test_ventanas_exactas_de_las_siete_jornadas` | Siete ventanas exactas en programa; T2 solo ejercita una ráfaga abreviada | Ejecutar patrón de siete horas y verificar las siete ocurrencias |
| J6/J7 | J6 reducido con 4 periodos base de 15 min; J7 reducido con 6 ráfagas base de 3 min, en cada bloque según Excel | Excel filas 11–12; prueba de ventanas exactas | Ventanas y perfiles coinciden; T2 ejercita niveles y transiciones abreviadas | Observar las 4 y 6 ventanas en duración completa |
| Particiones y transiciones | 14 bloques de 3,5 h; 28/10,5/10,5 h entrenamiento/calibración/desarrollo; pausas cortadas al borde, acción etiquetada por inicio | Excel «3 Jornadas» filas 29–31; contrato §7–§8; `test_corte_y_resiembra`, auditoría T2 | Configuración y cortes dirigidos comprobados | Verificar cronología real, guardas y separación durante el piloto y las 49 h |
| Piloto abreviado | `piloto-30min.json`, ahora 1800 s: J1 360 s, J2–J7 240 s; 14 bloques y siete patrones | Prueba nueva `test_piloto_abreviado_dura_30_minutos_y_cubre_siete_patrones` | Corregida discrepancia nombre/duración de 1680 s; seis perfiles completan simulación | Piloto final real no iniciado; criterios C1–C13 aún pendientes |

## Reutilización y límites de T1/T2

Los registros publicados de T1 (`V2-T1-20261125T062528Z`) y T2 (`V2-T2-20261125T070500Z`) llevan respectivamente los SHA-256 `d93f81a8…` y `3089fc53…`, iguales a los programas dirigidos vigentes. La auditoría lee los originales, no copias modificadas: **84/84** y **598/598** intercambios, seis perfiles, asignación de jornada/bloque/nivel/factor, origen, destino, códigos y cuerpos esperados, DNS, ON de P6, conexiones P2 y alternancia, con 0 discrepancias. T1 ejercita base; T2, reducido/base/aumentado. Las pruebas de servidor y distribuciones complementan lo que esas duraciones cortas no permiten estimar. La captura de las jornadas definitivas sigue pendiente.

El primer intento de la auditoría nueva falló por un corchete omitido en el propio script antes de leer T1/T2; se corrigió sin relajar las condiciones y se conservó su diagnóstico. El primer pase dirigido aprobado corresponde al programa del piloto de 1680 s; después se corrigió a 1800 s y se repitieron las pruebas afectadas. El cambio del piloto no altera `captura-49h.json` ni los programas T1/T2.

## Discrepancias documentales corregidas y estado

`PROTOCOLO.md`, README, comentario de `lanzar_v2.sh` y `PENDIENTES.md` aún mencionaban 42 h, jornadas de 6 h, fases/multiplicadores de V1, POST aleatorio de V1 y una guarda de 60 s. Se actualizaron hacia el contrato v3 y la guarda de estado de 230 s, conservando los informes históricos. La sección de criterios del piloto se adaptó a jornadas/niveles/semillas V3; los criterios de captura C7–C13 no se dan por superados.

**Resultado del Bloque 2 de preparación:** configuración contrastada y pruebas dirigidas superadas. Queda pendiente la verificación integrada y prolongada. Esta distinción permite continuar con el despliegue preparatorio de Bloque 4 sin iniciar el piloto ni las 49 h.
