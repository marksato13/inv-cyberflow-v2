# Programas v3 de 49 h

El contrato normativo es docs/CONTRATO-GENERADOR-49H.md.
Ejecute python programas/generar_programas.py para regenerar los JSON y
python programas/generar_programas.py --comprobar para verificar sus bytes.

| Programa | ID | Duración | Uso |
|---|---|---:|---|
| captura-49h.json | V2-C49 | 176 400 s | Siete jornadas de 7 h, 14 bloques de 3,5 h |
| piloto-30min.json | V2-P49 | 1 680 s | Siete jornadas abreviadas de 240 s |
| prueba-perfiles-aislados.json | V2-T1 | 1 800 s | Un perfil activo en cada tramo de 300 s |
| prueba-niveles-transiciones.json | V2-T2 | 1 440 s | Niveles, bordes internos y ráfagas |

Los bloques tienen tres semillas independientes por perfil: espera, contenido y red.
La captura destina 28 h a entrenamiento, 10,5 h a calibración y 10,5 h a desarrollo.
Los programas anteriores de 42 h y las jornadas independientes se retiraron; permanecen
en el historial de git.
