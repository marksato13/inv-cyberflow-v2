#!/usr/bin/env python3
"""Genera los programas JSON de las siete jornadas, el piloto de 30 min y la prueba corta.

Los JSON generados son los artefactos que se congelan (con su sha256 en el manifiesto);
este script documenta cómo se derivaron. Volver a ejecutarlo debe producir bytes idénticos
(``--comprobar`` lo verifica).

Procedencia de cada parámetro (campo ``procedencia`` de cada programa):
  V1      = scripts/laboratorio/clientes_lab.py en inv-cyberflow-sistema@d2c97728916c2484f770a7a16a984c4c6bd42175
  PLAN    = Plan_nueva_evaluacion_CyberFlow.xlsx v0.2 (hojas Calendario y Patrones): propuesta, no estándar
  NUEVA   = decisión nueva de V2, a validar en el piloto
  PILOTO  = ajuste derivado del piloto (ninguno todavía)
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
SEMILLA_MAESTRA = "cyberflow-v2|programas|2026-11-24"

ORIGEN = {"ofimatica": "10.10.20.21", "navegacion": "10.10.20.22", "descargas": "10.10.20.23",
          "aplicacion": "10.10.20.24", "ligero": "10.10.20.25", "erratico": "10.10.20.26"}

# V1: ritmo (s) y pesos relativos, sin cambios.
PERFILES_V1 = {
    "ofimatica": (3.0, {"web_pequena": 50, "web_media": 20, "dns": 25, "api_ok": 15,
                        "api_auth": 3, "api_404": 4, "https": 20, "ping": 5}),
    "navegacion": (1.5, {"web_pequena": 40, "web_grande": 25, "https": 35, "dns": 30,
                         "dns_inexistente": 4, "api_ok": 10, "abandono": 6}),
    "descargas": (8.0, {"web_grande": 60, "web_media": 25, "https": 10, "dns": 5}),
    "aplicacion": (2.0, {"api_ok": 45, "api_post": 25, "api_500": 6, "api_lento": 8,
                         "https": 10, "dns": 10}),
    "ligero": (12.0, {"dns": 40, "api_ok": 25, "web_pequena": 20, "ping": 15}),
    "erratico": (5.0, {"web_pequena": 25, "web_grande": 15, "dns": 20, "api_ok": 15,
                       "puerto_cerrado": 10, "abandono": 8, "ping": 7}),
}

DESTINOS = {
    "servidor": "10.10.30.10", "puerto_http": 80, "puerto_https": 443,
    "dns_servidor": "10.10.10.20", "dns_zona": "cf-v2.lab",
    "dns_nombres": ["portal", "intranet", "correo", "wiki", "erp", "archivos"],
    "dns_ip_esperada": "10.10.30.10", "ping": "10.10.30.10",
    "puertos_cerrados": [8081, 9001, 4444, 31337],
}
TAMANOS = {
    "web_pequena": ["/", "/estatico/4k", "/estatico/16k"],
    "web_media": ["/estatico/64k", "/estatico/128k", "/estatico/256k"],
    "web_grande": ["/estatico/1024k", "/estatico/2048k", "/estatico/4096k"],
    "https": ["/", "/api/ok", "/estatico/32k"],
    "api_post_bytes": [200, 8000],
    "abandono": "/estatico/2048k",
}
RAFAGAS_V1 = {"erratico": {"probabilidad_por_iteracion": 0.02, "duracion_s": [20, 90], "factor": 6.0}}

PROCEDENCIA_COMUN = {
    "perfiles.*.ritmo_s": "V1 (PERFILES[*]['ritmo'])",
    "perfiles.*.acciones": "V1 (PERFILES[*]['acciones'], pesos relativos)",
    "perfiles.*.origen": "V1 (clientes_config.py: --base 10.10.20.21 + índice)",
    "espera": "V1: expovariate(1/max(ritmo/factor, 0.05)); piso sobre la media. NUEVA: la espera se corta en cada cambio de fase/pulso y se vuelve a sortear",
    "rafagas.erratico": "V1 (p=0.02 por iteración, 20-90 s, x6)",
    "tamanos": "V1 (rutas y tamaños de cada acción)",
    "destinos.servidor/puertos/ping/puertos_cerrados/dns_servidor": "V1",
    "destinos.dns_zona/dns_nombres": "NUEVA: zona controlada cf-v2.lab en DC1 (V1 usaba nombres de otro dominio que DC1 no servía; NXDOMAIN nunca ocurría)",
    "duracion_s/bloques/fases": "PLAN (Calendario: 2 bloques de 3 h por jornada) + NUEVA (tiempo transcurrido monotónico)",
    "fases.factor 1.00/0.55/0.90": "V1 (factor_horario: 08-13 1.0, 13-15 0.55, 15-19 0.9) reordenado por PLAN (Patrones)",
    "bloques.semillas": "NUEVA: sha256(SEMILLA_MAESTRA|programa|bloque|perfil), fijadas antes de capturar",
    "fin": "NUEVA: al cumplirse duracion_s no se inician acciones; la acción en curso termina y se registra",
}

PARTICION = {  # PLAN, hoja Calendario
    "J1": ("entrenamiento", "entrenamiento"), "J2": ("entrenamiento", "calibracion"),
    "J3": ("entrenamiento", "desarrollo"), "J4": ("entrenamiento", "calibracion"),
    "J5": ("entrenamiento", "desarrollo"), "J6": ("entrenamiento", "calibracion"),
    "J7": ("entrenamiento", "desarrollo"),
}


def semilla(prog_id: str, bloque: str, perfil: str) -> int:
    h = hashlib.sha256(("%s|%s|%s|%s" % (SEMILLA_MAESTRA, prog_id, bloque, perfil)).encode()).hexdigest()
    return int(h[:12], 16)


def perfiles(mult: dict | None = None) -> dict:
    mult = mult or {}
    return {p: {"origen": ORIGEN[p], "ritmo_s": r, "acciones": dict(a), "multiplicador": mult.get(p, 1.0)}
            for p, (r, a) in PERFILES_V1.items()}


def bloques(prog_id: str, tramos: list[tuple[str, int, int, str]]) -> list[dict]:
    return [{"id": b, "inicio_s": a, "fin_s": z, "particion": part,
             "semillas": {p: semilla(prog_id, b, p) for p in PERFILES_V1}} for b, a, z, part in tramos]


def fases_base(global_: float = 1.0) -> list[dict]:
    """Dos bloques de 3 h; en cada uno 60 min x1.00, 60 min x0.55, 60 min x0.90 (PLAN)."""
    out = []
    for b in (0, 1):
        for i, (nombre, f) in enumerate((("alta", 1.00), ("pausa", 0.55), ("media", 0.90))):
            a = b * 10800 + i * 3600
            out.append({"id": "B%d-%s" % (b + 1, nombre), "inicio_s": a, "fin_s": a + 3600,
                        "factor": round(f * global_, 6)})
    return out


def jornada(jid: str, titulo: str, descripcion: str, mult=None, global_=1.0, pulsos=(), extra_proc=None) -> dict:
    pid = "V2-%s" % jid
    p1, p2 = PARTICION[jid]
    prog = {
        "programa_id": pid, "jornada_id": jid, "version": "1.0.0", "titulo": titulo,
        "descripcion": descripcion, "duracion_s": 21600,
        "bloques": bloques(pid, [("B1", 0, 10800, p1), ("B2", 10800, 21600, p2)]),
        "fases": fases_base(global_), "pulsos": list(pulsos), "perfiles": perfiles(mult),
        "rafagas": copy.deepcopy(RAFAGAS_V1), "destinos": copy.deepcopy(DESTINOS),
        "tamanos": copy.deepcopy(TAMANOS),
        "procedencia": dict(PROCEDENCIA_COMUN, **(extra_proc or {})),
        "uso": "captura legítima de desarrollo (sesión sintética parcial; no representa una semana de 168 h)",
    }
    return prog


def pulsos_ultimos_5min(perfiles_: list[str], factor: float) -> list[dict]:
    return [{"id": "P%d" % (h + 1), "inicio_s": h * 3600 + 3300, "fin_s": (h + 1) * 3600,
             "factor": factor, "perfiles": perfiles_} for h in range(6)]


def pulsos_lista(prefijo: str, inicios: list[int], dur: int, factor: float, perfiles_: list[str]) -> list[dict]:
    return [{"id": "%s%d" % (prefijo, i + 1), "inicio_s": a, "fin_s": a + dur, "factor": factor,
             "perfiles": perfiles_} for i, a in enumerate(inicios)]


TODOS = list(PERFILES_V1)
RESTITUYE = round(1 / 0.30, 6)


def todas() -> dict[str, dict]:
    p = {}
    p["J1"] = jornada("J1", "Habitual con pausas",
                      "Seis perfiles con pesos V1 y multiplicador 1. La fase 'pausa' (x0.55) reproduce la pausa de V1.")
    p["J2"] = jornada("J2", "Más navegación y ofimática",
                      "Seis perfiles; ofimática y navegación x1.25.", mult={"ofimatica": 1.25, "navegacion": 1.25},
                      extra_proc={"perfiles.ofimatica/navegacion.multiplicador": "PLAN (propuesta 1.25, a validar en piloto)"})
    p["J3"] = jornada("J3", "Más descargas y aplicación",
                      "Seis perfiles; descargas y aplicación x1.25.", mult={"descargas": 1.25, "aplicacion": 1.25},
                      extra_proc={"perfiles.descargas/aplicacion.multiplicador": "PLAN (propuesta 1.25, a validar en piloto)"})
    p["J4"] = jornada("J4", "Habitual con ráfagas legítimas programadas",
                      "Seis perfiles; últimos 5 min de cada hora x1.5 en ofimática, navegación y aplicación.",
                      pulsos=pulsos_ultimos_5min(["ofimatica", "navegacion", "aplicacion"], 1.5),
                      extra_proc={"pulsos": "PLAN (propuesta: últimos 5 min de cada hora x1.5)"})
    p["J5"] = jornada("J5", "Mezcla habitual con secuencias nuevas",
                      "Misma mezcla que J1 con otras semillas: no reutiliza la secuencia de eventos.")
    p["J6"] = jornada("J6", "Actividad reducida con periodos activos",
                      "Fases base x0.30; dos periodos activos de 15 min por bloque devuelven el nivel base (x1/0.30).",
                      global_=0.30,
                      pulsos=pulsos_lista("A", [1800, 7200, 12600, 18000], 900, RESTITUYE, TODOS),
                      extra_proc={"fases.global 0.30": "V1 (factor de fin de semana 0.3) aplicado por PLAN",
                                  "pulsos (periodos activos)": "NUEVA: 2 x 15 min por bloque a nivel base; a validar en piloto"})
    p["J7"] = jornada("J7", "Actividad reducida con ráfagas ocasionales",
                      "Fases base x0.30; ráfagas V1 de errático y tres pulsos breves (3 min x4) por bloque en perfiles alternos.",
                      global_=0.30,
                      pulsos=(pulsos_lista("Q", [2400, 6000, 9300], 180, 4.0, ["ofimatica", "navegacion", "ligero"])
                              + pulsos_lista("R", [12900, 16500, 19800], 180, 4.0, ["descargas", "aplicacion", "erratico"])),
                      extra_proc={"fases.global 0.30": "V1 (factor de fin de semana 0.3) aplicado por PLAN",
                                  "pulsos (ráfagas ocasionales)": "NUEVA: 3 pulsos de 3 min x4 por bloque, sin acciones nuevas; a validar en piloto"})
    p["P0"] = piloto()
    p["PRUEBA-CORTA"] = prueba_corta()
    return p


def piloto() -> dict:
    """30 min con los seis perfiles y todos los tipos de cambio que usan las jornadas."""
    pid = "V2-P0"
    f = [("F1-alta", 0, 300, 1.00), ("F2-pausa", 300, 600, 0.55), ("F3-media", 600, 900, 0.90),
         ("F4-parada", 900, 1080, 0.0), ("F5-reducida", 1080, 1500, 0.30), ("F6-alta", 1500, 1800, 1.00)]
    return {
        "programa_id": pid, "jornada_id": "P0", "version": "1.0.0",
        "titulo": "Piloto de instrumentación (30 min)",
        "descripcion": "Seis perfiles; cambios de fase, pausa total, reducida, pulso y cambio de bloque/semilla. Sin uso en métricas.",
        "duracion_s": 1800,
        "bloques": bloques(pid, [("B1", 0, 900, "piloto"), ("B2", 900, 1800, "piloto")]),
        "fases": [{"id": i, "inicio_s": a, "fin_s": z, "factor": x} for i, a, z, x in f],
        "pulsos": pulsos_lista("P", [1320], 120, 1.5, ["ofimatica", "navegacion", "aplicacion"])
                  + pulsos_lista("A", [1200], 60, RESTITUYE, TODOS),
        "perfiles": perfiles({"ofimatica": 1.25, "navegacion": 1.25}),
        "rafagas": copy.deepcopy(RAFAGAS_V1), "destinos": copy.deepcopy(DESTINOS), "tamanos": copy.deepcopy(TAMANOS),
        "procedencia": dict(PROCEDENCIA_COMUN, **{"fases/pulsos": "NUEVA: comprimido para comprobar cada tipo de cambio"}),
        "uso": "piloto de instrumentación; prohibido en métricas, entrenamiento o calibración",
    }


def prueba_corta() -> dict:
    """4 min para las pruebas técnicas cortas de preparación (no es el piloto)."""
    pid = "V2-PRUEBA-CORTA"
    f = [("F1-alta", 0, 60, 1.0), ("F2-parada", 60, 90, 0.0), ("F3-pausa", 90, 150, 0.55), ("F4-alta", 150, 240, 1.0)]
    return {
        "programa_id": pid, "jornada_id": "PRUEBA", "version": "1.0.0",
        "titulo": "Prueba técnica corta (4 min)",
        "descripcion": "Comprueba acciones, registro, pausa, cambio de bloque y parada. Sin uso en métricas.",
        "duracion_s": 240,
        "bloques": bloques(pid, [("B1", 0, 120, "prueba"), ("B2", 120, 240, "prueba")]),
        "fases": [{"id": i, "inicio_s": a, "fin_s": z, "factor": x} for i, a, z, x in f],
        "pulsos": pulsos_lista("P", [180], 30, 1.5, ["ofimatica", "navegacion", "aplicacion"]),
        "perfiles": perfiles(), "rafagas": copy.deepcopy(RAFAGAS_V1),
        "destinos": copy.deepcopy(DESTINOS), "tamanos": copy.deepcopy(TAMANOS),
        "procedencia": dict(PROCEDENCIA_COMUN), "uso": "prueba técnica; prohibido en métricas",
    }


def serializar(prog: dict) -> bytes:
    return (json.dumps(prog, ensure_ascii=False, indent=1, sort_keys=False) + "\n").encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--comprobar", action="store_true", help="falla si algún JSON en disco difiere")
    a = ap.parse_args()
    sys.path.insert(0, str(AQUI.parent / "generador"))
    import programa as prg
    nombres = {"P0": "piloto-30min.json", "PRUEBA-CORTA": "prueba-corta.json"}
    distintos = 0
    for k, prog in todas().items():
        prg.validar(prog)
        ruta = AQUI / nombres.get(k, "jornada-%s.json" % k)
        datos = serializar(prog)
        if a.comprobar:
            if not ruta.exists() or ruta.read_bytes() != datos:
                print("DIFIERE", ruta.name)
                distintos += 1
        else:
            ruta.write_bytes(datos)
        print("%-24s %s" % (ruta.name, hashlib.sha256(datos).hexdigest()))
    return 1 if distintos else 0


if __name__ == "__main__":
    raise SystemExit(main())
