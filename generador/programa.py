"""Programa de una jornada de CyberFlow V2: carga, validación y factor por tiempo transcurrido.

Un programa sustituye al factor ambiental de V1 (``factor_horario(datetime.now())``):
la intensidad depende SOLO del tiempo transcurrido desde el inicio de la ejecución,
medido con un reloj monotónico. Una misma jornada produce las mismas distribuciones
programadas a cualquier hora del día y sin cambiar los relojes de las máquinas.

Solo biblioteca estándar (las VM del laboratorio no tienen salida a Internet).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PERFILES_V1 = ("ofimatica", "navegacion", "descargas", "aplicacion", "ligero", "erratico")

# Acciones implementadas por el generador. Cualquier otra en un programa es un error.
ACCIONES = frozenset({
    "web_pequena", "web_media", "web_grande", "https", "dns", "dns_inexistente",
    "api_ok", "api_post", "api_auth", "api_404", "api_500", "api_lento",
    "abandono", "puerto_cerrado", "ping",
})


class ProgramaInvalido(ValueError):
    pass


def huella(ruta: str | Path) -> str:
    return hashlib.sha256(Path(ruta).read_bytes()).hexdigest()


def cargar(ruta: str | Path) -> dict:
    with open(ruta, encoding="utf-8") as f:
        prog = json.load(f)
    validar(prog)
    return prog


def _tramos_contiguos(tramos: list[dict], inicio: float, fin: float, que: str) -> None:
    """Exige tramos ordenados, sin huecos ni solapes, que cubran [inicio, fin)."""
    if not tramos:
        raise ProgramaInvalido("%s: sin tramos" % que)
    cursor = inicio
    for t in tramos:
        a, b = t["inicio_s"], t["fin_s"]
        if a != cursor:
            raise ProgramaInvalido("%s: hueco o solape en %s (se esperaba inicio %s)"
                                   % (que, t.get("id"), cursor))
        if b <= a:
            raise ProgramaInvalido("%s: tramo %s vacío o invertido" % (que, t.get("id")))
        cursor = b
    if cursor != fin:
        raise ProgramaInvalido("%s: los tramos acaban en %s y la duración es %s" % (que, cursor, fin))


def validar(prog: dict) -> None:
    for clave in ("programa_id", "version", "duracion_s", "bloques", "fases", "perfiles", "destinos"):
        if clave not in prog:
            raise ProgramaInvalido("falta '%s'" % clave)
    dur = prog["duracion_s"]
    if not isinstance(dur, (int, float)) or dur <= 0:
        raise ProgramaInvalido("duracion_s debe ser positiva")
    _tramos_contiguos(prog["bloques"], 0, dur, "bloques")
    _tramos_contiguos(prog["fases"], 0, dur, "fases")
    nombres = set(prog["perfiles"])
    if not nombres <= set(PERFILES_V1):
        raise ProgramaInvalido("perfiles desconocidos: %s" % sorted(nombres - set(PERFILES_V1)))
    for nombre, p in prog["perfiles"].items():
        if p["ritmo_s"] <= 0:
            raise ProgramaInvalido("%s: ritmo_s debe ser positivo" % nombre)
        desconocidas = set(p["acciones"]) - ACCIONES
        if desconocidas:
            raise ProgramaInvalido("%s: acciones desconocidas %s" % (nombre, sorted(desconocidas)))
        if any(w <= 0 for w in p["acciones"].values()):
            raise ProgramaInvalido("%s: pesos deben ser positivos" % nombre)
    for b in prog["bloques"]:
        falta = nombres - set(b["semillas"])
        if falta:
            raise ProgramaInvalido("bloque %s sin semilla para %s" % (b["id"], sorted(falta)))
    semillas = [s for b in prog["bloques"] for s in b["semillas"].values()]
    if len(semillas) != len(set(semillas)):
        raise ProgramaInvalido("semillas repetidas entre perfiles o bloques")
    for f in prog["fases"]:
        if f["factor"] < 0:
            raise ProgramaInvalido("fase %s: factor negativo" % f["id"])
        for perfil, m in f.get("multiplicador_perfil", {}).items():
            if perfil not in nombres or m < 0:
                raise ProgramaInvalido("fase %s: multiplicador inválido para %s" % (f["id"], perfil))
    for pz in prog.get("pulsos", []):
        if not (0 <= pz["inicio_s"] < pz["fin_s"] <= dur) or pz["factor"] <= 0:
            raise ProgramaInvalido("pulso %s fuera de rango" % pz.get("id"))
        if not set(pz["perfiles"]) <= nombres:
            raise ProgramaInvalido("pulso %s con perfiles desconocidos" % pz.get("id"))
    for perfil, r in prog.get("rafagas", {}).items():
        if perfil not in nombres:
            raise ProgramaInvalido("ráfaga para perfil desconocido %s" % perfil)
        lo, hi = r["duracion_s"]
        if not (0 <= r["probabilidad_por_iteracion"] <= 1 and 0 < lo <= hi and r["factor"] > 0):
            raise ProgramaInvalido("ráfaga de %s con parámetros inválidos" % perfil)
    d = prog["destinos"]
    for clave in ("servidor", "puerto_http", "puerto_https", "dns_servidor", "dns_zona",
                  "dns_nombres", "dns_ip_esperada", "ping", "puertos_cerrados"):
        if clave not in d:
            raise ProgramaInvalido("destinos: falta '%s'" % clave)


def tramo_en(tramos: list[dict], t: float) -> dict:
    for tr in tramos:
        if tr["inicio_s"] <= t < tr["fin_s"]:
            return tr
    return tramos[-1]


def factor(prog: dict, perfil: str, t: float) -> tuple[float, dict, list[str]]:
    """Factor programado del perfil en el segundo ``t`` (sin la ráfaga, que es aleatoria).

    Devuelve (factor, fase, ids de pulsos activos). El factor final es
    fase.factor x multiplicador_global del perfil x multiplicador de fase x pulsos.
    Un factor 0 significa perfil en pausa.
    """
    fase = tramo_en(prog["fases"], t)
    f = fase["factor"] * prog["perfiles"][perfil].get("multiplicador", 1.0)
    f *= fase.get("multiplicador_perfil", {}).get(perfil, 1.0)
    pulsos = []
    for pz in prog.get("pulsos", []):
        if perfil in pz["perfiles"] and pz["inicio_s"] <= t < pz["fin_s"]:
            f *= pz["factor"]
            pulsos.append(pz["id"])
    return f, fase, pulsos


def proximo_cambio(prog: dict, t: float) -> float:
    """Primer instante > t en que cambia la fase, un pulso o el bloque."""
    bordes = [x for tr in prog["fases"] + prog["bloques"] for x in (tr["inicio_s"], tr["fin_s"])]
    bordes += [x for pz in prog.get("pulsos", []) for x in (pz["inicio_s"], pz["fin_s"])]
    futuros = [b for b in bordes if b > t]
    return min(futuros) if futuros else prog["duracion_s"]
