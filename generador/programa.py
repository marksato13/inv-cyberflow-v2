"""Validación y consulta del calendario v3."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PERFILES = tuple("P%d" % n for n in range(1, 7))
FLUJOS = ("espera", "contenido", "red")
NIVELES = ("reducido", "base", "aumentado", "inactivo")


class ProgramaInvalido(ValueError):
    pass


def huella(ruta: str | Path) -> str:
    return hashlib.sha256(Path(ruta).read_bytes()).hexdigest()


def cargar(ruta: str | Path) -> dict:
    prog = json.loads(Path(ruta).read_text(encoding="utf-8"))
    validar(prog)
    return prog


def _contiguos(tramos, fin, nombre):
    if not tramos:
        raise ProgramaInvalido("%s vacío" % nombre)
    cursor = 0
    ids = set()
    for tramo in tramos:
        if tramo["id"] in ids or tramo["inicio_s"] != cursor or tramo["fin_s"] <= cursor:
            raise ProgramaInvalido("%s con id repetido, hueco o solape" % nombre)
        ids.add(tramo["id"])
        cursor = tramo["fin_s"]
    if cursor != fin:
        raise ProgramaInvalido("%s no cubre la duración" % nombre)


def validar(prog: dict) -> None:
    obligatorios = ("programa_id", "version", "tipo", "duracion_s", "jornadas",
                    "bloques", "niveles", "factores", "perfiles", "distribuciones",
                    "destinos", "procedencia", "equivalencia")
    for clave in obligatorios:
        if clave not in prog:
            raise ProgramaInvalido("falta %s" % clave)
    if prog["version"] != "3.0.0" or prog["tipo"] not in ("captura", "piloto", "prueba"):
        raise ProgramaInvalido("versión o tipo inválido")
    dur = prog["duracion_s"]
    if not isinstance(dur, (int, float)) or dur <= 0:
        raise ProgramaInvalido("duración inválida")
    for clave in ("jornadas", "bloques", "niveles"):
        _contiguos(prog[clave], dur, clave)
    factores = prog["factores"]
    if set(factores) != ({"reducido", "base", "aumentado"} |
                        ({"inactivo"} if prog["tipo"] == "prueba" else set())):
        raise ProgramaInvalido("factores desconocidos")
    if any(abs(factores[k] - v) > 1e-12 for k, v in
           {"reducido": 1 / 3, "base": 1, "aumentado": 2}.items()):
        raise ProgramaInvalido("factor incorrecto")
    if "inactivo" in factores and factores["inactivo"] != 0:
        raise ProgramaInvalido("factor inactivo incorrecto")
    if set(prog["perfiles"]) != set(PERFILES):
        raise ProgramaInvalido("se requieren P1–P6")
    modelos = {"P1": ("consulta", 30), "P2": ("navegacion", 30),
               "P3": ("archivo", 180), "P4": ("transaccional", 10),
               "P5": ("consulta", 90), "P6": ("intermitente", 10)}
    for nombre, perfil in prog["perfiles"].items():
        if (perfil.get("modelo"), perfil.get("media_espera_s")) != modelos[nombre] or not perfil.get("origen"):
            raise ProgramaInvalido("perfil %s inválido" % nombre)
    p6 = prog["perfiles"]["P6"]
    if (p6.get("on_s"), p6.get("off_s"), p6["media_espera_s"]) != (60, 120, 10):
        raise ProgramaInvalido("P6 inválido")
    if (prog["perfiles"]["P2"].get("parsing_media_s") != 0.13 or
            prog["perfiles"]["P2"].get("alternancia") != ["http", "https"]):
        raise ProgramaInvalido("P2 inválido")
    jornadas = {j["id"]: j for j in prog["jornadas"]}
    if len(jornadas) != len(prog["jornadas"]) or any(
            not j.get("titulo") or not j.get("patron") for j in prog["jornadas"]):
        raise ProgramaInvalido("jornadas inválidas")
    if prog["tipo"] in ("piloto", "prueba") and set(prog["equivalencia"]) != set(jornadas):
        raise ProgramaInvalido("falta equivalencia de jornadas")
    semillas = []
    for b in prog["bloques"]:
        j = jornadas.get(b["jornada"])
        if not j or not (j["inicio_s"] <= b["inicio_s"] < b["fin_s"] <= j["fin_s"]):
            raise ProgramaInvalido("bloque fuera de jornada")
        if b.get("particion") not in ("entrenamiento", "calibracion", "desarrollo", "piloto", "prueba"):
            raise ProgramaInvalido("partición desconocida")
        if set(b["semillas"]) != set(PERFILES):
            raise ProgramaInvalido("faltan semillas")
        for perfil in PERFILES:
            s = b["semillas"][perfil]
            if set(s) != set(FLUJOS) or any(not isinstance(s[f], int) or s[f] < 0 for f in FLUJOS):
                raise ProgramaInvalido("semillas inválidas")
            semillas.extend(s.values())
    if len(semillas) != len(set(semillas)):
        raise ProgramaInvalido("semillas repetidas")
    for n in prog["niveles"]:
        if set(n["perfiles"]) != set(PERFILES):
            raise ProgramaInvalido("niveles sin seis perfiles")
        if any(v not in factores for v in n["perfiles"].values()):
            raise ProgramaInvalido("nivel desconocido")
    for clave in ("H1", "H2", "H3", "F1"):
        if clave not in prog["distribuciones"]:
            raise ProgramaInvalido("falta distribución %s" % clave)
    d = prog["destinos"]
    for clave in ("servidor", "puerto_http", "puerto_https", "dns_servidor",
                  "dns_zona", "dns_nombres", "dns_ip_esperada"):
        if clave not in d:
            raise ProgramaInvalido("falta destino %s" % clave)


def tramo_en(tramos: list[dict], t: float) -> dict:
    for tramo in tramos:
        if tramo["inicio_s"] <= t < tramo["fin_s"]:
            return tramo
    return tramos[-1]


def nivel_en(prog: dict, perfil: str, t: float) -> str:
    return tramo_en(prog["niveles"], t)["perfiles"][perfil]


def on_p6(prog: dict, t: float) -> bool:
    p = prog["perfiles"]["P6"]
    return t % (p["on_s"] + p["off_s"]) < p["on_s"]


def proximo_borde(prog: dict, perfil: str, t: float) -> float:
    bordes = [prog["duracion_s"]]
    for clave in ("jornadas", "bloques"):
        bordes.extend(x["fin_s"] for x in prog[clave] if x["fin_s"] > t)
    actual = nivel_en(prog, perfil, t)
    bordes.extend(x["inicio_s"] for x in prog["niveles"]
                  if x["inicio_s"] > t and x["perfiles"][perfil] != actual)
    if perfil == "P6":
        p = prog["perfiles"]["P6"]
        ciclo = p["on_s"] + p["off_s"]
        base = int(t // ciclo) * ciclo
        bordes.extend((base + p["on_s"], base + ciclo, base + ciclo + p["on_s"]))
    return min(b for b in bordes if b > t)
