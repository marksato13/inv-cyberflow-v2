#!/usr/bin/env python3
"""Genera programas v3 deterministas para captura, piloto y pruebas."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

AQUI = Path(__file__).resolve().parent
PERFILES = tuple("P%d" % n for n in range(1, 7))
FLUJOS = ("espera", "contenido", "red")
PARTICIONES = (("entrenamiento", "entrenamiento"),
               ("entrenamiento", "calibracion"),
               ("entrenamiento", "desarrollo"),
               ("entrenamiento", "calibracion"),
               ("entrenamiento", "desarrollo"),
               ("entrenamiento", "calibracion"),
               ("entrenamiento", "desarrollo"))
DESTINOS = {"servidor": "10.10.30.10", "puerto_http": 80, "puerto_https": 443,
            "dns_servidor": "10.10.10.20", "dns_zona": "cf-v2.lab",
            "dns_nombres": ["portal", "intranet", "correo", "wiki", "erp", "archivos"],
            "dns_ip_esperada": "10.10.30.10"}
DISTRIBUCIONES = {
    "H1": {"media": 10710, "desviacion": 25032, "minimo": 100, "maximo_exclusivo": 2000000},
    "H2": {"media": 7758, "desviacion": 126168, "minimo": 50, "maximo_exclusivo": 2000000},
    "H3": {"escala": 2, "forma": 1.1, "maximo_exclusivo": 55, "restar": 2},
    "F1": {"mu": 14.45, "sigma": 0.35, "maximo_exclusivo": 5000000}}
PERFILES_BASE = {
    "P1": ("consulta", 30),
    "P2": ("navegacion", 30),
    "P3": ("archivo", 180),
    "P4": ("transaccional", 10),
    "P5": ("consulta", 90),
    "P6": ("intermitente", 10)}
PROCEDENCIA = {
    "contrato": "docs/CONTRATO-GENERADOR-49H.md v3.0.0",
    "perfiles.P1/P2.H1/H2/H3/parsing": "PUB S2 (ns-3)",
    "perfiles.P3.F1/pausa": "PUB S3/S6 (MathWorks/IEEE); HTTP ADAP",
    "perfiles.P4.media_espera_s": "PUB S5 (SPECweb2009); exponencial ADAP S4",
    "perfiles.P5/P6/on_off": "D1 (diseño experimental)",
    "perfiles.*.origen": "V1: alias de cliente; P1–P6 10.10.20.21–26",
    "destinos.dns_nombres/zona": "NUEVA: seis nombres en cf-v2.lab",
    "destinos.endpoints": "NUEVA: /contenido/<n>, /app/consulta, /app/envio",
    "factores/jornadas/bloques/niveles": "D1 y NUEVA: calendario §7",
    "semillas": "NUEVA: sha256(cyberflow-v2|49h|2026-11-25|programa_id|bloque|perfil|flujo)",
    "post_bytes": "V1: U{200,…,8000}",
}



def semilla(programa_id, bloque, perfil, flujo):
    texto = "cyberflow-v2|49h|2026-11-25|%s|%s|%s|%s" % (
        programa_id, bloque, perfil, flujo)
    return int(hashlib.sha256(texto.encode()).hexdigest()[:12], 16)


def comun(programa_id, tipo, duracion):
    perfiles = {}
    for i, (modelo, media) in PERFILES_BASE.items():
        p = {"origen": "10.10.20.%d" % (20 + int(i[1:])),
             "modelo": modelo, "media_espera_s": media}
        if i == "P2":
            p.update(parsing_media_s=0.13, alternancia=["http", "https"])
        if i == "P6":
            p.update(on_s=60, off_s=120)
        perfiles[i] = p
    factores = {"reducido": 1 / 3, "base": 1, "aumentado": 2}
    if tipo == "prueba":
        factores["inactivo"] = 0
    return {"programa_id": programa_id, "version": "3.0.0", "tipo": tipo,
            "duracion_s": duracion, "jornadas": [], "bloques": [], "niveles": [],
            "factores": factores, "perfiles": perfiles,
            "distribuciones": DISTRIBUCIONES, "destinos": DESTINOS,
            "procedencia": PROCEDENCIA, "equivalencia": {}}


def jornada(prog, jid, inicio, fin, patron, titulo=None):
    prog["jornadas"].append({"id": jid, "inicio_s": inicio, "fin_s": fin,
                             "titulo": titulo or patron, "patron": patron})


def bloque(prog, bid, jid, inicio, fin, particion):
    prog["bloques"].append({"id": bid, "jornada": jid, "inicio_s": inicio, "fin_s": fin,
                            "particion": particion,
                            "semillas": {p: {f: semilla(prog["programa_id"], bid, p, f)
                                            for f in FLUJOS} for p in PERFILES}})


def niveles(prog, base_por_jornada, ventanas):
    """Divide el calendario en los bordes de todas las ventanas programadas."""
    bordes = {0, prog["duracion_s"]}
    for j in prog["jornadas"]:
        bordes.update((j["inicio_s"], j["fin_s"]))
    for inicio, fin, _perfiles, _nivel in ventanas:
        bordes.update((inicio, fin))
    for i, (a, b) in enumerate(zip(sorted(bordes), sorted(bordes)[1:]), 1):
        j = next(j for j in prog["jornadas"] if j["inicio_s"] <= a < j["fin_s"])
        valores = {p: base_por_jornada[j["id"]] for p in PERFILES}
        for va, vb, ps, nivel in ventanas:
            if va <= a < vb:
                valores.update({p: nivel for p in ps})
        prog["niveles"].append({"id": "N%03d" % i, "inicio_s": a,
                                "fin_s": b, "perfiles": valores})


def captura():
    prog = comun("V2-C49", "captura", 176400)
    ventanas = []
    bases = {}
    for i in range(7):
        jid = "J%d" % (i + 1)
        a, m, fin = i * 25200, i * 25200 + 12600, (i + 1) * 25200
        patron = ("base", "web_aumentado", "archivo_app_aumentado", "rafagas_web_app",
                  "base_repetida", "reducido_periodos", "reducido_rafagas")[i]
        jornada(prog, jid, a, fin, patron, "Jornada %d: %s" % (i + 1, patron))
        bloque(prog, jid + "-B1", jid, a, m, PARTICIONES[i][0])
        bloque(prog, jid + "-B2", jid, m, fin, PARTICIONES[i][1])
        bases[jid] = "reducido" if i >= 5 else "base"
        if i == 1:
            ventanas.append((a, fin, ("P1", "P2"), "aumentado"))
        if i == 2:
            ventanas.append((a, fin, ("P3", "P4"), "aumentado"))
        if i == 3:
            for h in range(1, 8):
                ventanas.append((a + h * 3600 - 300, a + h * 3600,
                                 ("P1", "P2", "P4"), "aumentado"))
        if i == 5:
            for mitad in (a, m):
                for ini in (30, 120):
                    ventanas.append((mitad + ini * 60, mitad + (ini + 15) * 60,
                                     PERFILES, "base"))
        if i == 6:
            for mitad in (a, m):
                for ini in (40, 100, 160):
                    ventanas.append((mitad + ini * 60, mitad + (ini + 3) * 60,
                                     PERFILES, "base"))
    niveles(prog, bases, ventanas)
    prog["horas_por_particion"] = {"entrenamiento": 28, "calibracion": 10.5,
                                    "desarrollo": 10.5}
    return prog


def piloto():
    prog = comun("V2-P49", "piloto", 1800)
    ventanas = []
    bases = {}
    cursor = 0
    for i in range(7):
        jid, a = "J%d" % (i + 1), cursor
        duracion = 360 if i == 0 else 240  # 2 min adicionales de referencia base: piloto de 30 min
        mitad = duracion // 2
        cursor += duracion
        patron = ("base", "web_aumentado", "archivo_app_aumentado", "rafagas_web_app",
                  "base_repetida", "reducido_periodos", "reducido_rafagas")[i]
        jornada(prog, jid, a, cursor, patron)
        bloque(prog, jid + "-B1", jid, a, a + mitad, "piloto")
        bloque(prog, jid + "-B2", jid, a + mitad, cursor, "piloto")
        bases[jid] = "reducido" if i >= 5 else "base"
        prog["equivalencia"][jid] = {
            "tipo": "prueba abreviada", "programa_definitivo": "V2-C49",
            "jornada_definitiva": jid, "patron": patron,
            "compresion": "7 h a %d s; bloques de 3,5 h a %d s; ventanas abreviadas" %
                         (duracion, mitad)}
        if i == 1:
            ventanas.append((a, cursor, ("P1", "P2"), "aumentado"))
        if i == 2:
            ventanas.append((a, cursor, ("P3", "P4"), "aumentado"))
        if i == 3:
            for x, y in ((90, 120), (210, 240)):
                ventanas.append((a + x, a + y, ("P1", "P2", "P4"), "aumentado"))
        if i == 5:
            for x, y in ((30, 60), (150, 180)):
                ventanas.append((a + x, a + y, PERFILES, "base"))
        if i == 6:
            for x, y in ((40, 55), (160, 175)):
                ventanas.append((a + x, a + y, PERFILES, "base"))
    niveles(prog, bases, ventanas)
    assert cursor == prog["duracion_s"]
    return prog


def aislados():
    prog = comun("V2-T1", "prueba", 1800)
    jornada(prog, "A", 0, 1800, "perfiles_aislados")
    for i in range(2):
        bloque(prog, "A-B%d" % (i + 1), "A", i * 900, (i + 1) * 900, "prueba")
    prog["niveles"] = [{"id": "N%03d" % (i + 1), "inicio_s": i * 300,
                        "fin_s": (i + 1) * 300,
                        "perfiles": {p: "base" if p == PERFILES[i] else "inactivo"
                                    for p in PERFILES}} for i in range(6)]
    prog["equivalencia"] = {"A": {"tipo": "prueba dirigida", "programa_definitivo": "V2-C49",
                                  "jornada_definitiva": "J1",
                                  "patron": "un perfil activo por tramo de 300 s",
                                  "compresion": "sin equivalencia temporal directa"}}
    return prog


def transiciones():
    prog = comun("V2-T2", "prueba", 1440)
    jornada(prog, "A", 0, 720, "reducido_base_aumentado")
    jornada(prog, "B", 720, 1440, "reducido_con_rafagas")
    for i in range(4):
        bloque(prog, ("A" if i < 2 else "B") + "-B%d" % (i % 2 + 1),
               "A" if i < 2 else "B", i * 360, (i + 1) * 360, "prueba")
    ventanas = [(240, 480, PERFILES, "base"), (480, 720, PERFILES, "aumentado"),
                (840, 900, PERFILES, "base"),
                (1080, 1140, ("P1", "P2", "P4"), "aumentado"),
                (1260, 1320, PERFILES, "base")]
    niveles(prog, {"A": "reducido", "B": "reducido"}, ventanas)
    prog["equivalencia"] = {
        "A": {"tipo": "prueba dirigida", "programa_definitivo": "V2-C49",
              "jornada_definitiva": "J1", "patron": "niveles sucesivos",
              "compresion": "tramos de 240 s"},
        "B": {"tipo": "prueba dirigida", "programa_definitivo": "V2-C49",
              "jornada_definitiva": "J6 y J4", "patron": "periodos y ráfaga",
              "compresion": "ventanas de 60 s"}}
    return prog


def todas():
    return {"captura-49h.json": captura(), "piloto-30min.json": piloto(),
            "prueba-perfiles-aislados.json": aislados(),
            "prueba-niveles-transiciones.json": transiciones()}


def serializar(prog):
    return (json.dumps(prog, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--comprobar", action="store_true")
    args = ap.parse_args()
    for nombre, prog in todas().items():
        datos = serializar(prog)
        ruta = AQUI / nombre
        if args.comprobar:
            if not ruta.exists() or ruta.read_bytes() != datos:
                print("difiere: %s" % nombre)
                return 1
        else:
            ruta.write_bytes(datos)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
