#!/usr/bin/env python3
"""Reproduce, fuera del laboratorio, el dictamen de VD2/VD3/VD4/VD6 desde los RESULTADOS INTERMEDIOS
publicados (Bloque 1, revisión 4). No lee PCAP ni EVE: eso lo hace recalcular_desde_capturas.py.

    python3 -X utf8 operacion/reproducir_dictamen.py [DIR] [--salida informe.json]

DIR (por omisión evidencias/bloque1/entradas-r4) contiene una carpeta por ejecución con:
  pruebas/<ID>/ y capturas/<ID>/   entradas de texto saneadas (lo que leen los programas del dictamen)
  referencia/                      lo que dio el LABORATORIO con esas entradas sin sanear:
                                   resultado-global.json, criterios-revisados.json, dictamen-casos.json

Para cada ejecución copia sus entradas a una carpeta temporal, ejecuta revisar_criterios.py,
estado_global.py y dictamen_casos.py, y compara con la referencia:
  - dictamen: global, dictamen, codigo_salida, motivos, alcance y los estados (espejo, calidad_*,
    referencias, transferencias, analisis, exclusion_v1);
  - criterios: `ok` de C7 y C9–C13 (revisados) y las listas de pendientes de duración prolongada y de
    otra comprobación;
  - los ocho casos de dictamen_casos.py: caso, global, codigo_salida, calidad y motivos.
Una ejecución esperada ausente, un fichero de entrada o de referencia ausente, un programa que falla
o cualquier diferencia => NO SATISFACTORIO y rc 1. No escribe en el repositorio.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ESPERADAS = ("V2-VD2-20261126T090705Z", "V2-VD3-20261126T104230Z", "V2-VD4-20261126T141333Z",
             "V2-VD6-20261126T151456Z")
CAMPOS_DICTAMEN = ("global", "dictamen", "codigo_salida", "motivos", "alcance", "espejo", "calidad_copias",
                   "calidad_dns", "calidad_extremo", "calidad_sonda", "referencias", "transferencias",
                   "analisis", "exclusion_v1", "pendientes_duracion_prolongada", "pendientes_otra_comprobacion")
CAMPOS_CASO = ("caso", "global", "codigo_salida", "calidad", "motivos")
N_CASOS = 8


def dec(p):
    return json.JSONDecoder().raw_decode(Path(p).read_text(encoding="utf-8"))[0]


def resumen_dictamen(g):
    return {k: g.get(k) for k in CAMPOS_DICTAMEN}


def resumen_criterios(c):
    return {k: v.get("ok") for k, v in c["criterios"].items()}


def resumen_casos(d):
    return [{k: c.get(k) for k in CAMPOS_CASO} for c in d["casos"]]


def comparar(nombre, ref, nuevo, difs):
    if ref != nuevo:
        if isinstance(ref, dict) and isinstance(nuevo, dict):
            for k in sorted(set(ref) | set(nuevo)):
                if ref.get(k) != nuevo.get(k):
                    difs.append("%s.%s: laboratorio %s, reproducido %s" % (
                        nombre, k, json.dumps(ref.get(k), ensure_ascii=False)[:120],
                        json.dumps(nuevo.get(k), ensure_ascii=False)[:120]))
        else:
            difs.append("%s: laboratorio %s, reproducido %s" % (nombre, json.dumps(ref, ensure_ascii=False)[:300],
                                                                 json.dumps(nuevo, ensure_ascii=False)[:300]))


def una(E: Path, ID: str):
    res = {"ejecucion": ID, "diferencias": [], "ausentes": []}
    R = E / "referencia"
    for f in (E / "pruebas" / ID, E / "capturas" / ID, R / "resultado-global.json",
              R / "criterios-revisados.json", R / "dictamen-casos.json"):
        if not f.exists():
            res["ausentes"].append(str(f.relative_to(E.parent)))
    if res["ausentes"]:
        res["satisfactorio"] = False
        return res
    op, py = REPO / "operacion", [sys.executable, "-I", "-X", "utf8"]
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        P, K = t / ID, E / "capturas" / ID
        shutil.copytree(E / "pruebas" / ID, P)
        pasos = [
            ("revisar_criterios", [str(op / "revisar_criterios.py"), "--pruebas", str(P), "--capturas", str(K)]),
            ("estado_global", [str(op / "estado_global.py"), ID, "--pruebas", str(P), "--ejecucion-dir",
                               str(P / "registros"), "--captura-dir", str(K)]),
            ("dictamen_casos", [str(op / "dictamen_casos.py"), ID, "--pruebas", str(P), "--capturas", str(K),
                                "--salida", str(t / "casos")]),
        ]
        salidas = {}
        for nombre, cmd in pasos:
            r = subprocess.run(py + cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            salidas[nombre] = r.stdout
            # estado_global devuelve rc = código del dictamen (0/1/2); los otros dos, 0 si van bien
            if nombre != "estado_global" and r.returncode != 0:
                res["diferencias"].append("%s terminó con rc %d: %s" % (nombre, r.returncode, (r.stderr or r.stdout)[-300:]))
        try:
            g = json.JSONDecoder().raw_decode(salidas["estado_global"])[0]
            comparar("dictamen", resumen_dictamen(dec(R / "resultado-global.json")), resumen_dictamen(g), res["diferencias"])
            comparar("criterios", resumen_criterios(dec(R / "criterios-revisados.json")),
                     resumen_criterios(dec(P / "criterios-revisados.json")), res["diferencias"])
            ref_c, nuevo_c = resumen_casos(dec(R / "dictamen-casos.json")), resumen_casos(dec(t / "casos" / "dictamen-casos.json"))
            if len(ref_c) != N_CASOS:
                res["diferencias"].append("la referencia tiene %d casos, se esperaban %d" % (len(ref_c), N_CASOS))
            comparar("casos", ref_c, nuevo_c, res["diferencias"])
            res["dictamen"], res["motivos"] = g.get("global"), g.get("motivos")
            res["criterios"] = resumen_criterios(dec(P / "criterios-revisados.json"))
            res["casos"] = [(c["caso"], c["global"]) for c in nuevo_c]
        except (ValueError, OSError, KeyError) as exc:
            res["diferencias"].append("salida ilegible: %s" % exc)
    res["satisfactorio"] = not res["diferencias"]
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir", nargs="?", type=Path, default=REPO / "evidencias" / "bloque1" / "entradas-r4")
    ap.add_argument("--salida", type=Path)
    a = ap.parse_args(argv)
    informe = {"version": 2, "comprobacion": "dictamen desde resultados intermedios", "ejecuciones": []}
    for ID in ESPERADAS:
        E = a.dir / ID
        r = una(E, ID) if E.is_dir() else {"ejecucion": ID, "satisfactorio": False, "ausentes": [str(E)], "diferencias": []}
        informe["ejecuciones"].append(r)
        print(ID, "SATISFACTORIO" if r["satisfactorio"] else "NO SATISFACTORIO", r.get("dictamen"), r.get("motivos"),
              r.get("criterios"), r.get("casos"))
        for x in r["ausentes"] + r["diferencias"]:
            print("   ", x)
    informe["satisfactorio"] = all(r["satisfactorio"] for r in informe["ejecuciones"])
    if a.salida:
        a.salida.write_text(json.dumps(informe, ensure_ascii=False, indent=1), encoding="utf-8")
    print("GLOBAL", "SATISFACTORIO" if informe["satisfactorio"] else "NO SATISFACTORIO")
    return 0 if informe["satisfactorio"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
