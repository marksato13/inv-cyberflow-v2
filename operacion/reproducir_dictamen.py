#!/usr/bin/env python3
"""Reproduce, fuera del laboratorio, el dictamen de VD2/VD3/VD4 con las entradas publicadas.

    python3 -X utf8 operacion/reproducir_dictamen.py [evidencias/bloque1/extractos-539c48e]

Para cada `entradas-<ID>/` (texto saneado, sin PCAP ni EVE) copia la ejecución a una carpeta
temporal, ejecuta revisar_criterios.py, estado_global.py y dictamen_casos.py, y compara el dictamen,
los motivos y C7/C9–C13 con los resultados del laboratorio publicados en
`evidencias/bloque1/reanalisis/<código>/<ID>/`. No escribe en el repositorio. rc 0 si todo coincide.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REF = {"V2-VD2-20261126T090705Z": "5d4d51f", "V2-VD3-20261126T104230Z": "5d4d51f",
       "V2-VD4-20261126T141333Z": "3e0c73e"}


def dec(p):
    return json.JSONDecoder().raw_decode(Path(p).read_text(encoding="utf-8"))[0]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    X = Path(argv[0]) if argv else REPO / "evidencias" / "bloque1" / "extractos-539c48e"
    op, py = REPO / "operacion", [sys.executable, "-I", "-X", "utf8"]
    todo = True
    for ID, cod in REF.items():
        E = X / ("entradas-" + ID)
        ref = REPO / "evidencias" / "bloque1" / "reanalisis" / cod / ID
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            P, K = t / ID, E / "capturas" / ID
            shutil.copytree(E / "pruebas" / ID, P)
            subprocess.run(py + [str(op / "revisar_criterios.py"), "--pruebas", str(P), "--capturas", str(K)],
                           check=True, capture_output=True)
            g = subprocess.run(py + [str(op / "estado_global.py"), ID, "--pruebas", str(P), "--ejecucion-dir",
                                     str(P / "registros"), "--captura-dir", str(K)],
                               capture_output=True, text=True, encoding="utf-8")
            r, o = json.JSONDecoder().raw_decode(g.stdout)[0], dec(ref / "resultado-global.json")
            subprocess.run(py + [str(op / "dictamen_casos.py"), ID, "--pruebas", str(P), "--capturas", str(K),
                                 "--salida", str(t / "casos")], check=True, capture_output=True)
            casos = [(c["caso"], c["global"]) for c in dec(t / "casos" / "dictamen-casos.json")["casos"]]
            a = {k: v["ok"] for k, v in dec(P / "criterios-revisados.json")["criterios"].items()}
            b = {k: v["ok"] for k, v in dec(ref / "criterios-revisados.json")["criterios"].items()}
            igual = (r["global"], r["motivos"]) == (o["global"], o["motivos"]) and a == b
            todo &= igual
            print(ID, "COINCIDE" if igual else "DIFIERE", r["global"], r["motivos"], a, casos)
    return 0 if todo else 1


if __name__ == "__main__":
    raise SystemExit(main())
