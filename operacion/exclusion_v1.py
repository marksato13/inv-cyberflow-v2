#!/usr/bin/env python3
"""Sensor1: garantiza que V1 no aprende de una ejecución V2.

Añade "*@<desde>/<hasta>" a [reentrenamiento].excluir_ventanas de cyberflow.local.toml si
ninguna regla "*@" ya cubre el intervalo. Copia de respaldo con fecha antes de escribir; no
toca ninguna otra línea. Sale 0 si queda cubierto, 1 si no pudo.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

TOML = Path("/home/m4rk/cyberflow/configs/cyberflow.local.toml")


def iso(e: float) -> str:
    return dt.datetime.fromtimestamp(e, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def cubierto(reglas, desde, hasta) -> str | None:
    for r in reglas:
        if r.startswith("*@"):
            a, b = r[2:].split("/")
            if dt.datetime.fromisoformat(a).timestamp() <= desde and dt.datetime.fromisoformat(b).timestamp() >= hasta:
                return r
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--desde", type=float, required=True, help="epoch")
    ap.add_argument("--hasta", type=float, required=True, help="epoch")
    ap.add_argument("--toml", type=Path, default=TOML)
    a = ap.parse_args()
    texto = a.toml.read_text(encoding="utf-8")
    reglas = tomllib.loads(texto).get("reentrenamiento", {}).get("excluir_ventanas", [])
    r = cubierto(reglas, a.desde, a.hasta)
    if r:
        print(json.dumps({"cubierto": True, "regla": r, "cambio": False}))
        return 0
    nueva = "*@%s/%s" % (iso(a.desde), iso(a.hasta))
    lineas = texto.splitlines(keepends=True)
    idx = [i for i, l in enumerate(lineas) if re.match(r"\s*excluir_ventanas\s*=\s*\[", l)]
    if len(idx) != 1 or "]" not in lineas[idx[0]]:
        print(json.dumps({"cubierto": False, "error": "excluir_ventanas no está en una sola línea"}))
        return 1
    i = idx[0]
    l = lineas[i]
    cierre = l.index("]", l.index("["))
    lineas[i] = l[:cierre] + ', "%s"' % nueva + l[cierre:]
    respaldo = a.toml.with_name(a.toml.name + ".antes-v2-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    shutil.copy2(a.toml, respaldo)
    nuevo = "".join(lineas)
    if cubierto(tomllib.loads(nuevo)["reentrenamiento"]["excluir_ventanas"], a.desde, a.hasta) != nueva:
        print(json.dumps({"cubierto": False, "error": "la verificación tras editar falló; no se escribe"}))
        return 1
    a.toml.write_text(nuevo, encoding="utf-8")
    print(json.dumps({"cubierto": True, "regla": nueva, "cambio": True, "respaldo": str(respaldo)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
