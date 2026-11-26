#!/usr/bin/env python3
"""Dictamen con la política de calidad integrada sobre ejecuciones ya cerradas, sin escribir en ellas.

    python3 redictaminar_bloque1.py --pruebas ~/cyberflow-v2/pruebas --copias-dir <dir> --dns-dir <dir> \
        --salida redictamen.json ID [ID ...]

Para cada ejecución usa estado_global.evaluar() leyendo la ejecución tal cual, salvo dos
evidencias que se toman de los reanálisis del Bloque 1 (las del cierre original se hicieron con
herramientas anteriores): `copias-<ID>.json` de --copias-dir y `dns-<ID>.json` de --dns-dir. No
escribe resultado-global.json: el dictamen anterior se conserva y se informa al lado.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import estado_global as eg  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="+")
    ap.add_argument("--pruebas", required=True, type=Path)
    ap.add_argument("--copias-dir", required=True, type=Path)
    ap.add_argument("--dns-dir", required=True, type=Path)
    ap.add_argument("--carpeta", action="append", default=[],
                    help="ID=carpeta cuando la carpeta de pruebas no se llama como el ID")
    ap.add_argument("--salida", required=True, type=Path)
    a = ap.parse_args(argv)
    carpetas = dict(x.split("=", 1) for x in a.carpeta)
    original = eg.leer
    filas = []
    for ide in a.ids:
        p = a.pruebas / carpetas.get(ide, ide)
        sustitutos = {p / "calidad-copias-espejo.json": a.copias_dir / ("copias-%s.json" % ide),
                      p / "calidad-contraste-dns.json": a.dns_dir / ("dns-%s.json" % ide)}
        eg.leer = lambda ruta, s=sustitutos: original(s.get(ruta, ruta))
        try:
            r = eg.evaluar(ide, p)
        finally:
            eg.leer = original
        anterior = original(p / "resultado-global.json") or {}
        filas.append({"ejecucion": ide, "anterior": {k: anterior.get(k) for k in ("global", "motivos")},
                      "nuevo": r, "fuentes_sustituidas": {k.name: str(v) for k, v in sustitutos.items()}})
        print(ide, "anterior=%s" % anterior.get("global"), "nuevo=%s" % r["global"],
              "copias=%s dns=%s" % (r["calidad_copias"], r["calidad_dns"]),
              "motivos=%s" % ",".join(m for m in r["motivos"] if not m.startswith("falta:criterio")))
    a.salida.write_text(json.dumps(filas, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
