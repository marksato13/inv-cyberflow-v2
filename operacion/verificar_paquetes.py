#!/usr/bin/env python3
"""Verifica y extrae los paquetes de la release del Bloque 1 (revisión 4).

    python3 -X utf8 operacion/verificar_paquetes.py CARPETA_DESCARGAS [--destino evidencias/bloque1/entradas-r4]

1. El sha256 de cada .tgz descargado debe coincidir con el manifiesto VERSIONADO en el repositorio
   (evidencias/bloque1/entradas-r4/SHA256SUMS-bloque1-r4.txt), no solo con el que trae la release.
2. Extrae cada paquete en el destino (tarfile, filtro «data»: sin rutas absolutas, sin «..», sin
   enlaces fuera del destino).
3. Dentro de cada ejecución comprueba MANIFIESTO-PAQUETE.sha256: todos los ficheros listados existen y
   su sha256 coincide. Eso cubre también los ficheros de texto que ya estaban en el repositorio.
Cualquier fallo: rc 1 y «NO SATISFACTORIO».
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFIESTO = REPO / "evidencias" / "bloque1" / "entradas-r4" / "SHA256SUMS-bloque1-r4.txt"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def leer_sumas(p: Path) -> dict:
    out = {}
    for l in p.read_text(encoding="utf-8").splitlines():
        if l.strip():
            h, n = l.split(None, 1)
            out[n.strip().lstrip("*").removeprefix("./")] = h
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("descargas", type=Path)
    ap.add_argument("--destino", type=Path, default=MANIFIESTO.parent)
    a = ap.parse_args(argv)
    fallos = []
    esperado = leer_sumas(MANIFIESTO)
    for nombre, h in sorted(esperado.items()):
        f = a.descargas / nombre
        if not f.exists():
            fallos.append("falta el paquete %s" % nombre)
            continue
        real = sha256(f)
        print("%s  %s  %s" % (real, nombre, "OK" if real == h else "DISTINTO (esperado %s)" % h))
        if real != h:
            fallos.append("sha256 distinto: %s" % nombre)
            continue
        with tarfile.open(f) as t:
            t.extractall(a.destino, filter="data")
    for d in sorted(p for p in a.destino.iterdir() if p.is_dir() and p.name.startswith("V2-")):
        m = d / "MANIFIESTO-PAQUETE.sha256"
        if not m.exists():
            fallos.append("%s: sin MANIFIESTO-PAQUETE.sha256" % d.name)
            continue
        sumas = leer_sumas(m)
        malos = [n for n, h in sumas.items() if not (d / n).is_file() or sha256(d / n) != h]
        print("%s: %d ficheros del manifiesto, %d distintos o ausentes" % (d.name, len(sumas), len(malos)))
        fallos += ["%s/%s" % (d.name, n) for n in malos[:20]]
    print("GLOBAL", "SATISFACTORIO" if not fallos else "NO SATISFACTORIO")
    for x in fallos:
        print("   ", x)
    return 0 if not fallos else 1


if __name__ == "__main__":
    sys.exit(main())
