#!/usr/bin/env python3
"""Escribe manifiestos/MANIFIESTO.json: sha256 de cada fichero versionado y referencias externas.

    python manifiestos/generar_manifiesto.py
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
EXTERNO = RAIZ / "manifiestos" / "referencias-externas.json"


def main() -> int:
    ficheros = subprocess.run(["git", "-C", str(RAIZ), "ls-files"], capture_output=True, text=True).stdout.split()
    salida = {
        "repositorio": "cyberflow-v2",
        "python_generacion": platform.python_version(),
        "ficheros": {f: hashlib.sha256((RAIZ / f).read_bytes()).hexdigest()
                     for f in sorted(ficheros) if f != "manifiestos/MANIFIESTO.json"},
        "referencias_externas": json.loads(EXTERNO.read_text(encoding="utf-8")),
    }
    (RAIZ / "manifiestos" / "MANIFIESTO.json").write_text(
        json.dumps(salida, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print("ficheros:", len(salida["ficheros"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
