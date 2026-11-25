"""Temporales de pruebas dentro del repositorio en Windows.

Python 3.14 crea mkdtemp con modo 0700, que la política del worktree
restringido impide reabrir. mkdir sin modo explícito conserva la ACL heredada.
"""
import os
import tempfile
import uuid
from pathlib import Path

if os.name == "nt":
    BASE = Path(__file__).resolve().parent / "_temporales_pytest"
    BASE.mkdir(exist_ok=True)
    tempfile.tempdir = str(BASE)

    def mkdtemp(suffix=None, prefix=None, dir=None):
        destino = Path(dir) if dir is not None else BASE
        destino.mkdir(parents=True, exist_ok=True)
        while True:
            ruta = destino / ((prefix or "tmp") + uuid.uuid4().hex + (suffix or ""))
            try:
                ruta.mkdir()
                return str(ruta)
            except FileExistsError:
                pass

    tempfile.mkdtemp = mkdtemp


def pytest_ignore_collect(collection_path, config):
    nombre = collection_path.name
    return (collection_path.is_dir() and
            (nombre.startswith("tmp") or nombre.startswith("temporal-") or
             nombre in ("_scratch", "_temporales_pytest")))
