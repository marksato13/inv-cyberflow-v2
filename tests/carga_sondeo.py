"""Reproduce con la máquina cargada las pruebas del sondeo (BLOQUE1-REVISION-8, §1).

Arranca cpu × FACTOR procesos que ocupan CPU y ejecuta K pasadas de tests/test_sondeo_span.py, cada una
con la salida COMPLETA (-v -rA) y un junit XML en <salida>/<prefijo>-NN.{txt,xml}. Escribe
<salida>/resumen.json con el código de salida, la duración y las pruebas fallidas de cada pasada.
No es una prueba (pytest no lo recoge). Uso:
  python tests/carga_sondeo.py --factor 3 --pasadas 8 --salida evidencias/bloque1/suite-r8/sondeo-despues-x3 --prefijo despues-x3
"""
import argparse
import json
import multiprocessing as mp
import os
import re
import subprocess
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def ocupar(fin):
    x = 0
    while time.time() < fin:
        x = (x * 31 + 7) % 1000003


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--factor", type=float, default=1)
    p.add_argument("--pasadas", type=int, default=8)
    p.add_argument("--salida", required=True)
    p.add_argument("--prefijo", required=True)
    p.add_argument("--pruebas", default="tests/test_sondeo_span.py")
    a = p.parse_args()
    d = (RAIZ / a.salida) if not Path(a.salida).is_absolute() else Path(a.salida)
    d.mkdir(parents=True, exist_ok=True)
    n = max(0, round(os.cpu_count() * a.factor))
    fin = time.time() + 3600
    carga = [mp.Process(target=ocupar, args=(fin,), daemon=True) for _ in range(n)]
    for c in carga:
        c.start()
    filas = []
    try:
        time.sleep(2)
        for k in range(1, a.pasadas + 1):
            base = d / ("%s-%02d" % (a.prefijo, k))
            t0 = time.time()
            with open(str(base) + ".txt", "w", encoding="utf-8") as f:
                r = subprocess.run([sys.executable, "-m", "pytest", "-v", "-rA", "-p", "no:cacheprovider",
                                    "--junitxml", str(base) + ".xml", a.pruebas],
                                   cwd=RAIZ, stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            texto = Path(str(base) + ".txt").read_text(encoding="utf-8", errors="replace")
            # La sesión puede abortar antes del resumen de pytest; conservar también los ids que
            # aparecen durante la ejecución (errores de setup incluidos).
            fallidas = sorted(set(re.findall(r"^(?:FAILED|ERROR) (\S+)", texto, re.M)) |
                             set(re.findall(r"^(tests/\S+?::\S+?)\s+(?:FAILED|ERROR)(?:\s|$)",
                                            texto, re.M)))
            filas.append({"pasada": k, "rc": r.returncode, "duracion_s": round(time.time() - t0, 1),
                          "fallidas": fallidas, "error_de_sesion": r.returncode != 0 and not fallidas})
            print(json.dumps(filas[-1]), flush=True)
    finally:
        for c in carga:
            c.terminate()
    (d / "resumen.json").write_text(json.dumps({"cpu": os.cpu_count(), "procesos_de_carga": n,
                                                "factor": a.factor, "pasadas": filas}, indent=1),
                                    encoding="utf-8")
    if any(fila["rc"] != 0 for fila in filas):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
