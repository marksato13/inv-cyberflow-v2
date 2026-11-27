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
             nombre in ("_scratch", "_temporales_pytest", "_registros_pytest")))


# --- Registro completo de cada pasada (BLOQUE1-REVISION-8, §1) ---------------------------------
# En r7 una pasada de 175 s dio «1 failed» y no se supo cuál: solo se conservó la última línea de
# la consola y -p no:cacheprovider no deja lastfailed. Desde r8 cada pasada escribe, pase lo que pase
# en la consola, una carpeta tests/_registros_pytest/<UTC>-<pid>/ (o $CYBERFLOW_REGISTRO_PRUEBAS) con:
#   informes.jsonl  una línea por fase de cada prueba no superada (setup/call/teardown):
#                   id, resultado, duración, traza COMPLETA y salida capturada
#   resultados.tsv  id, resultado y duración de TODAS las pruebas
#   resumen.json    totales, ids fallidos, duración, versiones, commit, argumentos, CPU
# La carpeta no se borra ni se sobrescribe; las pasadas fallidas se conservan.
import json as _json
import platform as _platform
import subprocess as _subprocess
import sys as _sys
import time as _time

_REG = {}


def pytest_configure(config):
    if hasattr(config, "workerinput"):
        return
    raiz = Path(os.environ.get("CYBERFLOW_REGISTRO_PRUEBAS") or
                Path(__file__).resolve().parent / "_registros_pytest")
    d = raiz / ("%s-%d" % (_time.strftime("%Y%m%dT%H%M%SZ", _time.gmtime()), os.getpid()))
    d.mkdir(parents=True, exist_ok=True)
    _REG.update(dir=d, t0=_time.time(), cuentas={}, fallidas=[],
                informes=open(d / "informes.jsonl", "a", encoding="utf-8"),
                tabla=open(d / "resultados.tsv", "a", encoding="utf-8"))


def pytest_runtest_logreport(report):
    if not _REG:
        return
    if report.when == "call" or report.outcome != "passed":
        clave = report.outcome if report.when == "call" or report.outcome == "skipped" else "error"
        _REG["cuentas"][clave] = _REG["cuentas"].get(clave, 0) + 1
        _REG["tabla"].write("%s\t%s\t%s\t%.3f\n" % (report.nodeid, report.when, report.outcome,
                                                     report.duration))
        _REG["tabla"].flush()
    if report.outcome == "failed":
        _REG["fallidas"].append({"id": report.nodeid, "fase": report.when})
        _REG["informes"].write(_json.dumps({
            "id": report.nodeid, "fase": report.when, "resultado": report.outcome,
            "duracion_s": round(report.duration, 3), "traza": report.longreprtext,
            "salida": report.capstdout, "error_estandar": report.capstderr,
            "secciones": [[n, c] for n, c in report.sections]}, ensure_ascii=False) + "\n")
        _REG["informes"].flush()


def pytest_sessionfinish(session, exitstatus):
    if not _REG:
        return
    try:
        commit = _subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
                                 capture_output=True, text=True, timeout=10,
                                 stdin=_subprocess.DEVNULL).stdout.strip()
        sucio = bool(_subprocess.run(["git", "status", "--porcelain"], cwd=Path(__file__).resolve().parents[1],
                                     capture_output=True, text=True, timeout=10,
                                     stdin=_subprocess.DEVNULL).stdout.strip())
    except Exception:
        commit, sucio = None, None
    import pytest as _pytest
    resumen = {"codigo_salida": int(exitstatus), "cuentas": _REG["cuentas"], "fallidas": _REG["fallidas"],
               "duracion_s": round(_time.time() - _REG["t0"], 2),
               "inicio_utc": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(_REG["t0"])),
               "argumentos": list(session.config.invocation_params.args),
               "python": _sys.version.split()[0], "pytest": _pytest.__version__,
               "plataforma": _platform.platform(), "cpu": os.cpu_count(),
               "commit": commit, "arbol_con_cambios": sucio}
    (_REG["dir"] / "resumen.json").write_text(_json.dumps(resumen, ensure_ascii=False, indent=1),
                                              encoding="utf-8")
    _REG["informes"].close()
    _REG["tabla"].close()


def pytest_terminal_summary(terminalreporter):
    if _REG:
        terminalreporter.write_line("registro completo de esta pasada: %s" % _REG["dir"])
