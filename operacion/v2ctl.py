#!/usr/bin/env python3
"""Control de una ejecución V2 en la VM Clientes: preflight, iniciar, estado, parar.

Sin sudo ni systemd: ``iniciar`` deja un supervisor desacoplado (setsid) que lanza un
proceso por perfil activo, espera a que terminen y registra su salida. NO reinicia nada:
si un perfil muere, queda registrado como interrupción y la ejecución se clasifica
después según docs/PROTOCOLO.md (§ interrupciones).

    python3 v2ctl.py preflight --programa P.json
    python3 v2ctl.py iniciar   --programa P.json --ejecucion V2-P0-20261125T150000Z
    python3 v2ctl.py estado    --ejecucion V2-P0-20261125T150000Z
    python3 v2ctl.py parar     --ejecucion V2-P0-20261125T150000Z
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

AQUI = Path(__file__).resolve().parent
GEN = AQUI.parent / "generador"
sys.path.insert(0, str(GEN))
import programa as prg  # noqa: E402
import transacciones as tx  # noqa: E402

RAIZ = Path(os.environ.get("CF_V2_EJECUCIONES", str(Path.home() / "cyberflow-v2" / "ejecuciones")))
ID_OK = re.compile(r"^V2-[A-Z0-9-]+-\d{8}T\d{6}Z$")


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def sh(orden: list[str]) -> str:
    try:
        return subprocess.run(orden, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception as e:  # noqa: BLE001
        return "ERROR %s" % e


def entorno() -> dict:
    return {"host": socket.gethostname(), "python": platform.python_version(), "utc": utc(),
            "monotonic": time.monotonic(), "ntp_sincronizado": sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]),
            "timesync": sh(["timedatectl", "timesync-status"]),
            "codigo": {p.name: sha(p) for p in sorted(GEN.glob("*.py"))} | {"v2ctl.py": sha(Path(__file__))}}


def relojes() -> dict:
    seguimiento = sh(["chronyc", "tracking"]) if shutil.which("chronyc") else sh(["timedatectl", "timesync-status"])
    return {"utc": utc(), "monotonic": time.monotonic(),
            "timedatectl_show": sh(["timedatectl", "show"]), "seguimiento_ntp": seguimiento}


def motivo_permiso(d: Path, iniciado_epoch: float, ahora=time.time,
                   max_s: float = 90, gracia_s: float = 120) -> str | None:
    """Permite inyectar el reloj y deja gracia solo antes del primer permiso."""
    permiso = d / "PERMISO_CAPTURA"
    if permiso.exists():
        if ahora() - permiso.stat().st_mtime > max_s:
            return "sin_permiso_captura"
    elif ahora() - iniciado_epoch > gracia_s:
        return "sin_permiso_captura"
    return None


def detener_sin_permiso(d: Path, hijos: dict, iniciado_epoch: float, ahora=time.time,
                        max_s: float = 90, gracia_s: float = 120) -> str | None:
    motivo = motivo_permiso(d, iniciado_epoch, ahora=ahora, max_s=max_s, gracia_s=gracia_s)
    if motivo:
        for h in hijos.values():
            if h.poll() is None:
                h.send_signal(signal.SIGTERM)
    return motivo


# -- preflight ---------------------------------------------------------------
def preflight(prog: dict) -> list[tuple[str, bool, str]]:
    r = []
    ips = sh(["ip", "-o", "-4", "addr"])
    for perfil, p in prog["perfiles"].items():
        r.append(("alias %s %s" % (perfil, p["origen"]), (" %s/" % p["origen"]) in ips, ""))
    otros = sh(["pgrep", "-af", "clientes_lab"])
    otros = "\n".join(l for l in otros.splitlines() if "pgrep" not in l)
    r.append(("ningún generador en marcha", not otros, otros[:200]))
    r.append(("reloj sincronizado (NTP)", sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]) == "yes", ""))
    libre = shutil.disk_usage(str(Path.home())).free
    r.append(("espacio libre > 1 GB", libre > 1e9, "%.1f GB" % (libre / 1e9)))
    # Solo informativo: cruzar 00:00 UTC está permitido; el archivador sigue el EVE a través de la
    # rotación (copytruncate) y registra cualquier hueco en eve/huecos.jsonl.
    fin = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=prog["duracion_s"])
    cruza = fin.date() != datetime.datetime.now(datetime.timezone.utc).date()
    r.append(("no cruza 00:00 UTC (informativo, no bloquea)", not cruza, "fin estimado %s" % fin.isoformat(timespec="seconds")))
    return r


# Margen entre el fin de la última sonda y el arranque del generador (t0). La primera ventana útil
# cierra en t0 + PASO_S (metadatos_v2: E5) y su historia mira HORIZONTE_S hacia atrás
# (extraer_v2.HORIZONTE_MOTOR_S), así que la sonda debe terminar antes de t0 + PASO_S − HORIZONTE_S.
# Se exige un paso entero más de holgura (relojes, cierres TCP tardíos, dispersión de t0 entre
# perfiles): sonda_fin <= t0 − (HORIZONTE_S + PASO_S). Derivado de las constantes del extractor, no
# de los datos.
HORIZONTE_S = 230.0
PASO_S = 10.0
MARGEN_SONDA_S = HORIZONTE_S + PASO_S


def _registro_sonda(ejecucion, contexto, nombre_sonda, accion, reg, t0, t1, m0, m1):
    """Una línea del registro de sondas: lo necesario para relacionar cada paquete con su sonda."""
    claves = ("protocolo", "origen_puerto", "destino_ip", "destino_puerto", "dns_id", "dns_nombre",
              "ruta", "metodo", "http_codigo", "tls_version", "bytes_enviados", "bytes_recibidos",
              "timeout", "incompleta", "excepcion", "clase", "resultado_observado", "resultado_esperado")
    out = {"tipo": "sonda", "ejecucion_id": ejecucion, "contexto": contexto, "sonda": nombre_sonda,
           "accion": accion, "origen_ip": reg.get("origen_ip"),
           "inicio_utc": t0, "fin_utc": t1, "inicio_monotonic": m0, "fin_monotonic": m1}
    out.update({k: reg.get(k) for k in claves})
    return out


def sondas(prog: dict, ejecucion: str | None, contexto: str):
    """Sondas de red del preflight (DNS y HTTP/HTTPS/consulta/envío). Devuelve (resultados, registro).

    Salen del origen del primer perfil, igual que antes; lo nuevo es que cada una queda registrada
    con ejecución, origen, puerto, id, nombre completo e instantes, para distinguirlas después de la
    generación experimental (contraste_dns.py --sondas, ventanas_sonda.py)."""
    import random
    r, registro = [], []
    perfil0 = next(iter(prog["perfiles"]))
    origen = prog["perfiles"][perfil0]["origen"]
    c = tx.Cliente(origen, prog["destinos"], random.Random(0), random.Random(1))

    def medir(nombre_sonda, accion, ejecutar):
        reg = {"timeout": False, "incompleta": False, "excepcion": None, "origen_ip": origen}
        t0, m0 = utc(), time.monotonic()
        salida = None
        try:
            salida = ejecutar(reg)
        except Exception as e:  # noqa: BLE001
            reg["excepcion"] = "%s: %s" % (type(e).__name__, e)
        t1, m1 = utc(), time.monotonic()
        tx.clasificar(accion, reg, prog["destinos"])
        registro.append(_registro_sonda(ejecucion, contexto, nombre_sonda, accion, reg, t0, t1, m0, m1))
        r.append(("sonda %s" % nombre_sonda, reg["clase"] == "ok",
                  "%s / esperado %s" % (reg.get("resultado_observado"), reg.get("resultado_esperado"))))
        return salida

    nombre = "portal." + prog["destinos"]["dns_zona"]
    ip = medir("dns", "dns", lambda reg: c.dns(reg, nombre))
    if ip:
        medir("obtener HTTP", "obtener", lambda reg: c.obtener(reg, ip, 100))
        medir("obtener HTTPS", "obtener", lambda reg: c.obtener(reg, ip, 100, https=True))
        medir("consulta", "consulta", lambda reg: c.consulta(reg, ip, 1))
        medir("envio", "envio", lambda reg: c.envio(reg, ip, b"p" * 200))
    else:
        for nombre_sonda in ("obtener HTTP", "obtener HTTPS", "consulta", "envio"):
            r.append(("sonda %s" % nombre_sonda, False, "sin IP resuelta por DNS"))
    return r, registro


def registro_preflight(ejecucion, contexto, comprobaciones, registro_sondas):
    """Preflight completo: comprobaciones locales y sondas de red, en una lista de líneas JSON."""
    lineas = [{"tipo": "comprobacion", "ejecucion_id": ejecucion, "contexto": contexto, "utc": utc(),
               "comprobacion": n, "ok": ok, "detalle": det} for n, ok, det in comprobaciones]
    return lineas + list(registro_sondas)


def escribir_jsonl(ruta: Path, lineas) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_suffix(ruta.suffix + ".tmp")
    tmp.write_text("".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in lineas),
                   encoding="utf-8")
    tmp.replace(ruta)


def epoch_utc(s: str) -> float:
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def validar_sondas_previas(ruta: Path, ejecucion: str, ahora: float, margen_s: float = MARGEN_SONDA_S):
    """Comprueba el registro de `sondear` antes de arrancar: misma ejecución, todas las
    comprobaciones y sondas correctas, y el margen respecto a la última sonda ya cumplido.
    Devuelve (fallos, resumen)."""
    fallos = []
    try:
        lineas = [json.loads(x) for x in ruta.read_text(encoding="utf-8").splitlines() if x.strip()]
    except (OSError, ValueError) as e:
        return ["registro de sondas ilegible: %s" % e], {}
    s = [x for x in lineas if x.get("tipo") == "sonda"]
    if not s:
        fallos.append("registro sin sondas")
    if any(x.get("ejecucion_id") != ejecucion for x in lineas):
        fallos.append("el registro de sondas es de otra ejecución")
    fallos += ["comprobación previa falla: %s" % x["comprobacion"] for x in lineas
               if x.get("tipo") == "comprobacion" and not x.get("ok") and not x["comprobacion"].startswith("no cruza")]
    fallos += ["sonda falla: %s" % x["sonda"] for x in s if x.get("clase") != "ok"]
    fin = max((epoch_utc(x["fin_utc"]) for x in s), default=None)
    if fin is not None and ahora < fin + margen_s:
        fallos.append("margen de sonda no cumplido: faltan %.1f s" % (fin + margen_s - ahora))
    return fallos, {"sondas": len(s), "ultima_sonda_fin_epoch": fin, "margen_s": margen_s,
                    "margen_real_s": None if fin is None else ahora - fin}


# -- supervisor ----------------------------------------------------------------
def supervisar(a) -> int:
    d = RAIZ / a.ejecucion
    prog = prg.cargar(a.programa)
    log = open(d / "supervisor.jsonl", "a", encoding="utf-8")
    iniciado_epoch = time.time()
    interrupcion = None

    def ev(tipo, **k):
        log.write(json.dumps(dict(k, tipo=tipo, utc=utc(), monotonic=time.monotonic()), sort_keys=True) + "\n")
        log.flush()

    hijos = {}
    for perfil, p in prog["perfiles"].items():
        out = open(d / ("salida-%s.txt" % perfil), "a")
        hijos[perfil] = subprocess.Popen(
            [sys.executable, str(GEN / "clientes_lab_v2.py"), "--programa", str(d / "programa.json"),
             "--perfil", perfil, "--origen", p["origen"], "--ejecucion", a.ejecucion, "--salida", str(d)],
            stdout=out, stderr=subprocess.STDOUT)
        ev("perfil_lanzado", perfil=perfil, pid=hijos[perfil].pid)
    (d / "pids.json").write_text(json.dumps({"supervisor": os.getpid(), **{k: v.pid for k, v in hijos.items()}}))

    def reenviar(signum, _f):
        nonlocal interrupcion
        motivo_f = d / "motivo-parada.txt"
        interrupcion = motivo_f.read_text(encoding="utf-8").strip() if motivo_f.exists() else signal.Signals(signum).name
        ev("senal_recibida", nombre=signal.Signals(signum).name)
        ev("interrupcion", motivo=interrupcion)
        for h in hijos.values():
            if h.poll() is None:
                h.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGTERM, reenviar)
    signal.signal(signal.SIGINT, reenviar)
    vivos = dict(hijos)
    while vivos:
        if getattr(a, "requiere_permiso", False) and interrupcion is None:
            interrupcion = detener_sin_permiso(d, vivos, iniciado_epoch, max_s=a.permiso_max_s,
                                               gracia_s=a.permiso_gracia_s)
            if interrupcion:
                ev("interrupcion", motivo=interrupcion)
        for perfil, h in list(vivos.items()):
            rc = h.poll()
            if rc is not None:
                ev("perfil_terminado", perfil=perfil, codigo=rc,
                   clasificacion="completo" if rc == 0 else ("parado" if rc == 3 else "interrupcion"))
                del vivos[perfil]
        if vivos:
            time.sleep(1)
    (d / "relojes-fin.json").write_text(json.dumps(relojes(), indent=1, sort_keys=True))
    fin = {"ejecucion": a.ejecucion, "entorno_fin": entorno(),
           "estado": "incompleta" if interrupcion or any(h.returncode != 0 for h in hijos.values()) else "completa",
           "motivo": interrupcion,
           "codigos": {k: v.returncode for k, v in hijos.items()},
           "ficheros": {p.name: sha(p) for p in sorted(d.glob("*.jsonl")) if p.name != "supervisor.jsonl"}}
    (d / "manifiesto-fin.json").write_text(json.dumps(fin, indent=1, sort_keys=True))
    ev("fin", codigos=fin["codigos"])
    return 0


def iniciar(a) -> int:
    if not ID_OK.match(a.ejecucion):
        raise SystemExit("identificador inválido (V2-<JORNADA>-AAAAMMDDTHHMMSSZ): %s" % a.ejecucion)
    prog = prg.cargar(a.programa)
    d = RAIZ / a.ejecucion
    if d.exists():
        raise SystemExit("ya existe %s: una ejecución no se reutiliza; usa un identificador nuevo" % d)
    comprobaciones = preflight(prog)
    resumen_sondas = None
    if a.sondas_previas:
        # Las sondas de red ya se hicieron con `sondear`, con margen antes del periodo útil: aquí solo
        # se repiten las comprobaciones locales, que no generan tráfico.
        fallos_previos, resumen_sondas = validar_sondas_previas(Path(a.sondas_previas), a.ejecucion,
                                                                time.time(), a.margen_sonda_s)
        resultado_sondas, reg_sondas = [], []
    else:
        resultado_sondas, reg_sondas = sondas(prog, a.ejecucion, "iniciar")
        fallos_previos = []
    fallos = [x for x in comprobaciones + resultado_sondas if not x[1] and not x[0].startswith("no cruza")]
    if (fallos or fallos_previos) and not a.forzar:
        for f in fallos + fallos_previos:
            print("FALLA", f)
        raise SystemExit("preflight con fallos; no se inicia")
    d.mkdir(parents=True)
    shutil.copy2(a.programa, d / "programa.json")
    # Registro del preflight completo dentro de la ejecución: las sondas previas (si las hubo) y lo
    # comprobado al iniciar. contraste_dns.py y ventanas_sonda.py lo leen de aquí.
    previas = []
    if a.sondas_previas:
        previas = [json.loads(x) for x in Path(a.sondas_previas).read_text(encoding="utf-8").splitlines() if x.strip()]
    escribir_jsonl(d / "preflight.jsonl", previas + registro_preflight(a.ejecucion, "iniciar", comprobaciones, reg_sondas))
    ini = {"ejecucion": a.ejecucion, "programa_origen": str(Path(a.programa).resolve()),
           "programa_sha256": sha(d / "programa.json"), "programa_id": prog["programa_id"],
           "jornada_id": prog.get("jornada_id"), "duracion_s": prog["duracion_s"],
           "perfiles": {k: v["origen"] for k, v in prog["perfiles"].items()},
           "semillas": {b["id"]: b["semillas"] for b in prog["bloques"]},
           "preflight_forzado": bool(fallos or fallos_previos),
           "preflight_fallos_forzados": [list(f) for f in fallos] + fallos_previos,
           # Sin sondas previas la sonda cae al arrancar, dentro del periodo útil (Bloque 1, revisión 26-nov).
           "sondas": {"modo": "previas" if a.sondas_previas else "al_iniciar",
                      "registro": "preflight.jsonl", "resumen_previas": resumen_sondas,
                      "margen_exigido_s": a.margen_sonda_s if a.sondas_previas else None},
           "entorno_inicio": entorno()}
    (d / "manifiesto-inicio.json").write_text(json.dumps(ini, indent=1, sort_keys=True))
    (d / "relojes-inicio.json").write_text(json.dumps(relojes(), indent=1, sort_keys=True))
    sup = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_supervisar",
                            "--programa", str(d / "programa.json"), "--ejecucion", a.ejecucion,
                            "--permiso-max-s", str(a.permiso_max_s), "--permiso-gracia-s", str(a.permiso_gracia_s),
                            "--requiere-permiso" if a.requiere_permiso else "--sin-requiere-permiso"],
                           stdout=open(d / "supervisor-salida.txt", "a"), stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL, start_new_session=True)
    print(json.dumps({"ejecucion": a.ejecucion, "directorio": str(d), "supervisor_pid": sup.pid,
                      "programa_sha256": ini["programa_sha256"], "inicio_utc": ini["entorno_inicio"]["utc"]}))
    return 0


def vivo(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def estado(a) -> int:
    d = RAIZ / a.ejecucion
    pids = json.loads((d / "pids.json").read_text()) if (d / "pids.json").exists() else {}
    fin = d / "manifiesto-fin.json"
    manifiesto = json.loads(fin.read_text()) if fin.exists() else {}
    out = {"ejecucion": a.ejecucion, "terminado": fin.exists(), "terminada": fin.exists(),
           "fin_utc": (manifiesto.get("entorno_fin") or {}).get("utc") or manifiesto.get("utc"),
           "estado": manifiesto.get("estado"), "perfiles": {}}
    if getattr(a, "json", False):
        print(json.dumps(out, sort_keys=True))
        return 0
    for k, pid in pids.items():
        info = {"pid": pid, "vivo": vivo(pid)}
        f = d / ("transacciones-%s.jsonl" % k)
        if f.exists():
            lineas = f.read_text(encoding="utf-8").splitlines()
            regs = [json.loads(x) for x in lineas]
            info["transacciones"] = len(regs)
            info["clases"] = {c: sum(r["clase"] == c for r in regs) for c in sorted({r["clase"] for r in regs})}
            info["ultima_utc"] = regs[-1]["fin_utc"] if regs else None
        out["perfiles"][k] = info
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


def parar(a) -> int:
    d = RAIZ / a.ejecucion
    if a.motivo:
        (d / "motivo-parada.txt").write_text(a.motivo, encoding="utf-8")
    pids = json.loads((d / "pids.json").read_text())
    supervisor_vivo = vivo(pids["supervisor"])
    if supervisor_vivo:
        os.kill(pids["supervisor"], signal.SIGTERM)
    else:
        for perfil, pid in pids.items():
            if perfil != "supervisor" and vivo(pid):
                os.kill(pid, signal.SIGTERM)
        fin = d / "manifiesto-fin.json"
        if not fin.exists():
            fin.write_text(json.dumps({"ejecucion": a.ejecucion, "estado": "incompleta",
                                       "motivo": a.motivo or "supervisor_ausente", "utc": utc()},
                                      indent=1, sort_keys=True))
    for _ in range(60):  # la acción más larga posible ronda los 10 s de espera de red
        if not vivo(pids["supervisor"]):
            break
        time.sleep(1)
    print("supervisor %s" % ("terminado" if not vivo(pids["supervisor"]) else "SIGUE VIVO: revisar"))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="orden", required=True)
    for n in ("preflight", "sondear", "iniciar", "_supervisar"):
        s = sub.add_parser(n)
        s.add_argument("--programa", required=True)
        if n in ("preflight", "sondear"):
            s.add_argument("--ejecucion", required=(n == "sondear"), default=None)
            s.add_argument("--registro", required=(n == "sondear"),
                           help="JSONL del preflight completo (comprobaciones y sondas)")
        else:
            s.add_argument("--ejecucion", required=True)
        if n == "iniciar":
            s.add_argument("--forzar", action="store_true", help="inicia aunque falle el preflight (queda registrado)")
            s.add_argument("--sondas-previas", default=None,
                           help="registro de `sondear`: no repite las sondas de red y exige el margen")
            s.add_argument("--margen-sonda-s", type=float, default=MARGEN_SONDA_S)
        if n not in ("preflight", "sondear"):
            s.add_argument("--requiere-permiso", dest="requiere_permiso", action="store_true", default=True)
            s.add_argument("--sin-requiere-permiso", dest="requiere_permiso", action="store_false")
            s.add_argument("--permiso-max-s", type=float, default=90.0)
            s.add_argument("--permiso-gracia-s", type=float, default=120.0)
    for n in ("estado", "parar"):
        s = sub.add_parser(n)
        s.add_argument("--ejecucion", required=True)
        if n == "estado":
            s.add_argument("--json", action="store_true")
        if n == "parar":
            s.add_argument("--motivo", default="")
    a = p.parse_args()
    if a.orden in ("preflight", "sondear"):
        if a.ejecucion is not None and not ID_OK.match(a.ejecucion):
            raise SystemExit("identificador inválido: %s" % a.ejecucion)
        prog = prg.cargar(a.programa)
        comprobaciones = preflight(prog)
        res_sondas, reg_sondas = sondas(prog, a.ejecucion, a.orden)
        res = comprobaciones + res_sondas
        if a.registro:
            escribir_jsonl(Path(a.registro), registro_preflight(a.ejecucion, a.orden, comprobaciones, reg_sondas))
        ok_total = all(ok for n, ok, _ in res if not n.startswith("no cruza"))
        if a.orden == "sondear":
            fin = max((epoch_utc(x["fin_utc"]) for x in reg_sondas), default=None)
            print(json.dumps({"ejecucion": a.ejecucion, "ok": ok_total, "sondas": len(reg_sondas),
                              "ultima_sonda_fin_epoch": fin, "margen_sonda_s": MARGEN_SONDA_S,
                              "generador_no_antes_de_epoch": None if fin is None else fin + MARGEN_SONDA_S,
                              "fallos": [n for n, ok, _ in res if not ok and not n.startswith("no cruza")]}))
        else:
            for nombre, ok, det in res:
                print("%-6s %-40s %s" % ("OK" if ok else "FALLA", nombre, det))
        return 0 if ok_total else 1
    return {"iniciar": iniciar, "_supervisar": supervisar, "estado": estado, "parar": parar}[a.orden](a)


if __name__ == "__main__":
    raise SystemExit(main())
