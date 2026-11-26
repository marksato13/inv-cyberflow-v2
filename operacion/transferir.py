#!/usr/bin/env python3
"""Coordina las transferencias de evidencia con las capturas (BASTIÓN, gadmin).

Una copia de gestión por el cortafuegos durante una captura se refleja en el SPAN y puede
desbordar su destino (VD3: un scp de 2,6 MB → 1 descarte en Gi2/0/19). Regla: NINGUNA copia
durante el intervalo completo de captura, que va desde que el lanzador crea el candado hasta que
el cierre ha parado el archivador y las dos referencias.

    python3 transferir.py comprobar                 # rc 0 libre, 3 captura en curso
    python3 transferir.py copiar -- <args de scp>   # comprueba, registra y copia
    python3 transferir.py candado crear <ID>        # lanzar_v2.sh (espera la holgura tras la última copia)
    python3 transferir.py candado quitar <ID>       # cerrar_v2.sh, con las capturas ya paradas
    python3 transferir.py solapes --desde E --hasta E --salida transferencias.json
    python3 transferir.py externa-inicio "<qué>"     # copia desde el portátil: imprime «ID INICIO»
    python3 transferir.py externa-fin ID INICIO RC

Cada copia queda en ~/cyberflow-v2/transferencias.jsonl (inicio, fin, rc, argumentos), también
las rechazadas. Así el cierre puede demostrar que ninguna cayó dentro de la captura.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(os.environ.get("CF_V2_BASE", Path.home() / "cyberflow-v2"))
CANDADO = BASE / "CAPTURA_EN_CURSO"
REGISTRO = BASE / "transferencias.jsonl"
HOLGURA_S = 60          # entre el fin de una copia y el arranque de una captura
LIBRE, OCUPADO = 0, 3
# Procesos que significan captura viva aunque falte el candado (defensa en profundidad)
PROCESOS = {"sensor1": "[a]rchivar_v2.py --ejecucion", "srvdmz": "[t]cpdump .* -w /home/adminsrvdmz/cyberflow-v2/extremo/"}


def ahora():
    return time.time()


def registrar(**d):
    REGISTRO.parent.mkdir(parents=True, exist_ok=True)
    with REGISTRO.open("a", encoding="utf-8") as f:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")


def leer_registro():
    if not REGISTRO.exists():
        return []
    salida = []
    for linea in REGISTRO.read_text(encoding="utf-8").splitlines():
        try:
            salida.append(json.loads(linea))
        except ValueError:
            salida.append({"ilegible": linea[:200]})
    return salida


def procesos_vivos(ejecutar=subprocess.run):
    vivos = {}
    for host, patron in PROCESOS.items():
        r = ejecutar(["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host,
                      "pgrep -af '%s' || true" % patron], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            vivos[host] = "sin_respuesta"          # sin respuesta = no se puede descartar una captura
        elif r.stdout.strip():
            vivos[host] = r.stdout.strip()[:200]
    return vivos


def estado(ejecutar=subprocess.run):
    """(libre, motivo). Libre solo si no hay candado y ningún proceso de captura responde vivo."""
    if CANDADO.exists():
        return False, "candado %s: %s" % (CANDADO, CANDADO.read_text(encoding="utf-8").strip())
    vivos = procesos_vivos(ejecutar)
    if vivos:
        return False, "procesos de captura: %s" % json.dumps(vivos, ensure_ascii=False)
    return True, "libre"


def copiar(args, ejecutar=subprocess.run):
    libre, motivo = estado(ejecutar)
    if not libre:
        registrar(tipo="rechazada", utc_epoch=ahora(), motivo=motivo, args=args)
        print("NO SE COPIA: " + motivo, file=sys.stderr)
        return OCUPADO
    inicio = ahora()
    registrar(tipo="inicio", inicio_epoch=inicio, args=args, pid=os.getpid())
    rc = ejecutar(["scp", "-q", "-o", "BatchMode=yes"] + args).returncode
    registrar(tipo="fin", inicio_epoch=inicio, fin_epoch=ahora(), rc=rc, args=args, pid=os.getpid())
    return rc


def externa_inicio(descripcion, ejecutar=subprocess.run):
    """Copia hecha desde fuera del bastión (portátil): se comprueba y se registra su inicio ANTES
    de copiar; devuelve el identificador para externa_fin. Mientras no tenga fin cuenta abierta."""
    libre, motivo = estado(ejecutar)
    if not libre:
        registrar(tipo="rechazada", utc_epoch=ahora(), motivo=motivo, args=["externa", descripcion])
        print("NO SE COPIA: " + motivo, file=sys.stderr)
        return OCUPADO, None
    inicio = round(ahora(), 6)          # VD5: el fin llega por la CLI con 6 decimales
    ident = "externa-%d" % int(inicio * 1000)
    registrar(tipo="inicio", inicio_epoch=inicio, args=["externa", descripcion], pid=ident)
    return LIBRE, "%s %.6f" % (ident, inicio)


def externa_fin(ident, inicio, rc):
    registrar(tipo="fin", inicio_epoch=float(inicio), fin_epoch=ahora(), rc=rc, args=["externa"], pid=ident)
    return LIBRE


def clave(x):
    """Empareja inicio y fin de una copia: pid + inicio a 6 decimales (VD5: un inicio sin redondear
    y su fin redondeado dejaban la copia «abierta» y el candado esperaba sin fin)."""
    i = x.get("inicio_epoch")
    return (x.get("pid"), round(i, 6) if isinstance(i, (int, float)) else i)


def ultima_copia_fin(reg):
    """Fin de la última copia; una copia iniciada sin fin registrado cuenta como en curso (ahora)."""
    fines = {}
    for x in reg:
        if x.get("tipo") == "inicio":
            fines.setdefault(clave(x), None)
        elif x.get("tipo") == "fin":
            fines[clave(x)] = x.get("fin_epoch")
    if not fines:
        return None
    return max((f if f is not None else ahora()) for f in fines.values())


def crear_candado(ident, holgura=HOLGURA_S, dormir=time.sleep, espera_max_s=900):
    """Crea el candado (atómico) y espera hasta `holgura` s tras la última copia: el archivador
    recoge también el anillo de los 30-35 s anteriores a su arranque."""
    BASE.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(CANDADO, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        print("ya hay una captura en curso: %s" % CANDADO.read_text(encoding="utf-8").strip(), file=sys.stderr)
        return OCUPADO
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("%s desde %.3f\n" % (ident, ahora()))
    limite = ahora() + espera_max_s
    while True:
        fin = ultima_copia_fin(leer_registro())
        if fin is None or ahora() >= fin + holgura:
            break
        if ahora() > limite:
            print("una copia no termina; no se arranca la captura", file=sys.stderr)
            CANDADO.unlink()
            return OCUPADO
        dormir(1)
    registrar(tipo="candado_creado", ejecucion=ident, utc_epoch=ahora(),
              ultima_copia_fin_epoch=fin, holgura_s=holgura)
    return LIBRE


def quitar_candado(ident):
    if not CANDADO.exists():
        return LIBRE
    if not CANDADO.read_text(encoding="utf-8").startswith(ident + " "):
        print("el candado es de otra ejecución: %s" % CANDADO.read_text(encoding="utf-8").strip(), file=sys.stderr)
        return OCUPADO
    CANDADO.unlink()
    registrar(tipo="candado_quitado", ejecucion=ident, utc_epoch=ahora())
    return LIBRE


def solapes(desde, hasta, reg=None):
    """Copias (y rechazos) cuyo intervalo toca [desde, hasta]. Una copia sin fin cuenta abierta."""
    reg = leer_registro() if reg is None else reg
    abiertas = {}
    copias = []
    for x in reg:
        k = clave(x)
        if x.get("tipo") == "inicio":
            abiertas[k] = x
        elif x.get("tipo") == "fin":
            abiertas.pop(k, None)
            copias.append(dict(inicio_epoch=x["inicio_epoch"], fin_epoch=x["fin_epoch"], rc=x.get("rc"),
                               args=x.get("args")))
    copias += [dict(inicio_epoch=x["inicio_epoch"], fin_epoch=None, rc=None, args=x.get("args"))
               for x in abiertas.values()]
    en = [c for c in copias if c["inicio_epoch"] <= hasta and (c["fin_epoch"] is None or c["fin_epoch"] >= desde)]
    rechazadas = [x for x in reg if x.get("tipo") == "rechazada" and desde <= x.get("utc_epoch", 0) <= hasta]
    return {"version": 1, "desde_epoch": desde, "hasta_epoch": hasta, "registro": str(REGISTRO),
            "registro_existe": REGISTRO.exists(), "copias_en_captura": en,
            "rechazadas_en_captura": len(rechazadas),
            "estado": "sin_copias" if not en else "copias_durante_captura"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    sub.add_parser("comprobar")
    c = sub.add_parser("copiar")
    c.add_argument("scp", nargs=argparse.REMAINDER)
    k = sub.add_parser("candado")
    k.add_argument("accion", choices=("crear", "quitar"))
    k.add_argument("ejecucion")
    x = sub.add_parser("externa-inicio")
    x.add_argument("descripcion")
    y = sub.add_parser("externa-fin")
    y.add_argument("ident")
    y.add_argument("inicio", type=float)
    y.add_argument("rc", type=int)
    s = sub.add_parser("solapes")
    s.add_argument("--desde", type=float, required=True)
    s.add_argument("--hasta", type=float, required=True)
    s.add_argument("--salida", required=True)
    a = ap.parse_args(argv)
    if a.orden == "comprobar":
        libre, motivo = estado()
        print(motivo)
        return LIBRE if libre else OCUPADO
    if a.orden == "copiar":
        args = a.scp[1:] if a.scp[:1] == ["--"] else a.scp
        return copiar(args)
    if a.orden == "externa-inicio":
        rc, token = externa_inicio(a.descripcion)
        if token:
            print(token)
        return rc
    if a.orden == "externa-fin":
        return externa_fin(a.ident, a.inicio, a.rc)
    if a.orden == "candado":
        return crear_candado(a.ejecucion) if a.accion == "crear" else quitar_candado(a.ejecucion)
    r = solapes(a.desde, a.hasta)
    Path(a.salida).write_text(json.dumps(r, indent=1, ensure_ascii=False), encoding="utf-8")
    print(r["estado"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
