#!/usr/bin/env python3
"""Contadores de captura de Suricata (capture.kernel_packets / kernel_drops) desde los eventos `stats`
de la EVE dedicada de V2 (/var/log/suricata/v2/eve.json, copiada por el archivador en
capturas/<ID>/eve/).

Por qué de la EVE y no de stats.log: stats.log tiene `null-values` en su valor por omisión (no) y
OMITE los contadores que valen 0; la EVE sí los escribe. «No aparece en stats.log» significaba «vale
0», no «no se mide» (Bloque 1, revisión 5).

Estados de una serie de eventos (nunca se sustituye un dato ausente por cero):
  presente      todos los eventos traen capture.kernel_drops (puede valer 0)
  ausente       al menos un evento stats sin capture.kernel_drops
  sin_eventos   ningún evento stats en el intervalo
  reinicio      uptime o kernel_packets retroceden: el proceso se reinició y los contadores volvieron
                a cero; la pérdida durante el reinicio no es cuantificable
La lectura fallida (no se pudo leer la EVE) la registra quien lee: vigia_v2 (eve_error) o
revisar_criterios (fichero ausente => sin_eventos con falta de evidencia).

    python3 suricata_stats.py extraer EVE... --salida suricata-stats-<ID>.jsonl
    python3 suricata_stats.py evaluar FICHERO...
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

INTERVALO_STATS_S = 8           # stats.interval de /etc/suricata/suricata.yaml en Sensor1
HUECO_MAXIMO_S = 3 * INTERVALO_STATS_S


def epoch(ts: str) -> float:
    ts = ts.replace("Z", "+00:00")
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return dt.datetime.fromisoformat(ts).timestamp()


def eventos_stats(rutas) -> list[dict]:
    """Eventos stats de uno o varios EVE/JSONL, en orden de timestamp. Líneas ilegibles se ignoran
    (la EVE puede cortarse a mitad de línea en la copia del archivador)."""
    ev = []
    for r in rutas:
        with open(r, encoding="utf-8", errors="replace") as f:
            for linea in f:
                if '"stats"' not in linea:
                    continue
                try:
                    e = json.loads(linea)
                except ValueError:
                    continue
                if e.get("event_type") == "stats" and isinstance(e.get("stats"), dict):
                    ev.append(e)
    ev.sort(key=lambda e: epoch(e["timestamp"]))
    return ev


def lectura(e: dict) -> dict:
    """Un evento stats -> los campos que importan, con None cuando faltan (no 0)."""
    s = e.get("stats") or {}
    cap = s.get("capture")
    cap = cap if isinstance(cap, dict) else {}
    return {"timestamp": e.get("timestamp"), "uptime": s.get("uptime"),
            "kernel_packets": cap.get("kernel_packets"), "kernel_drops": cap.get("kernel_drops"),
            "errors": cap.get("errors")}


def evaluar(eventos: list[dict]) -> dict:
    L = [lectura(e) for e in eventos]
    r = {"eventos": len(L), "intervalo_stats_s": INTERVALO_STATS_S}
    if not L:
        r.update(estado="sin_eventos", delta_kernel_drops=None)
        return r
    r["primero"], r["ultimo"] = L[0]["timestamp"], L[-1]["timestamp"]
    ausentes = [x["timestamp"] for x in L if x["kernel_drops"] is None or x["kernel_packets"] is None]
    t = [epoch(x["timestamp"]) for x in L]
    huecos = [round(b - a, 3) for a, b in zip(t, t[1:]) if b - a > HUECO_MAXIMO_S]
    r["hueco_maximo_s"] = round(max((b - a for a, b in zip(t, t[1:])), default=0), 3)
    r["huecos_mayores_que_%ds" % HUECO_MAXIMO_S] = huecos
    if ausentes:
        r.update(estado="ausente", sin_kernel_drops=len(ausentes), primer_ausente=ausentes[0],
                 delta_kernel_drops=None)
        return r
    reinicios, tramos, ini = [], [], 0
    for i in range(1, len(L)):
        a, b = L[i - 1], L[i]
        up_atras = a["uptime"] is not None and b["uptime"] is not None and b["uptime"] < a["uptime"]
        if up_atras or b["kernel_packets"] < a["kernel_packets"] or b["kernel_drops"] < a["kernel_drops"]:
            reinicios.append(b["timestamp"])
            tramos.append((ini, i - 1))
            ini = i
    tramos.append((ini, len(L) - 1))
    d = sum(L[j]["kernel_drops"] - L[i]["kernel_drops"] for i, j in tramos)
    p = sum(L[j]["kernel_packets"] - L[i]["kernel_packets"] for i, j in tramos)
    r.update(delta_kernel_drops=d, delta_kernel_packets=p,
             kernel_drops=[L[0]["kernel_drops"], L[-1]["kernel_drops"]],
             kernel_packets=[L[0]["kernel_packets"], L[-1]["kernel_packets"]],
             uptime=[L[0]["uptime"], L[-1]["uptime"]],
             errors=[L[0]["errors"], L[-1]["errors"]])
    if reinicios:
        r.update(estado="reinicio", reinicios=reinicios)
    else:
        r["estado"] = "presente"
    return r


def extraer(rutas, salida: Path) -> dict:
    ev = eventos_stats(rutas)
    datos = "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in ev).encode("utf-8")
    salida.write_bytes(datos)
    return {"entradas": [str(r) for r in rutas], "salida": salida.name, "eventos": len(ev),
            "sha256": hashlib.sha256(datos).hexdigest(), "evaluacion": evaluar(ev)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    x = sub.add_parser("extraer"); x.add_argument("eve", nargs="+", type=Path); x.add_argument("--salida", type=Path, required=True)
    v = sub.add_parser("evaluar"); v.add_argument("ficheros", nargs="+", type=Path)
    a = ap.parse_args(argv)
    if a.orden == "extraer":
        print(json.dumps(extraer(a.eve, a.salida), ensure_ascii=False))
    else:
        print(json.dumps(evaluar(eventos_stats(a.ficheros)), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
