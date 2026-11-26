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
  sin_eventos   ningún evento stats
  insuficiente  sin muestras que acoten el periodo, con huecos mayores de 16 s o una sola muestra:
                no certifica nada (ok None), nunca «0 descartes»
  reinicio      uptime no avanza como el reloj o kernel_packets retroceden: el proceso se reinició y los contadores volvieron
                a cero; la pérdida durante el reinicio no es cuantificable
La lectura fallida (no se pudo leer la EVE) la registra quien lee: vigia_v2 (eve_error) o
revisar_criterios (fichero ausente => sin_eventos con falta de evidencia).

    python3 suricata_stats.py extraer EVE... --salida suricata-stats-<ID>.jsonl
    python3 suricata_stats.py ventana /var/log/suricata/v2/eve.json --desde E --hasta E --salida F
    python3 suricata_stats.py evaluar FICHERO... [--desde E --hasta E]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

INTERVALO_STATS_S = 8           # stats.interval de /etc/suricata/suricata.yaml en Sensor1
# Suficiencia temporal (revisión 6). kernel_drops es acumulado: el Δ entre dos muestras cuenta todo lo
# descartado entre ellas, pero NADA de lo que ocurra antes de la primera o después de la última. Por
# eso un periodo [inicio, fin] solo queda certificado si:
#  - hay una muestra en o antes de `inicio` y otra en o después de `fin` (lo acotan; una sola muestra,
#    o solo muestras interiores, dejan los bordes sin observar => «insuficiente», nunca 0);
#  - entre muestras consecutivas no hay más de HUECO_MAXIMO_S. Suricata escribe cada 8 s; en las 41 h
#    de la EVE dedicada (19 742 muestras, 25–26 nov) el intervalo máximo fue 8,0 s. Se tolera una
#    escritura retrasada (2 intervalos); más indica que la salida de stats se detuvo y no se puede
#    afirmar continuidad;
#  - el uptime avanza como el reloj (|Δuptime − Δt| ≤ TOLERANCIA_UPTIME_S; uptime va en segundos
#    enteros): si no, el proceso se reinició aunque el uptime nuevo no sea menor que el anterior.
# El Δ se mide entre las muestras que acotan el periodo: puede incluir hasta un intervalo fuera de él
# en cada extremo, lo que solo puede atribuir de más, nunca ocultar.
HUECO_MAXIMO_S = 2 * INTERVALO_STATS_S
TOLERANCIA_UPTIME_S = 2.0
# Antigüedad admisible de la lectura del vigía: dos intervalos más la latencia de ssh + tail (≤ 4 s).
ANTIGUEDAD_MAXIMA_S = 2 * INTERVALO_STATS_S + 4

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


def evaluar(eventos: list[dict], desde: float | None = None, hasta: float | None = None) -> dict:
    """Estado de kernel_drops en [desde, hasta]. Sin periodo no se certifica nada (insuficiente)."""
    L = sorted((lectura(e) for e in eventos), key=lambda x: epoch(x["timestamp"]))
    r = {"eventos": len(L), "intervalo_stats_s": INTERVALO_STATS_S, "hueco_maximo_admitido_s": HUECO_MAXIMO_S,
         "periodo": [desde, hasta]}
    if not L:
        r.update(estado="sin_eventos", delta_kernel_drops=None)
        return r
    if desde is not None and hasta is not None:
        antes = [i for i, x in enumerate(L) if epoch(x["timestamp"]) <= desde]
        despues = [i for i, x in enumerate(L) if epoch(x["timestamp"]) >= hasta]
        a = antes[-1] if antes else 0
        b = despues[0] if despues else len(L) - 1
        r["muestra_antes_s"] = round(desde - epoch(L[antes[-1]]["timestamp"]), 3) if antes else None
        r["muestra_despues_s"] = round(epoch(L[despues[0]]["timestamp"]) - hasta, 3) if despues else None
        L = L[a:b + 1]
        r["eventos_usados"] = len(L)
        acotado = bool(antes) and bool(despues)
    else:
        acotado = False
    r["primero"], r["ultimo"] = L[0]["timestamp"], L[-1]["timestamp"]
    t = [epoch(x["timestamp"]) for x in L]
    r["hueco_maximo_s"] = round(max((b - a for a, b in zip(t, t[1:])), default=0), 3)
    huecos = [[L[i]["timestamp"], round(t[i + 1] - t[i], 3)] for i in range(len(t) - 1) if t[i + 1] - t[i] > HUECO_MAXIMO_S]
    ausentes = [x["timestamp"] for x in L if x["kernel_drops"] is None or x["kernel_packets"] is None]
    if ausentes:
        r.update(estado="ausente", sin_kernel_drops=len(ausentes), primer_ausente=ausentes[0], delta_kernel_drops=None)
        return r
    reinicios, tramos, ini = [], [], 0
    for i in range(1, len(L)):
        x, y = L[i - 1], L[i]
        salto = None
        if x["uptime"] is not None and y["uptime"] is not None:
            salto = abs((y["uptime"] - x["uptime"]) - (t[i] - t[i - 1])) > TOLERANCIA_UPTIME_S
        if salto or y["kernel_packets"] < x["kernel_packets"] or y["kernel_drops"] < x["kernel_drops"]:
            reinicios.append(y["timestamp"])
            tramos.append((ini, i - 1))
            ini = i
    tramos.append((ini, len(L) - 1))
    r.update(delta_kernel_drops=sum(L[j]["kernel_drops"] - L[i]["kernel_drops"] for i, j in tramos),
             delta_kernel_packets=sum(L[j]["kernel_packets"] - L[i]["kernel_packets"] for i, j in tramos),
             kernel_drops=[L[0]["kernel_drops"], L[-1]["kernel_drops"]],
             kernel_packets=[L[0]["kernel_packets"], L[-1]["kernel_packets"]],
             uptime=[L[0]["uptime"], L[-1]["uptime"]], errors=[L[0]["errors"], L[-1]["errors"]])
    if reinicios:
        r.update(estado="reinicio", reinicios=reinicios)        # aunque falte cobertura: es un hecho
    elif not acotado or huecos or len(L) < 2:
        motivo = ("sin periodo" if desde is None or hasta is None else
                  "sin muestra en o antes del inicio" if r.get("muestra_antes_s") is None else
                  "sin muestra en o después del fin" if r.get("muestra_despues_s") is None else
                  "huecos mayores de %d s" % HUECO_MAXIMO_S if huecos else "una sola muestra")
        r.update(estado="insuficiente", motivo=motivo, huecos=huecos[:10], delta_kernel_drops_observado=r["delta_kernel_drops"],
                 delta_kernel_drops=None)
    else:
        r["estado"] = "presente"
    return r


def ventana(rutas, desde: float, hasta: float, margen: float, salida: Path) -> dict:
    """Eventos stats de la EVE dedicada COMPLETA en [desde − margen, hasta + margen]: aportan las
    muestras que acotan el periodo y que el recorte del archivador (interior) no lleva."""
    ev = [e for e in eventos_stats(rutas) if desde - margen <= epoch(e["timestamp"]) <= hasta + margen]
    datos = "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in ev).encode("utf-8")
    salida.write_bytes(datos)
    return {"salida": salida.name, "eventos": len(ev), "desde": desde, "hasta": hasta, "margen_s": margen,
            "sha256": hashlib.sha256(datos).hexdigest(), "evaluacion": evaluar(ev, desde, hasta)}

def extraer(rutas, salida: Path, desde=None, hasta=None) -> dict:
    ev = eventos_stats(rutas)
    datos = "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in ev).encode("utf-8")
    salida.write_bytes(datos)
    return {"entradas": [str(r) for r in rutas], "salida": salida.name, "eventos": len(ev),
            "sha256": hashlib.sha256(datos).hexdigest(), "evaluacion": evaluar(ev, desde, hasta)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    x = sub.add_parser("extraer"); x.add_argument("eve", nargs="+", type=Path); x.add_argument("--salida", type=Path, required=True)
    v = sub.add_parser("evaluar"); v.add_argument("ficheros", nargs="+", type=Path)
    v.add_argument("--desde", type=float); v.add_argument("--hasta", type=float)
    w = sub.add_parser("ventana"); w.add_argument("eve", nargs="+", type=Path)
    w.add_argument("--desde", type=float); w.add_argument("--hasta", type=float)
    w.add_argument("--manifiesto", type=Path, help="capturas/<ID>/manifiesto.json: toma inicio y fin del archivador")
    w.add_argument("--margen", type=float, default=30.0); w.add_argument("--salida", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.orden == "extraer":
        print(json.dumps(extraer(a.eve, a.salida), ensure_ascii=False))
    elif a.orden == "ventana":
        if a.manifiesto is not None:
            m = json.loads(a.manifiesto.read_text(encoding="utf-8"))
            a.desde, a.hasta = epoch(m["inicio"]), epoch(m["fin"])
        if a.desde is None or a.hasta is None:
            ap.error("ventana necesita --manifiesto o --desde y --hasta")
        r = ventana(a.eve, a.desde, a.hasta, a.margen, a.salida)
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r["evaluacion"]["estado"] != "insuficiente" else 3
    else:
        print(json.dumps(evaluar(eventos_stats(a.ficheros), a.desde, a.hasta), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
