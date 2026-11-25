#!/usr/bin/env python3
"""Estimación aproximada de almacenamiento para los programas v3.

Cuenta ciclos por perfil según el factor programado y su media de espera,
sin descontar la duración de las acciones. Incluye DNS y objetos secundarios
de P2 mediante sus medias publicadas. Los parámetros de captura se calibran
con datos medidos; no se usan métricas del detector.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI.parent / "generador"))
import programa as prg  # noqa: E402

# Medias de planificación; las muestras reales se concilian por transacción.
PARETO_N = sum((x - 2) * ((2 / x) ** 1.1 - (2 / (x + 1)) ** 1.1)
               for x in range(2, 55)) / (1 - (2 / 55) ** 1.1)


def bytes_por_ciclo(nombre: str) -> float:
    h1, h2, f1 = 10710, 7758, 2_000_000
    if nombre == "P2":
        return 120 + h1 + PARETO_N * h2 + (2 + PARETO_N) * 160 + 1500
    if nombre == "P3":
        return 120 + f1 + 160
    if nombre == "P4":
        return 120 + 2 * 512 + 80 + 4100 + 3 * 160
    return 120 + h1 + 160


def acciones_por_ciclo(nombre: str) -> float:
    return 2 + PARETO_N if nombre == "P2" else 4 if nombre == "P4" else 2


def estimar(prog: dict, copias: float, sobrecarga: float, fondo_pcap_gbh: float, fondo_eve_mbh: float,
            eve_b_por_accion: float, paso: int = 10) -> dict:
    res, total = [], {"pcap_gb": 0.0, "eve_gb": 0.0, "app_gb": 0.0, "acciones": 0.0}
    claves = prog["niveles"]
    for f in claves:
        app = acc = 0.0
        for t in range(int(f["inicio_s"]), int(f["fin_s"]), paso):
            for nombre, p in prog["perfiles"].items():
                fac = prog["factores"][f["perfiles"][nombre]]
                if fac <= 0 or (nombre == "P6" and not prg.on_p6(prog, t)):
                    continue
                ciclos = fac / p["media_espera_s"] * paso
                if nombre == "P4":
                    ciclos /= 3  # tres pausas por secuencia DNS→consulta→envío→consulta
                acc += ciclos * acciones_por_ciclo(nombre)
                app += ciclos * bytes_por_ciclo(nombre)
        dur_h = (f["fin_s"] - f["inicio_s"]) / 3600
        pcap = app * copias * (1 + sobrecarga) / 1e9 + fondo_pcap_gbh * dur_h
        eve = (acc * eve_b_por_accion) / 1e9 + fondo_eve_mbh * dur_h / 1e3
        res.append({"fase": f["id"], "segmento": prg.tramo_en(prog["jornadas"], f["inicio_s"])["id"], "horas": round(dur_h, 3),
                    "acciones": round(acc), "app_gb": round(app / 1e9, 3), "pcap_gb": round(pcap, 3),
                    "pcap_gb_h": round(pcap / dur_h, 3), "eve_gb": round(eve, 4)})
        total["pcap_gb"] += pcap
        total["eve_gb"] += eve
        total["app_gb"] += app / 1e9
        total["acciones"] += acc
    seg = {}
    for r in res:
        s = seg.setdefault(r["segmento"] or "-", {"pcap_gb": 0.0, "eve_gb": 0.0, "horas": 0.0})
        s["pcap_gb"] += r["pcap_gb"]
        s["eve_gb"] += r["eve_gb"]
        s["horas"] += r["horas"]
    for s in seg.values():
        s["pcap_gb_h"] = round(s["pcap_gb"] / s["horas"], 3)
        s["pcap_gb"] = round(s["pcap_gb"], 2)
        s["eve_gb"] = round(s["eve_gb"], 3)
    pico = max(res, key=lambda r: r["pcap_gb_h"])
    return {"programa": prog["programa_id"], "parametros": {"copias": copias, "sobrecarga": sobrecarga,
            "fondo_pcap_gb_h": fondo_pcap_gbh, "fondo_eve_mb_h": fondo_eve_mbh, "eve_bytes_por_accion": eve_b_por_accion},
            "total": {k: round(v, 2) for k, v in total.items()}, "por_segmento": seg,
            "fase_pico": {"fase": pico["fase"], "pcap_gb_h": pico["pcap_gb_h"]}, "por_fase": res}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("programa")
    ap.add_argument("--copias", type=float, default=2.0, help="copias por paquete en el espejo (hoy 2)")
    ap.add_argument("--sobrecarga", type=float, default=0.06, help="cabeceras Ethernet/802.1Q/IP/TCP y ACK")
    ap.add_argument("--fondo-pcap-gb-h", type=float, default=0.10)
    ap.add_argument("--fondo-eve-mb-h", type=float, default=8.6)
    ap.add_argument("--eve-b-por-accion", type=float, default=4300.0)
    ap.add_argument("--calibracion", type=float, default=1.0,
                    help="bytes de aplicación medidos / estimados en una ejecución real (T8: 0,667)")
    ap.add_argument("--compresion", type=float, default=1.0, help="razón de gzip de los PCAP archivados (T8, gzip-1: 14,0)")
    ap.add_argument("--resumen", action="store_true")
    a = ap.parse_args()
    prog = prg.cargar(a.programa)
    r = estimar(prog, a.copias * a.calibracion, a.sobrecarga, a.fondo_pcap_gb_h, a.fondo_eve_mb_h,
                a.eve_b_por_accion * a.calibracion)
    r["parametros"].update({"calibracion": a.calibracion, "compresion": a.compresion})
    r["total"]["pcap_gb_comprimido"] = round(r["total"]["pcap_gb"] / a.compresion, 2)
    r["fase_pico"]["pcap_gb_h_comprimido"] = round(r["fase_pico"]["pcap_gb_h"] / a.compresion, 3)
    if a.resumen:
        r.pop("por_fase")
    print(json.dumps(r, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
