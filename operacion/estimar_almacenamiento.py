#!/usr/bin/env python3
"""Estimación del almacenamiento por fase y segmento a partir de un programa V2 (cota superior).

Modelo (por perfil, en cada segundo t del programa):
  acciones/s ≈ factor(t) / ritmo_s          (cota superior: ignora la duración de cada acción)
  bytes/acción = Σ peso_a · tamaño_a / Σ peso   (tamaños de la tabla TAMANOS; ver TAM_ACCION)
  ráfaga de errático: factor medio extra = 1 + p·E[duración]·(factor_ráfaga−1)/(ritmo/factor) acotado
PCAP ≈ (bytes de aplicación · copias del espejo · (1 + sobrecarga) ) + fondo medido.
EVE ≈ eventos por acción · bytes por evento + fondo medido.

Los parámetros empíricos (sobrecarga, fondo, bytes por evento) se pasan por argumento y se
calibran con una ejecución real (``--calibrar`` con el manifiesto y las transacciones de esa
ejecución). No usa ninguna métrica del detector.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI.parent / "generador"))
import programa as prg  # noqa: E402

KB = 1024
# bytes de respuesta típicos por acción (cuerpo + cabeceras ~160 B); abandono = cota (descarga entera)
TAM_ACCION = {
    "web_pequena": (60 + 4 * KB + 16 * KB) / 3 + 160, "web_media": (64 + 128 + 256) * KB / 3 + 160,
    "web_grande": (1024 + 2048 + 4096) * KB / 3 + 160, "https": (60 + 15 + 32 * KB) / 3 + 160 + 3000,
    "api_ok": 175, "api_post": 180 + 4100, "api_auth": 120, "api_404": 180, "api_500": 190, "api_lento": 190,
    "dns": 120, "dns_inexistente": 120, "ping": 98, "puerto_cerrado": 60, "abandono": 2048 * KB,
}


def bytes_por_accion(perfil: dict) -> float:
    w = perfil["acciones"]
    return sum(TAM_ACCION[a] * p for a, p in w.items()) / sum(w.values())


def estimar(prog: dict, copias: float, sobrecarga: float, fondo_pcap_gbh: float, fondo_eve_mbh: float,
            eve_b_por_accion: float, paso: int = 10) -> dict:
    res, total = [], {"pcap_gb": 0.0, "eve_gb": 0.0, "app_gb": 0.0, "acciones": 0.0}
    claves = prog["fases"]
    for f in claves:
        app = acc = 0.0
        for t in range(int(f["inicio_s"]), int(f["fin_s"]), paso):
            for nombre, p in prog["perfiles"].items():
                fac, _, _ = prg.factor(prog, nombre, t)
                if fac <= 0:
                    continue
                r = prog.get("rafagas", {}).get(nombre)
                if r:
                    med = sum(r["duracion_s"]) / 2
                    it_s = fac / p["ritmo_s"]
                    frac = min(1.0, r["probabilidad_por_iteracion"] * it_s * med)  # fracción del tiempo en ráfaga
                    fac *= (1 - frac) + frac * r["factor"]
                a = fac / p["ritmo_s"] * paso
                acc += a
                app += a * bytes_por_accion(p)
        dur_h = (f["fin_s"] - f["inicio_s"]) / 3600
        pcap = app * copias * (1 + sobrecarga) / 1e9 + fondo_pcap_gbh * dur_h
        eve = (acc * eve_b_por_accion) / 1e9 + fondo_eve_mbh * dur_h / 1e3
        res.append({"fase": f["id"], "segmento": f.get("segmento"), "horas": round(dur_h, 3),
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
