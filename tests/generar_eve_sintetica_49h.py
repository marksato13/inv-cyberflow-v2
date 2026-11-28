#!/usr/bin/env python3
"""Genera una EVE TÉCNICA SINTÉTICA para medir el cierre; no pertenece al dataset de investigación.

Los nombres de contadores siguen la forma de un evento stats publicado de VD6. Todos sus valores se
reemplazan por valores sintéticos. Hay 22 051 muestras cada 8 s, de 00:00 a 49:00 h inclusive;
los flow con relleno solo dan el tamaño solicitado y no contienen tráfico ni identificadores reales.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VD6 = "V2-VD6-20261126T151456Z"
MUESTRA = (REPO / "evidencias" / "bloque1" / "suricata-r5" / VD6 / "capturas" / VD6 /
           "eve" / ("suricata-stats-%s.jsonl" % VD6))
T0 = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
INTERVALO_S = 8
N = 49 * 3600 // INTERVALO_S + 1


def sintetizar(v):
    if isinstance(v, dict):
        return {k: sintetizar(x) for k, x in v.items()}
    if isinstance(v, list):
        return [sintetizar(x) for x in v]
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return 100000
    if isinstance(v, float):
        return 1.0
    if isinstance(v, str):
        return "sintetico"
    return None


def generar(salida: Path, tamano_bytes: int, muestra: Path = MUESTRA) -> dict:
    ejemplo = json.loads(muestra.open(encoding="utf-8").readline())
    base = sintetizar(ejemplo["stats"])
    base["capture"]["kernel_drops"] = 0
    base["capture"]["errors"] = 0
    # El tamaño por stats conserva el orden de magnitud del registro real (~9 KB).
    muestra = {"timestamp": T0.isoformat(), "event_type": "stats", "stats": base}
    stat_bytes = len((json.dumps(muestra, sort_keys=True, ensure_ascii=False) + "\n").encode())
    flow_relleno = "x" * 4000
    flow_ejemplo = {"timestamp": T0.isoformat(), "event_type": "flow", "synthetic_padding": flow_relleno}
    flow_bytes = len((json.dumps(flow_ejemplo, sort_keys=True) + "\n").encode())
    por_muestra = max(0, (tamano_bytes - N * stat_bytes) // N // flow_bytes)
    h, hs = hashlib.sha256(), hashlib.sha256()
    total = stats_bytes = 0
    salida.parent.mkdir(parents=True, exist_ok=True)
    with salida.open("wb") as f:
        def escribir(b, stats=False):
            nonlocal total, stats_bytes
            f.write(b)
            h.update(b)
            total += len(b)
            if stats:
                hs.update(b)
                stats_bytes += len(b)

        for i in range(N):
            marca = (T0 + dt.timedelta(seconds=i * INTERVALO_S)).isoformat()
            s = copy.deepcopy(base)
            s["uptime"] = 100000 + i * INTERVALO_S
            s["capture"]["kernel_packets"] = 1000000 + 1000 * i
            evento = {"timestamp": marca, "event_type": "stats", "stats": s}
            escribir((json.dumps(evento, sort_keys=True, ensure_ascii=False) + "\n").encode(), True)
            if por_muestra:
                flow = {"timestamp": marca, "event_type": "flow", "synthetic_padding": flow_relleno}
                b = (json.dumps(flow, sort_keys=True) + "\n").encode()
                escribir(b * por_muestra)
        # Ajuste del volumen con eventos flow válidos, posteriores a la última muestra stats.
        while total + flow_bytes <= tamano_bytes:
            escribir((json.dumps({"timestamp": marca, "event_type": "flow",
                                   "synthetic_padding": flow_relleno}, sort_keys=True) + "\n").encode())
    return {"tipo": "prueba tecnica sintetica; excluida del conjunto de investigacion",
            "fuente_forma": "evento stats publicado de VD6; valores sustituidos",
            "muestras_stats": N, "periodo_s": 49 * 3600, "intervalo_s": INTERVALO_S,
            "desde": T0.timestamp(), "hasta": (T0 + dt.timedelta(hours=49)).timestamp(),
            "kernel_drops": [0, 0], "kernel_packets": [1000000, 1000000 + 1000 * (N - 1)],
            "uptime": [100000, 100000 + 49 * 3600], "bytes": total,
            "stats_bytes": stats_bytes, "sha256_eve": h.hexdigest(), "sha256_stats": hs.hexdigest()}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--salida", type=Path, required=True)
    p.add_argument("--tamano-bytes", type=int, default=2_800_000_000)
    p.add_argument("--manifiesto", type=Path, required=True)
    p.add_argument("--muestra", type=Path, default=MUESTRA)
    a = p.parse_args()
    m = generar(a.salida, a.tamano_bytes, a.muestra)
    a.manifiesto.parent.mkdir(parents=True, exist_ok=True)
    a.manifiesto.write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(m, ensure_ascii=False))
