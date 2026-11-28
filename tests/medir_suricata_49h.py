#!/usr/bin/env python3
"""Mide el paso de stats del cierre con EVE técnica sintética; no ejecuta una captura.

Exige 49 h de stats continuos (22 051 muestras) y un EVE de tamaño elegido. Prueba una lectura
decidida y cuatro intentos sin muestra posterior, con las tres esperas reales de 6 s. Guarda fases,
RSS y hashes. La ejecución integrada de cerrar_v2.sh sigue pendiente del Bloque 4.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "operacion"))
import suricata_stats as ss


def sha256(ruta):
    h = hashlib.sha256()
    with ruta.open("rb") as f:
        for trozo in iter(lambda: f.read(1024 * 1024), b""):
            h.update(trozo)
    return h.hexdigest()


def medir(eve, manifiesto, directorio):
    m = json.loads(manifiesto.read_text(encoding="utf-8"))
    if m["muestras_stats"] != 22051 or m["periodo_s"] != 49 * 3600:
        raise ValueError("el manifiesto no describe las 49 h completas")
    if sha256(eve) != m["sha256_eve"]:
        raise ValueError("sha256 de la EVE sintética distinto del manifiesto")
    directorio.mkdir(parents=True, exist_ok=True)
    resultados = []
    for caso, fin, rc_esperado, n_esperado in (
        ("completo", m["hasta"], 0, 1),
        ("sin_muestra_posterior", m["hasta"] + 1, 3, 4),
    ):
        salida = directorio / (caso + ".jsonl")
        fases = []
        t0 = time.perf_counter()
        rc, r = ss.ventana_cierre([eve], m["desde"], fin, 30, salida, reintentos=4, espera=6,
                                  perfiles=fases)
        duracion = time.perf_counter() - t0
        evaluacion = r.get("evaluacion", {})
        assert rc == rc_esperado and len(r["intentos"]) == n_esperado, (rc, r["intentos"])
        assert r["eventos"] == m["muestras_stats"] and evaluacion["eventos_usados"] == m["muestras_stats"]
        assert evaluacion["kernel_drops"] == m["kernel_drops"]
        assert evaluacion["kernel_packets"] == m["kernel_packets"]
        assert evaluacion["uptime"] == m["uptime"]
        assert evaluacion["hueco_maximo_s"] == 8
        assert r["sha256"] == m["sha256_stats"] == sha256(salida)
        assert evaluacion["estado"] == ("presente" if rc == 0 else "insuficiente")
        assert evaluacion.get("muestra_antes_s") == 0
        if rc == 0:
            assert evaluacion.get("muestra_despues_s") == 0
            assert evaluacion["delta_kernel_drops"] == 0
            assert evaluacion["delta_kernel_packets"] == 1000 * (m["muestras_stats"] - 1)
        else:
            assert evaluacion.get("muestra_despues_s") is None
            assert evaluacion["motivo"] == "sin muestra en o después del fin"
        pico = max((f.get("rss_tras_evaluacion_kb", {}).get("VmHWM", 0) for f in fases), default=0)
        resultados.append({"caso": caso, "rc": rc, "estado": evaluacion["estado"],
                           "eventos": r["eventos"], "eventos_usados": evaluacion["eventos_usados"],
                           "intervalo_evaluado_s": fin - m["desde"], "intentos": r["intentos"],
                           "duracion_total_s": round(duracion, 3), "fases": fases,
                           "pico_rss_kb": pico, "sha256_salida": r["sha256"]})
    return {"tipo": m["tipo"], "eve_bytes": m["bytes"], "eve_sha256": m["sha256_eve"],
            "stats_sha256": m["sha256_stats"], "resultados": resultados}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--eve", type=Path, required=True)
    p.add_argument("--manifiesto", type=Path, required=True)
    p.add_argument("--directorio", type=Path, required=True)
    p.add_argument("--resumen", type=Path, required=True)
    a = p.parse_args()
    r = medir(a.eve, a.manifiesto, a.directorio)
    a.resumen.parent.mkdir(parents=True, exist_ok=True)
    a.resumen.write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(r, ensure_ascii=False))
