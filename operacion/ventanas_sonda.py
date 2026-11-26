#!/usr/bin/env python3
"""¿Qué ventanas de la población contienen la sonda DNS del preflight en su historia?

    python3 ventanas_sonda.py --ventanas extraccion/ventanas_meta.csv --dns calidad-contraste-dns.json \
        [--historia-s 230] --salida ventanas-sonda.json

Toma de contraste_dns.py las claves explicadas como `sonda_preflight` y el intervalo
[primera trama, última trama] de cada una (todas las fuentes). Una ventana de la misma
entidad queda afectada si [antecedentes_desde, cierre] toca ese intervalo (regla del §7.3 de
BLOQUE1-CIERRE). Informa también si la sonda cae antes del inicio de la primera ventana.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json


def ep(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ventanas", required=True)
    ap.add_argument("--dns", required=True)
    ap.add_argument("--historia-s", type=float, default=230)
    ap.add_argument("--salida", required=True)
    a = ap.parse_args(argv)
    d = json.load(open(a.dns, encoding="utf-8"))
    claves = {tuple(k) for k in d.get("sin_transaccion_clasificacion", {}).get("claves_explicadas", [])}
    if d["sin_transaccion"]["truncados"]:
        raise SystemExit("sin_transaccion truncado: aumentar --limite-lista en contraste_dns.py")
    sondas = {}
    for s in d["sin_transaccion"]["items"]:
        k = tuple(s["clave"])
        if k in claves:
            a0, b0 = sondas.get(k, (s["t"], s["t"]))
            sondas[k] = (min(a0, s["t"]), max(b0, s["t"]))
    ventanas = [v for v in csv.DictReader(open(a.ventanas, encoding="utf-8"))
                if v["regla_poblacion"] == "poblacion"]
    primera = min((ep(v["ventana_inicio_utc"]) for v in ventanas), default=None)
    filas = []
    for (cliente, puerto, ident), (desde, hasta) in sorted(sondas.items(), key=lambda x: x[1]):
        propias = [v for v in ventanas if v["entidad_ip"] == cliente]
        afectadas = []
        for v in propias:
            cierre = ep(v["ventana_cierre_utc"])
            antes = ep(v["antecedentes_desde_utc"]) if v.get("antecedentes_desde_utc") else cierre - a.historia_s
            if antes <= hasta and desde <= cierre:
                afectadas.append(v["ventana_id"])
        filas.append({"cliente": cliente, "puerto": puerto, "id": ident, "desde_epoch": desde, "hasta_epoch": hasta,
                      "antes_de_la_primera_ventana_s": None if primera is None else primera - hasta,
                      "ventanas_entidad": len(propias), "ventanas_afectadas": len(afectadas),
                      "ids_afectadas": afectadas})
    json.dump({"historia_s": a.historia_s, "ventanas_poblacion": len(ventanas), "sondas": filas},
              open(a.salida, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    for f in filas:
        print(f["cliente"], f["puerto"], "afectadas %d/%d" % (f["ventanas_afectadas"], f["ventanas_entidad"]),
              "antes_primera_ventana_s=%.3f" % f["antes_de_la_primera_ventana_s"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
