#!/usr/bin/env python3
"""¿Qué ventanas elimina una exclusión por intervalos, y elimina preferentemente un perfil o la actividad alta?

    python3 sesgo_exclusion.py --ventanas extraccion/ventanas_meta.csv --intervalos registros/invalidaciones.jsonl \
        [--historia-s 230] --salida sesgo.json

Ventanas consideradas: las de la población (regla_poblacion == "poblacion") que el programa no excluye
ya por otros motivos (excluir_entrenamiento == False). Una ventana queda afectada si su intervalo de
antecedentes [antecedentes_desde, cierre] toca algún intervalo [desde_epoch, hasta_epoch]. Si la
ventana no trae antecedentes_desde se usa cierre − historia_s. Informa, para todas y para las
afectadas: número por perfil, por nivel y por cuartil de paquetes en la ventana (los cuartiles se
calculan sobre todas las ventanas consideradas).
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import json


def ep(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ventanas", required=True)
    ap.add_argument("--intervalos", required=True, help="JSONL con desde_epoch y hasta_epoch")
    ap.add_argument("--historia-s", type=float, default=230)
    ap.add_argument("--salida", required=True)
    a = ap.parse_args()
    iv = [(float(x["desde_epoch"]), float(x["hasta_epoch"])) for x in
          (json.loads(l) for l in open(a.intervalos, encoding="utf-8") if l.strip())]
    filas = [r for r in csv.DictReader(open(a.ventanas, encoding="utf-8"))
             if r.get("regla_poblacion") == "poblacion" and r.get("excluir_entrenamiento") == "False"]
    paq = sorted(int(r["n_paquetes_ventana"] or 0) for r in filas)
    cortes = [paq[int(len(paq) * q)] for q in (.25, .5, .75)] if paq else []

    def cuartil(n):
        return "Q%d" % (1 + sum(n > c for c in cortes))

    tot, af = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    for r in filas:
        c = ep(r["ventana_cierre_utc"])
        d = ep(r["antecedentes_desde_utc"]) if r.get("antecedentes_desde_utc") else c - a.historia_s
        afectada = any(d <= h and c >= s for s, h in iv)
        for clave, v in (("perfil", r["perfil"]), ("nivel", r["nivel"]), ("cuartil_paquetes", cuartil(int(r["n_paquetes_ventana"] or 0)))):
            tot[clave][v] += 1
            if afectada:
                af[clave][v] += 1
    out = {"ventanas_consideradas": len(filas), "intervalos": len(iv),
           "afectadas": sum(af["perfil"].values()), "cortes_cuartiles_paquetes": cortes,
           "por": {k: {v: {"todas": tot[k][v], "afectadas": af[k][v],
                           "fraccion": round(af[k][v] / tot[k][v], 3) if tot[k][v] else None}
                       for v in sorted(tot[k])} for k in tot}}
    json.dump(out, open(a.salida, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
