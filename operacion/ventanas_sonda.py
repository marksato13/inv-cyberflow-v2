#!/usr/bin/env python3
"""¿Tocan las sondas del preflight alguna ventana útil de la población?

    python3 ventanas_sonda.py --ventanas extraccion/ventanas_meta.csv \
        --preflight generador/ID/preflight.jsonl [--dns calidad-contraste-dns.json] \
        [--historia-s 230] [--cola-s 1] --salida calidad-sonda.json

Intervalo de cada sonda: [inicio, fin + cola] del registro (DNS y HTTP/HTTPS/consulta/envío), unido
a las tramas DNS que contraste_dns.py relacionó con ella. La cola cubre los paquetes de cierre TCP
que llegan tras el fin registrado en el cliente.

Una ventana de la misma entidad está TOCADA si [antecedentes_desde, cierre] (o cierre − historia)
corta ese intervalo (regla del CIERRE §7.3, la misma del extractor). Se separan:
  - tocadas ya excluidas por una GUARDA PLANIFICADA (E1 estado, E5 fuera del programa): no cuentan;
  - tocadas ÚTILES (ninguna guarda planificada; pueden tener otros motivos de incidente): contaminadas.
Estado: «sin_contaminacion» (0 útiles tocadas), «contaminacion_en_periodo_util», «sin_registro»
(no hay preflight.jsonl: no se puede afirmar nada) o «sin_ventanas».
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from collections import defaultdict

GUARDAS_PLANIFICADAS = ("E1:", "E5:")


def ep(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def intervalos(preflight_lineas, dns=None, cola_s=1.0):
    """{origen_ip: [(desde, hasta, etiqueta)]} a partir del registro y de las relaciones DNS."""
    por_ip = defaultdict(list)
    for x in preflight_lineas:
        if x.get("tipo") != "sonda" or not x.get("origen_ip"):
            continue
        por_ip[x["origen_ip"]].append([ep(x["inicio_utc"]), ep(x["fin_utc"]) + cola_s,
                                       "%s/%s" % (x.get("contexto"), x.get("sonda"))])
    for rel in ((dns or {}).get("sin_transaccion_clasificacion") or {}).get("relaciones", []):
        cliente, t = rel["clave"][0], rel["t"]
        for iv in por_ip.get(cliente, []):
            if iv[0] - cola_s <= t <= iv[1] + cola_s:
                iv[0], iv[1] = min(iv[0], t), max(iv[1], t)
    return por_ip


def es_guarda(motivos: str) -> bool:
    return any(m.startswith(GUARDAS_PLANIFICADAS) for m in filter(None, (motivos or "").split(";")))


def evaluar(ventanas, por_ip, historia_s=230.0):
    filas, utiles_total, guardadas_total = [], 0, 0
    for ip, ivs in sorted(por_ip.items()):
        propias = [v for v in ventanas if v["entidad_ip"] == ip]
        t0s = [ep(v["ventana_cierre_utc"]) - float(v["t_programa_s"]) for v in propias if v.get("t_programa_s")]
        t0 = min(t0s) if t0s else None
        for desde, hasta, etiqueta in ivs:
            utiles, guardadas = [], []
            for v in propias:
                cierre = ep(v["ventana_cierre_utc"])
                antes = ep(v["antecedentes_desde_utc"]) if v.get("antecedentes_desde_utc") else cierre - historia_s
                antes = min(antes, cierre - historia_s)
                if antes <= hasta and desde <= cierre:
                    (guardadas if es_guarda(v.get("motivos_exclusion")) else utiles).append(v["ventana_id"])
            utiles_total += len(utiles)
            guardadas_total += len(guardadas)
            filas.append({"origen_ip": ip, "sonda": etiqueta, "desde_epoch": desde, "hasta_epoch": hasta,
                          "t0_perfil_epoch": t0, "margen_hasta_t0_s": None if t0 is None else t0 - hasta,
                          "ventanas_entidad": len(propias), "tocadas_en_guarda_planificada": len(guardadas),
                          "tocadas_utiles": len(utiles), "ids_utiles": utiles[:200]})
    return filas, utiles_total, guardadas_total


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ventanas", required=True)
    ap.add_argument("--preflight", nargs="*", default=[])
    ap.add_argument("--dns")
    ap.add_argument("--historia-s", type=float, default=230)
    ap.add_argument("--cola-s", type=float, default=1.0)
    ap.add_argument("--salida", required=True)
    a = ap.parse_args(argv)
    lineas = []
    for ruta in a.preflight:
        try:
            lineas += [json.loads(x) for x in open(ruta, encoding="utf-8") if x.strip()]
        except (OSError, ValueError) as e:
            print("registro de sondas ilegible: %s" % e, file=sys.stderr)
    dns = json.load(open(a.dns, encoding="utf-8")) if a.dns else None
    ventanas = [v for v in csv.DictReader(open(a.ventanas, encoding="utf-8"))
                if v.get("regla_poblacion", "poblacion") in ("poblacion", "")]
    por_ip = intervalos(lineas, dns, a.cola_s)
    filas, utiles, guardadas = evaluar(ventanas, por_ip, a.historia_s)
    fuentes = sorted({x.get("fuente", "v2ctl") for x in lineas if x.get("tipo") == "sonda"})
    if not any(x.get("tipo") == "sonda" for x in lineas):
        estado = "sin_registro"
    elif not ventanas:
        estado = "sin_ventanas"
    else:
        estado = "sin_contaminacion" if utiles == 0 else "contaminacion_en_periodo_util"
    out = {"version": 2, "estado": estado, "fuentes_registro": fuentes, "historia_s": a.historia_s,
           "cola_s": a.cola_s, "guardas_planificadas": list(GUARDAS_PLANIFICADAS),
           "ventanas_poblacion": len(ventanas), "tocadas_utiles": utiles,
           "tocadas_en_guarda_planificada": guardadas, "sondas": filas}
    json.dump(out, open(a.salida, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: out[k] for k in ("estado", "tocadas_utiles", "tocadas_en_guarda_planificada")}))
    return 0 if estado == "sin_contaminacion" else (1 if estado == "contaminacion_en_periodo_util" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
