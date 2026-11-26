#!/usr/bin/env python3
"""Resumen publicable de la prueba de gestión con contadores de toda la cadena (prueba_gestion_esxi.sh).

    python3 resumir_gestion_esxi.py --dir <carpeta de la prueba> --salida resumen.json

Lee contadores-C*.txt (switch, ESXi, vmxnet3, invitado), marcas.jsonl y copias-gestion.json
(copias_espejo.py) y da, por tramo entre marcas, el incremento de cada contador y las copias de
gestión faltantes con su instante. Los puertos del vSwitch se publican por función, no por número
ni MAC.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re

FUNCION = {"2281701388": "uplink_vmnic2", "134217746": "vnic_sensor1_espejo", "134217750": "vnic_suricata_espejo"}
INTERFAZ = {"Gi2/0/19": "switch_destino_span", "Gi1/0/23": "switch_origen_1", "Gi2/0/23": "switch_origen_2"}


def contadores(texto: str) -> dict:
    r, sec = {}, None
    for l in texto.splitlines():
        if l.startswith("## utc"):
            r["epoch"] = float(l.split()[-1])
        elif l.startswith("## switch"):
            sec = INTERFAZ.get(l.split()[-1], l.split()[-1])
        elif l.startswith("## esxi"):
            sec = "vmnic2"
        elif l.startswith("## sensor1"):
            sec = "invitado_ens37"
        elif l.startswith("port "):
            sec = FUNCION.get(l.split()[1], "puerto")
        elif l.startswith("vmxnet3"):
            sec = "vmxnet3_sensor1"
        for pat, k in ((r"(\d+) packets input", "paquetes_entrada"), (r"(\d+) packets output", "paquetes_salida"),
                       (r"Total output drops: (\d+)", "descartes_salida"), (r"(\d+) input errors", "errores_entrada"),
                       (r"(\d+) output errors", "errores_salida")):
            m = re.search(pat, l)
            if m and sec in INTERFAZ.values():
                r[sec + "." + k] = int(m.group(1))
        m = re.match(r"\s*([A-Za-z#][^:]*):\s*(\d+)\s*$", l) or re.match(r"(rx_\w+) (\d+)$", l)
        if m and sec and sec not in INTERFAZ.values():
            r[sec + "." + m.group(1).strip()] = int(m.group(2))
    return r


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--salida", required=True)
    a = ap.parse_args(argv)
    fs = sorted(glob.glob(os.path.join(a.dir, "contadores-C*.txt")))
    marcas = [os.path.basename(f)[len("contadores-"):-4] for f in fs]
    vals = [contadores(open(f, encoding="utf-8").read()) for f in fs]
    tramos = []
    cop = json.load(open(os.path.join(a.dir, "copias-gestion.json"), encoding="utf-8"))
    # Solo el par bastión <-> Sensor1 (la gestión que genera la prueba); copias_espejo da también el
    # tráfico del bastión con terceros, que no se publica.
    par = {"10.10.10.30", "10.10.60.11"}
    falt = [x for x in cop.get("anomalias", []) if x.get("clase") == "falta_copia"
            and set(x.get("identidad", [None, None, None])[1:3]) == par]
    for i in range(len(vals) - 1):
        t0, t1 = vals[i]["epoch"], vals[i + 1]["epoch"]
        delta = {k: vals[i + 1][k] - vals[i][k] for k in vals[i] if k != "epoch" and k in vals[i + 1]}
        en = [x for x in falt if t0 <= x["ts"] < t1]
        por_vlan = {}
        for x in en:
            for v in x.get("vlans_faltan") or []:
                por_vlan[str(v)] = por_vlan.get(str(v), 0) + 1
        segs = sorted({int(x["ts"]) for x in en})
        tramos.append({"desde": marcas[i], "hasta": marcas[i + 1], "segundos": round(t1 - t0, 1),
                       "copias_gestion_faltantes": len(en), "faltantes_por_vlan": por_vlan,
                       "segundos_con_faltantes": len(segs),
                       "faltantes_rel_inicio_tramo_s": [round(s - t0) for s in segs][:20],
                       "incrementos": {k: v for k, v in sorted(delta.items()) if v}})
    den = cop.get("denominadores", {})
    out = {"version": 1, "tramos": tramos,
           "copias_resumen": {"resultado_global": cop.get("resultado_global"),
                              "entrada_completa": cop.get("entrada_completa"),
                              "integridad_entrada": cop.get("integridad_entrada"),
                              "eventos_por_clase_todo_el_bastion": den.get("eventos_por_clase"),
                              "por_vlan_faltante_todo_el_bastion": cop.get("por_vlan_faltante"),
                              "indicios": cop.get("indicios"), "pico_1s": cop.get("pico_1s"),
                              "pico_10ms": cop.get("pico_10ms"),
                              "intervalos_10ms_a_linea": cop.get("intervalos_10ms_a_linea")},
           "faltantes_par_bastion_sensor1": len(falt),
           "nota": "puertos vSwitch por función; sin MAC ni direcciones de gestión del ESXi"}
    json.dump(out, open(a.salida, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    for t in tramos:
        print(t["desde"], "->", t["hasta"], t["segundos"], "s faltan", t["copias_gestion_faltantes"],
              {k: v for k, v in t["incrementos"].items() if re.search(r"drop|descart|missed|err|full|buffers", k, re.I)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
