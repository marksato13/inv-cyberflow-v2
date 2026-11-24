#!/usr/bin/env python3
"""Evalúa los criterios del piloto (PROTOCOLO §10, versión 2) sobre pruebas/<ID> en Sensor1.

    python3 evaluar_piloto.py --pruebas /home/m4rk/cyberflow-v2/pruebas/<ID> --capturas /home/m4rk/cyberflow-v2/capturas/<ID>

Escribe <pruebas>/criterios.json. Lo que necesita juicio (C9, C10, C12, C13) se extrae en bruto
con «revisar: true» y se dictamina en el informe; nada se aprueba por omisión.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import re
from pathlib import Path


def jsonl(p):
    p = Path(p)
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def cargar(p):
    p = Path(p)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pruebas", required=True)
    ap.add_argument("--capturas", required=True)
    a = ap.parse_args()
    P, CAP = Path(a.pruebas), Path(a.capturas)
    ID = P.name
    G = P / "generador" / ID
    prog = cargar(G / "programa.json")
    sup = jsonl(G / "supervisor.jsonl")
    man_g = cargar(G / "manifiesto-fin.json") or {}
    tx = [t for f in sorted(G.glob("transacciones-*.jsonl")) for t in jsonl(f)]
    ev = {Path(f).stem.split("-", 1)[1]: jsonl(f) for f in sorted(glob.glob(str(G / "eventos-*.jsonl")))}
    R = {}

    term = [s for s in sup if s.get("tipo") == "perfil_terminado"]
    R["C1"] = {"ok": len(term) == 6 and all(s["codigo"] == 0 for s in term) and man_g.get("estado") == "completa",
               "perfiles_terminados": len(term), "codigos": {s["perfil"]: s["codigo"] for s in term},
               "manifiesto": man_g.get("estado")}

    pausa = next(f for f in prog["fases"] if f["factor"] == 0)
    en_pausa = [t["transaccion_id"] for t in tx if pausa["inicio_s"] <= t["inicio_t_s"] < pausa["fin_s"]]
    fases_ev = {p: [e["fase_id"] for e in v if e.get("tipo") == "fase"] for p, v in ev.items()}
    esperadas = [f["id"] for f in prog["fases"]]
    R["C2"] = {"ok": not en_pausa and all(v == esperadas for v in fases_ev.values()) and len(fases_ev) == 6,
               "tx_en_pausa": len(en_pausa), "fases_por_perfil": {p: len(v) for p, v in fases_ev.items()},
               "secuencia_ok": {p: v == esperadas for p, v in fases_ev.items()}}

    def tramo(t):
        return next((f for f in prog["fases"] if f["inicio_s"] <= t < f["fin_s"]), None)
    mal_pulso, mal_factor, n_pulso = [], [], {}
    for t in tx:
        ps = t.get("pulsos") or []
        for pid in ps:
            n_pulso[pid] = n_pulso.get(pid, 0) + 1
            pu = next(p for p in prog["pulsos"] if p["id"] == pid)
            if not (pu["inicio_s"] <= t["inicio_t_s"] < pu["fin_s"]) or t["perfil"] not in pu["perfiles"]:
                mal_pulso.append(t["transaccion_id"])
        activos = [p for p in prog["pulsos"] if p["inicio_s"] <= t["inicio_t_s"] < p["fin_s"] and t["perfil"] in p["perfiles"]]
        if sorted(p["id"] for p in activos) != sorted(ps):
            mal_pulso.append(t["transaccion_id"])
        f = tramo(t["inicio_t_s"])
        esperado = f["factor"] * prog["perfiles"][t["perfil"]].get("multiplicador", 1.0) * math.prod(p["factor"] for p in activos)
        if t.get("en_rafaga"):
            raf = prog.get("rafagas", {}).get(t["perfil"])
            if raf is None:                      # ráfaga en un perfil que no la tiene programada
                mal_factor.append((t["transaccion_id"], t.get("factor"), "rafaga_no_programada"))
                continue
            esperado *= raf["factor"]
            n_pulso["rafaga"] = n_pulso.get("rafaga", 0) + 1
        if f and abs(t.get("factor", -1) - esperado) > 1e-3 * max(1, esperado):
            mal_factor.append((t["transaccion_id"], t.get("factor"), round(esperado, 6)))
    R["C3"] = {"ok": not mal_pulso and not mal_factor and all(n_pulso.get(p["id"], 0) > 0 for p in prog["pulsos"]),
               "tx_por_pulso": n_pulso, "pulso_mal_asignado": len(mal_pulso), "factor_distinto": len(mal_factor),
               "ejemplos_factor": mal_factor[:5]}

    bloques = {p: [(e["bloque_id"], e["semilla"]) for e in v if e.get("tipo") == "bloque"] for p, v in ev.items()}
    esperado_b = {p: [(b["id"], b["semillas"][p]) for b in prog["bloques"]] for p in prog["perfiles"]}
    R["C4"] = {"ok": bloques == esperado_b, "bloques": {p: [b for b, _ in v] for p, v in bloques.items()},
               "semillas_coinciden": {p: bloques.get(p) == esperado_b[p] for p in esperado_b}}

    clases = {}
    for t in tx:
        clases[t["clase"]] = clases.get(t["clase"], 0) + 1
    R["C5"] = {"ok": clases.get("fallo_inesperado", 0) == 0, "transacciones": len(tx), "clases": clases}

    cr = cargar(P / "conciliacion" / "conciliacion-resumen.json") or {}
    cc = cr.get("clases", cr.get("por_clase", {}))
    R["C6"] = {"ok": bool(cr) and cc.get("fallo_imprevisto", 0) == 0 and cc.get("incompleta_no_verificable", 0) == 0,
               "resumen": cr}

    cob = cargar(P / "cobertura" / "cobertura.json") or {}
    R["C7"] = {"ok": None, "revisar": True, "resumen": {k: v for k, v in cob.items() if k != "transacciones"}}

    man_a = cargar(CAP / "manifiesto.json") or {}
    R["C8"] = {"ok": man_a.get("estado") == "completa" and man_a.get("pcap_huecos", 1) == 0 and man_a.get("eve_huecos", 1) == 0
               and man_a.get("eve_corruptas", 0) == 0,
               **{k: man_a.get(k) for k in ("estado", "motivo", "pcap_huecos", "eve_huecos", "eve_corruptas", "pcap_ficheros", "eve_lineas")}}

    R["C9"] = {"ok": None, "revisar": True, "fuente": ["registros/contadores-lab-inicio.txt", "registros/contadores-lab-fin.txt"]}
    R["C10"] = {"ok": None, "revisar": True, "ntp_clientes_fin": (man_g.get("entorno_fin") or {}).get("ntp_sincronizado")}

    sal = P / "registros" / "reanalisis-salida.txt"
    if not sal.exists():
        sal = P / "registros" / "analisis-salida.txt"
    rcs = dict(re.findall(r"([a-z]+) rc=(\d+)", sal.read_text(encoding="utf-8", errors="replace"))) if sal.exists() else {}
    ver = cargar(P / "extraccion" / "verificacion.json") or cargar(P / "extraccion" / "verificar.json") or {}
    res = cargar(P / "extraccion" / "resumen.json") or {}
    R["C11"] = {"ok": None, "revisar": True, "rc": rcs, "verificacion": {k: v for k, v in ver.items() if not isinstance(v, list)},
                "resumen_extraccion": {k: res.get(k) for k in ("filas", "orden_eve", "orden_pcap", "tardias", "constantes") if k in res}}
    tr = cargar(P / "extraccion" / "trazabilidad.json") or {}
    R["C11b"] = {"ok": bool(tr.get("trazabilidad_ok")), **tr}

    R["C12"] = {"ok": None, "revisar": True, "volumen_minutos": len(jsonl(CAP / "volumen.jsonl"))}
    R["C13"] = {"ok": None, "revisar": True}
    (P / "criterios.json").write_text(json.dumps(R, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v["ok"] for k, v in R.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
