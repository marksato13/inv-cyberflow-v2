#!/usr/bin/env python3
"""Trazabilidad de cada ventana extraída, separada de las 28 entradas del IF.

Dos órdenes:

  fronteras  --generador G --salida fronteras.json
      Fronteras de bloque (resiembra/partición) en epoch UTC: arranque real de cada perfil
      (evento «inicio» de eventos-<perfil>.jsonl) + inicio_s de cada bloque del programa.
      Se pasan a extraer_v2.py --fronteras para que ninguna ventana mezcle bloques.

  metadatos  --capturas C --extraccion X --generador G [--cobertura cobertura.csv] [--conciliacion conciliacion.jsonl]
      Lee X/filas.csv y escribe:
        X/entradas_if.csv     ventana_id + las 28 columnas, en el orden del contrato y nada más
        X/ventanas_meta.csv   ventana_id + ejecución, entidad, perfil, cierre temporal, bloque,
                              partición, fase, pulsos, PCAP/EVE de origen, cobertura,
                              conciliación, huecos y exclusión con su motivo
        X/trazabilidad.json   comprobación: 1:1 entre ambos ficheros, ids únicos, campos
                              obligatorios llenos, ninguna columna de metadatos entre las 28

Reglas de exclusión del entrenamiento (se aplican aquí y se documentan en PROTOCOLO §7):
  E1 marca de arranque o de frontera de bloque (historia de 60 s incompleta)
  E2 hueco de captura PCAP o EVE que toca [cierre − 60 s, cierre]
  E3 alguna transacción del perfil en la ventana con cobertura «no verificable» o «incompleta»
  E4 alguna transacción del perfil en la ventana conciliada como fallo_imprevisto o no verificable
  E5 ventana fuera del programa (márgenes previo y final de la captura)
Las pausas programadas NO excluyen: son inactividad legítima del perfil.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))
import extraer_v2 as ex  # noqa: E402

v2 = ex.v2
HISTORIA_S = 60.0
PASO_S = 10.0
META = ("ventana_id", "ejecucion", "entidad_ip", "perfil", "regla_poblacion", "ventana_inicio_utc",
        "ventana_cierre_utc", "t_programa_s", "bloque_id", "particion", "segmento", "fase_id", "cruza_fase",
        "pulsos", "marca_extraccion", "n_paquetes_ventana", "n_eventos_l7_ventana",
        "pcap_ventana", "pcap_historia_n", "pcap_historia_primero", "pcap_historia_ultimo",
        "eve_fichero", "eve_sha256", "tx_en_ventana", "cobertura_estado", "conciliacion_estado",
        "hueco_captura", "excluir_entrenamiento", "motivos_exclusion")
OBLIGATORIOS = ("ventana_id", "ejecucion", "entidad_ip", "perfil", "ventana_cierre_utc", "bloque_id",
                "particion", "fase_id", "eve_fichero", "cobertura_estado", "conciliacion_estado",
                "excluir_entrenamiento")


def epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def jsonl(p: Path):
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def arranques(gen: Path) -> dict[str, float]:
    """Instante t=0 de cada perfil según su propio evento «inicio»."""
    t0 = {}
    for f in sorted(gen.glob("eventos-*.jsonl")):
        for ev in jsonl(f):
            if ev.get("tipo") == "inicio":
                t0[ev["perfil"]] = epoch(ev["utc"]) - float(ev.get("t_s", 0.0))
                break
    if not t0:
        raise SystemExit("sin eventos «inicio» en %s" % gen)
    return t0


def cmd_fronteras(a) -> int:
    gen = Path(a.generador)
    prog = json.loads((gen / "programa.json").read_text(encoding="utf-8"))
    t0 = arranques(gen)
    base = min(t0.values())
    fr = [base + b["inicio_s"] for b in prog["bloques"][1:]]
    out = {"fronteras": fr, "fronteras_utc": [ex.utc(x) for x in fr], "t0_por_perfil": {k: ex.utc(v) for k, v in t0.items()},
           "dispersion_t0_s": max(t0.values()) - base, "bloques": [b["id"] for b in prog["bloques"]]}
    Path(a.salida).write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({"fronteras": len(fr), "dispersion_t0_s": round(out["dispersion_t0_s"], 3)}))
    return 0


def tramo(lista, t):
    for x in lista:
        if x["inicio_s"] <= t < x["fin_s"]:
            return x
    return None


def resumen_estado(estados: list[str], malos: set[str], vacio="sin_transacciones") -> str:
    if not estados:
        return vacio
    if any(e in malos for e in estados):
        return "|".join(sorted({e for e in estados if e in malos}))
    return "ok"


def cmd_metadatos(a) -> int:
    cap, x, gen = Path(a.capturas), Path(a.extraccion), Path(a.generador)
    prog = json.loads((gen / "programa.json").read_text(encoding="utf-8"))
    ide = cap.name
    t0 = arranques(gen)
    ip_perfil = {p["origen"]: k for k, p in prog["perfiles"].items()}
    man = json.loads((cap / "manifiesto.json").read_text(encoding="utf-8")) if (cap / "manifiesto.json").exists() else {}
    eve_f = "eve/eve-%s.json" % ide
    # PCAP archivados con sus marcas de paquete
    inv = sorted((r for r in jsonl(cap / "inventario.jsonl") if r.get("primer_paquete_epoch") is not None),
                 key=lambda r: r["primer_paquete_epoch"])
    ini_pcap = [r["primer_paquete_epoch"] for r in inv]
    def pcap_en(a0, a1):
        i = max(0, bisect.bisect_left(ini_pcap, a0) - 2)
        return [r.get("fichero_archivado") or r["fichero"] for r in inv[i:]
                if r["primer_paquete_epoch"] <= a1 and r["ultimo_paquete_epoch"] >= a0]
    # Huecos: intervalos (desde, hasta) en epoch
    huecos = []
    for h in jsonl(cap / "huecos-pcap.jsonl"):
        if "anterior_epoch" in h:
            huecos.append((h["anterior_epoch"], h.get("siguiente_epoch") or h["anterior_epoch"] + h.get("segundos", 0)))
        else:
            t = epoch(h["utc"]); huecos.append((t - 10, t))
    for h in jsonl(cap / "eve" / "huecos.jsonl"):
        if "irrecuperable" in h["tipo"] or h["tipo"] in ("eve_ausente", "linea_incompleta", "copytruncate_parcial"):
            t = epoch(h["utc"]); huecos.append((t - 10, t))
    # Transacciones por perfil, con cobertura y conciliación
    cob = {}
    if a.cobertura and Path(a.cobertura).exists():
        with open(a.cobertura, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                cob[r["transaccion_id"]] = r.get("transferencia") if r.get("estado") == "verificable" else "no verificable"
    conc = {r["transaccion_id"]: r["clase"] for r in jsonl(Path(a.conciliacion))} if a.conciliacion else {}
    tx = {}
    for f in sorted(gen.glob("transacciones-*.jsonl")):
        for t in jsonl(f):
            tx.setdefault(t["perfil"], []).append((epoch(t["inicio_utc"]), epoch(t["fin_utc"]), t["transaccion_id"]))
    for v in tx.values():
        v.sort()
    inicios_tx = {k: [t[0] for t in v] for k, v in tx.items()}
    max_dur = {k: max((t[1] - t[0] for t in v), default=0) for k, v in tx.items()}
    inv_ips = {r["ip"]: r["regla"] for r in json.loads((x / "inventario_ips.json").read_text(encoding="utf-8"))} \
        if (x / "inventario_ips.json").exists() else {}

    filas_meta, ids, n = [], set(), 0
    feats = list(v2.FEATURE_NAMES)
    with open(x / "filas.csv", newline="", encoding="utf-8") as fin, \
         open(x / "entradas_if.csv", "w", newline="", encoding="utf-8") as fe, \
         open(x / "ventanas_meta.csv", "w", newline="", encoding="utf-8") as fm:
        we = csv.DictWriter(fe, fieldnames=["ventana_id"] + feats)
        wm = csv.DictWriter(fm, fieldnames=list(META))
        we.writeheader(); wm.writeheader()
        for r in csv.DictReader(fin):
            n += 1
            ip, cierre = r["ip"], epoch(r["ventana_fin"])
            perfil = ip_perfil.get(ip, "")
            vid = "%s|%s|%s" % (ide, ip, r["ventana_fin"])
            ids.add(vid)
            base = t0.get(perfil, min(t0.values()))
            trel = cierre - base
            dentro = 0 <= trel - PASO_S and trel <= prog["duracion_s"]
            b = tramo(prog["bloques"], trel - PASO_S / 2) or {}
            fa = tramo(prog["fases"], trel - PASO_S / 2) or {}
            fa_ini = tramo(prog["fases"], max(trel - PASO_S, 0)) or {}
            pulsos = sorted({p["id"] for p in prog.get("pulsos", [])
                             if p.get("inicio_s", 0) < trel and p.get("fin_s", 0) > trel - PASO_S
                             and (not p.get("perfiles") or perfil in p.get("perfiles"))})
            # transacciones del perfil que solapan la ventana
            lst, ini = tx.get(perfil, []), inicios_tx.get(perfil, [])
            j = bisect.bisect_left(ini, cierre - PASO_S - max_dur.get(perfil, 0))
            en = [t for t in lst[j:bisect.bisect_right(ini, cierre)] if t[1] >= cierre - PASO_S]
            est_cob = resumen_estado([cob.get(t[2], "sin_cobertura") for t in en] if cob else [],
                                     {"no verificable", "incompleta", "sin_cobertura"},
                                     vacio="sin_transacciones" if cob else "no_calculada")
            est_con = resumen_estado([conc.get(t[2], "sin_conciliar") for t in en] if conc else [],
                                     {"fallo_imprevisto", "incompleta_no_verificable", "sin_conciliar"},
                                     vacio="sin_transacciones" if conc else "no_calculada")
            hueco = any(h0 <= cierre and h1 >= cierre - HISTORIA_S for h0, h1 in huecos)
            motivos = []
            if r.get("motivo_marca"):
                motivos.append("E1:" + r["motivo_marca"])
            if hueco:
                motivos.append("E2:hueco_captura")
            if est_cob not in ("ok", "sin_transacciones"):
                motivos.append("E3:cobertura_" + est_cob)
            if est_con not in ("ok", "sin_transacciones"):
                motivos.append("E4:conciliacion_" + est_con)
            if not dentro:
                motivos.append("E5:fuera_del_programa")
            pv, ph = pcap_en(cierre - PASO_S, cierre), pcap_en(cierre - HISTORIA_S, cierre)
            m = {"ventana_id": vid, "ejecucion": r["ejecucion"], "entidad_ip": ip, "perfil": perfil,
                 "regla_poblacion": inv_ips.get(ip, ""), "ventana_inicio_utc": r["ventana_inicio"],
                 "ventana_cierre_utc": r["ventana_fin"], "t_programa_s": round(trel, 3),
                 "bloque_id": b.get("id", "fuera"), "particion": b.get("particion", "fuera"),
                 "segmento": b.get("segmento", ""), "fase_id": fa.get("id", "fuera"),
                 "cruza_fase": bool(fa and fa_ini and fa.get("id") != fa_ini.get("id")),
                 "pulsos": ",".join(pulsos), "marca_extraccion": r.get("motivo_marca", ""),
                 "n_paquetes_ventana": r["n_paquetes_ventana"], "n_eventos_l7_ventana": r["n_eventos_l7_ventana"],
                 "pcap_ventana": ",".join(pv), "pcap_historia_n": len(ph),
                 "pcap_historia_primero": ph[0] if ph else "", "pcap_historia_ultimo": ph[-1] if ph else "",
                 "eve_fichero": eve_f, "eve_sha256": man.get("eve_sha256", ""),
                 "tx_en_ventana": len(en), "cobertura_estado": est_cob, "conciliacion_estado": est_con,
                 "hueco_captura": hueco, "excluir_entrenamiento": bool(motivos), "motivos_exclusion": ";".join(motivos)}
            wm.writerow(m)
            we.writerow({"ventana_id": vid, **{k: r[k] for k in feats}})
            filas_meta.append(m)
    vacios = {c: sum(1 for m in filas_meta if m[c] in ("", None)) for c in OBLIGATORIOS}
    with open(x / "entradas_if.csv", newline="", encoding="utf-8") as f:
        cab_e = next(csv.reader(f))
        ids_e = [row[0] for row in csv.reader(f)]
    solape = sorted(set(META) & set(feats))
    excl = {}
    for m in filas_meta:
        for mot in filter(None, m["motivos_exclusion"].split(";")):
            excl[mot.split(":")[0]] = excl.get(mot.split(":")[0], 0) + 1
    informe = {"ejecucion": ide, "ventanas": n, "ids_unicos": len(ids) == n,
               "uno_a_uno": ids_e == [m["ventana_id"] for m in filas_meta],
               "entradas_columnas_ok": cab_e == ["ventana_id"] + feats, "n_entradas": len(cab_e) - 1,
               "metadatos_fuera_de_las_28": not solape, "solape": solape,
               "obligatorios_vacios": vacios, "obligatorios_ok": not any(vacios.values()),
               "por_particion": _cuenta(filas_meta, "particion"), "por_bloque": _cuenta(filas_meta, "bloque_id"),
               "por_perfil": _cuenta(filas_meta, "perfil"), "por_cobertura": _cuenta(filas_meta, "cobertura_estado"),
               "por_conciliacion": _cuenta(filas_meta, "conciliacion_estado"),
               "excluidas": sum(m["excluir_entrenamiento"] for m in filas_meta), "exclusion_por_regla": excl,
               "dispersion_t0_s": round(max(t0.values()) - min(t0.values()), 3)}
    informe["trazabilidad_ok"] = all(informe[k] for k in ("ids_unicos", "uno_a_uno", "entradas_columnas_ok",
                                                          "metadatos_fuera_de_las_28", "obligatorios_ok")) and informe["n_entradas"] == 28
    (x / "trazabilidad.json").write_text(json.dumps(informe, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: informe[k] for k in ("ventanas", "trazabilidad_ok", "excluidas", "exclusion_por_regla")}, ensure_ascii=False))
    return 0 if informe["trazabilidad_ok"] else 1


def _cuenta(filas, campo):
    c = {}
    for m in filas:
        c[str(m[campo])] = c.get(str(m[campo]), 0) + 1
    return dict(sorted(c.items()))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    f = sub.add_parser("fronteras"); f.add_argument("--generador", required=True); f.add_argument("--salida", required=True)
    m = sub.add_parser("metadatos")
    for k in ("--capturas", "--extraccion", "--generador"):
        m.add_argument(k, required=True)
    m.add_argument("--cobertura"); m.add_argument("--conciliacion")
    a = ap.parse_args()
    return cmd_fronteras(a) if a.orden == "fronteras" else cmd_metadatos(a)


if __name__ == "__main__":
    raise SystemExit(main())
