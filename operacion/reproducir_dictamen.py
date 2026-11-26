#!/usr/bin/env python3
"""Reproduce, fuera del laboratorio, el dictamen de VD2/VD3/VD4/VD6 desde los RESULTADOS INTERMEDIOS
publicados (Bloque 1, revisión 4). No lee PCAP ni EVE: eso lo hace recalcular_desde_capturas.py.

    python3 -X utf8 operacion/reproducir_dictamen.py [DIR] [--salida informe.json]

DIR (por omisión evidencias/bloque1/entradas-r4) contiene una carpeta por ejecución con:
  pruebas/<ID>/ y capturas/<ID>/   entradas de texto saneadas (lo que leen los programas del dictamen)
  referencia/                      lo que dio el LABORATORIO con esas entradas sin sanear:
                                   resultado-global.json, criterios-revisados.json, dictamen-casos.json

Para cada ejecución copia sus entradas a una carpeta temporal, ejecuta revisar_criterios.py,
estado_global.py y dictamen_casos.py, y compara con la referencia:
  - dictamen: global, dictamen, codigo_salida, motivos, alcance y los estados (espejo, calidad_*,
    referencias, transferencias, analisis, exclusion_v1);
  - criterios: `ok` de C7 y C9–C13 (revisados) y las listas de pendientes de duración prolongada y de
    otra comprobación;
  - los ocho casos de dictamen_casos.py: caso, global, codigo_salida, calidad y motivos.
Una ejecución esperada ausente, un fichero de entrada o de referencia ausente, un programa que falla
o cualquier diferencia => NO SATISFACTORIO y rc 1. No escribe en el repositorio.

Complementos (--complemento, repetible; por omisión evidencias/bloque1/suricata-r5 y suricata-r6). r5: Añade, por
ejecución, los eventos stats originales de Suricata (capturas/<ID>/eve/suricata-stats-<ID>.jsonl, que
el EVE filtrado de r4 no lleva) y la referencia del laboratorio recalculada con el código que mide
kernel_drops; esa referencia sustituye a la de r4. Se compara además el componente de Suricata de C9
(estado, eventos, Δ kernel_drops, kernel_packets, uptime, primero y último) y que cada lectura
de supervision.jsonl sea igual al último evento stats anterior de la EVE.
r6: muestras stats de la EVE dedicada completa que acotan el periodo de captura
(pruebas/<ID>/registros/suricata-stats-ventana-<ID>.jsonl) y la referencia recalculada con el código
que exige esa cobertura; la referencia es la del último complemento que la tenga.
--sin-complemento reproduce la referencia de r4, válida solo para el código hasta 57b2293.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ESPERADAS = ("V2-VD2-20261126T090705Z", "V2-VD3-20261126T104230Z", "V2-VD4-20261126T141333Z",
             "V2-VD6-20261126T151456Z")
CAMPOS_DICTAMEN = ("global", "dictamen", "codigo_salida", "motivos", "alcance", "espejo", "calidad_copias",
                   "calidad_dns", "calidad_extremo", "calidad_sonda", "referencias", "transferencias",
                   "analisis", "exclusion_v1", "pendientes_duracion_prolongada", "pendientes_otra_comprobacion")
CAMPOS_CASO = ("caso", "global", "codigo_salida", "calidad", "motivos")
N_CASOS = 8


def dec(p):
    return json.JSONDecoder().raw_decode(Path(p).read_text(encoding="utf-8"))[0]


def resumen_dictamen(g):
    return {k: g.get(k) for k in CAMPOS_DICTAMEN}


def resumen_criterios(c):
    return {k: v.get("ok") for k, v in c["criterios"].items()}


def resumen_casos(d):
    return [{k: c.get(k) for k in CAMPOS_CASO} for c in d["casos"]]


def comparar(nombre, ref, nuevo, difs):
    if ref != nuevo:
        if isinstance(ref, dict) and isinstance(nuevo, dict):
            for k in sorted(set(ref) | set(nuevo)):
                if ref.get(k) != nuevo.get(k):
                    difs.append("%s.%s: laboratorio %s, reproducido %s" % (
                        nombre, k, json.dumps(ref.get(k), ensure_ascii=False)[:120],
                        json.dumps(nuevo.get(k), ensure_ascii=False)[:120]))
        else:
            difs.append("%s: laboratorio %s, reproducido %s" % (nombre, json.dumps(ref, ensure_ascii=False)[:300],
                                                                 json.dumps(nuevo, ensure_ascii=False)[:300]))


CAMPOS_SURICATA = ("estado", "motivo", "eventos", "eventos_usados", "muestra_antes_s", "muestra_despues_s",
                   "hueco_maximo_s", "delta_kernel_drops", "delta_kernel_packets", "kernel_drops",
                   "kernel_packets", "uptime", "primero", "ultimo")


def suricata_c9(c):
    for x in c["criterios"]["C9"].get("comprobaciones", []):
        if x.get("que", "").startswith("Suricata capture.kernel_drops"):
            v = x.get("valor") or {}
            return {"ok": x.get("ok"), **{k: v.get(k) for k in CAMPOS_SURICATA}}
    return None


def supervision_frente_a_stats(P: Path, K: Path, ID: str, difs: list) -> dict:
    """Cada lectura kernel_drops de supervision.jsonl debe ser igual al último evento stats de la EVE
    anterior a esa lectura (procedencia del valor). Lectura sin evento previo o distinta = diferencia."""
    sys.path.insert(0, str(REPO / "operacion"))
    import suricata_stats as ss
    fuentes = sorted((K / "eve").glob("suricata-stats-*.jsonl")) + sorted((P / "registros").glob("suricata-stats-ventana*.jsonl"))
    ev = sorted({(ss.epoch(e["timestamp"]), ss.lectura(e)["kernel_drops"]) for e in ss.eventos_stats(fuentes)})
    sup = [json.loads(x) for x in (P / "registros" / "supervision.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    n = 0
    for s in sup:
        previos = [v for t, v in ev if t <= s.get("hasta_epoch", 0)]
        if not previos:
            difs.append("supervisión %s: sin evento stats anterior" % s.get("utc"))
        elif s.get("kernel_drops") is None or previos[-1] != s.get("kernel_drops"):
            difs.append("supervisión %s: kernel_drops %s, EVE %s" % (s.get("utc"), s.get("kernel_drops"), previos[-1]))
        else:
            n += 1
    return {"lecturas": len(sup), "iguales_a_la_eve": n}


def una(E: Path, ID: str, Cs=()):
    """Cs: carpetas de complemento de esta ejecución, en orden; cada una superpone sus capturas/<ID>
    y pruebas/<ID> a la copia temporal, y la referencia es la del último complemento que la tenga."""
    res = {"ejecucion": ID, "diferencias": [], "ausentes": []}
    Cs = [Path(c) for c in Cs]
    con_ref = [c for c in Cs if (c / "referencia").is_dir()]
    R = con_ref[-1] / "referencia" if con_ref else E / "referencia"
    res["referencia"] = str(R)
    extra = list(Cs) + [c / "capturas" / ID / "eve" / ("suricata-stats-%s.jsonl" % ID) for c in Cs if (c / "capturas").is_dir()]
    for f in [E / "pruebas" / ID, E / "capturas" / ID, R / "resultado-global.json",
              R / "criterios-revisados.json", R / "dictamen-casos.json"] + extra:
        if not f.exists():
            res["ausentes"].append(str(f))
    if res["ausentes"]:
        res["satisfactorio"] = False
        return res
    op, py = REPO / "operacion", [sys.executable, "-I", "-X", "utf8"]
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        P, K = t / ID, E / "capturas" / ID
        shutil.copytree(E / "pruebas" / ID, P)
        if Cs:
            K = t / "capturas" / ID
            shutil.copytree(E / "capturas" / ID, K)
            for C in Cs:
                if (C / "capturas" / ID).is_dir():
                    shutil.copytree(C / "capturas" / ID, K, dirs_exist_ok=True)
                if (C / "pruebas" / ID).is_dir():
                    shutil.copytree(C / "pruebas" / ID, P, dirs_exist_ok=True)
        pasos = [
            ("revisar_criterios", [str(op / "revisar_criterios.py"), "--pruebas", str(P), "--capturas", str(K)]),
            ("estado_global", [str(op / "estado_global.py"), ID, "--pruebas", str(P), "--ejecucion-dir",
                               str(P / "registros"), "--captura-dir", str(K)]),
            ("dictamen_casos", [str(op / "dictamen_casos.py"), ID, "--pruebas", str(P), "--capturas", str(K),
                                "--salida", str(t / "casos")]),
        ]
        salidas = {}
        for nombre, cmd in pasos:
            r = subprocess.run(py + cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            salidas[nombre] = r.stdout
            # estado_global devuelve rc = código del dictamen (0/1/2); los otros dos, 0 si van bien
            if nombre != "estado_global" and r.returncode != 0:
                res["diferencias"].append("%s terminó con rc %d: %s" % (nombre, r.returncode, (r.stderr or r.stdout)[-300:]))
        try:
            g = json.JSONDecoder().raw_decode(salidas["estado_global"])[0]
            comparar("dictamen", resumen_dictamen(dec(R / "resultado-global.json")), resumen_dictamen(g), res["diferencias"])
            comparar("criterios", resumen_criterios(dec(R / "criterios-revisados.json")),
                     resumen_criterios(dec(P / "criterios-revisados.json")), res["diferencias"])
            if Cs:
                ref_s, nuevo_s = suricata_c9(dec(R / "criterios-revisados.json")), suricata_c9(dec(P / "criterios-revisados.json"))
                if ref_s is None:
                    res["diferencias"].append("la referencia r5 no tiene el componente de Suricata en C9")
                comparar("C9.suricata", ref_s, nuevo_s, res["diferencias"])
                res["suricata"] = nuevo_s
                res["supervision_frente_a_stats"] = supervision_frente_a_stats(P, K, ID, res["diferencias"])
            ref_c, nuevo_c = resumen_casos(dec(R / "dictamen-casos.json")), resumen_casos(dec(t / "casos" / "dictamen-casos.json"))
            if len(ref_c) != N_CASOS:
                res["diferencias"].append("la referencia tiene %d casos, se esperaban %d" % (len(ref_c), N_CASOS))
            comparar("casos", ref_c, nuevo_c, res["diferencias"])
            res["dictamen"], res["motivos"] = g.get("global"), g.get("motivos")
            res["criterios"] = resumen_criterios(dec(P / "criterios-revisados.json"))
            res["casos"] = [(c["caso"], c["global"]) for c in nuevo_c]
        except (ValueError, OSError, KeyError) as exc:
            res["diferencias"].append("salida ilegible: %s" % exc)
    res["satisfactorio"] = not res["diferencias"]
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir", nargs="?", type=Path, default=REPO / "evidencias" / "bloque1" / "entradas-r4")
    ap.add_argument("--salida", type=Path)
    ap.add_argument("--complemento", type=Path, action="append",
                    help="carpeta de complemento (se puede repetir, en orden); por omisión suricata-r5 y suricata-r6")
    ap.add_argument("--sin-complemento", action="store_true")
    a = ap.parse_args(argv)
    if a.complemento is None:
        a.complemento = [REPO / "evidencias" / "bloque1" / "suricata-r5", REPO / "evidencias" / "bloque1" / "suricata-r6"]
    informe = {"version": 4, "complementos": [] if a.sin_complemento else [str(c) for c in a.complemento],
               "comprobacion": "dictamen desde resultados intermedios", "ejecuciones": []}
    for ID in ESPERADAS:
        E = a.dir / ID
        Cs = [] if a.sin_complemento else [c / ID for c in a.complemento]
        r = una(E, ID, Cs) if E.is_dir() else {"ejecucion": ID, "satisfactorio": False, "ausentes": [str(E)], "diferencias": []}
        informe["ejecuciones"].append(r)
        print(ID, "SATISFACTORIO" if r["satisfactorio"] else "NO SATISFACTORIO", r.get("dictamen"), r.get("motivos"),
              r.get("criterios"), r.get("casos"), r.get("suricata"), r.get("supervision_frente_a_stats"))
        for x in r["ausentes"] + r["diferencias"]:
            print("   ", x)
    informe["satisfactorio"] = all(r["satisfactorio"] for r in informe["ejecuciones"])
    if a.salida:
        a.salida.write_text(json.dumps(informe, ensure_ascii=False, indent=1), encoding="utf-8")
    print("GLOBAL", "SATISFACTORIO" if informe["satisfactorio"] else "NO SATISFACTORIO")
    return 0 if informe["satisfactorio"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
