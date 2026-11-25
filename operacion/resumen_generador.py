#!/usr/bin/env python3
"""Resumen programado frente a observado de una ejecución del generador v3.

    python3 resumen_generador.py <dir_generador> [--salida resumen-generador.json]

<dir_generador> contiene programa.json, transacciones-P*.jsonl y eventos-P*.jsonl. Por perfil y
nivel: transacciones por acción y clase, ciclos (secuencias), pausas observadas (espera_previa_s
de la primera acción de cada ciclo; para P4, de cada operación), media programada de la pausa,
tamaños pedidos/recibidos, objetos secundarios por página (P2), protocolo por página (P2), acciones
de P6 iniciadas en OFF y que cruzan el borde ON, conexiones de P2 y TTL DNS. No juzga ajuste de
distribuciones: con muestras cortas solo informa n, media y la media programada.
"""
from __future__ import annotations

import argparse
import collections
import json
import statistics
from pathlib import Path


def jsonl(p: Path):
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def resumen(d: Path) -> dict:
    prog = json.loads((d / "programa.json").read_text(encoding="utf-8"))
    out = {"programa_id": prog["programa_id"], "perfiles": {}}
    for perfil, cfg in prog["perfiles"].items():
        f = d / ("transacciones-%s.jsonl" % perfil)
        tx = jsonl(f) if f.exists() else []
        ev = jsonl(d / ("eventos-%s.jsonl" % perfil)) if (d / ("eventos-%s.jsonl" % perfil)).exists() else []
        r = {"transacciones": len(tx),
             "por_accion": dict(collections.Counter(t["accion"] for t in tx)),
             "por_clase": dict(collections.Counter(t.get("clase") for t in tx)),
             "ciclos": len({t["secuencia_id"] for t in tx}),
             "eventos": dict(collections.Counter(e["tipo"] for e in ev))}
        # Pausas: la que precede a cada ciclo (P1-P3, P5, P6) o a cada operación (P4).
        niveles = collections.defaultdict(list)
        for t in tx:
            primera = t["accion"] == "dns" or (perfil == "P4" and t["paso"] in ("envio", "consulta_final"))
            if primera:
                niveles[t["nivel"]].append(t["espera_previa_s"])
        r["pausas"] = {n: {"n": len(v), "media_obs_s": round(statistics.fmean(v), 3) if v else None,
                           "media_programada_s": round(cfg["media_espera_s"] / prog["factores"][n], 3)
                           if prog["factores"].get(n) else None}
                       for n, v in sorted(niveles.items())}
        obt = [t for t in tx if t["accion"] in ("obtener", "consulta", "envio")]
        r["tamanos"] = {"n": len(obt),
                        "pedidos_iguales_recibidos": sum(1 for t in obt if t["accion"] == "envio" or
                                                         t.get("bytes_cuerpo_recibidos") == t.get("bytes_solicitados")),
                        "min": min((t["bytes_solicitados"] for t in obt), default=None),
                        "max": max((t["bytes_solicitados"] for t in obt), default=None),
                        "media": round(statistics.fmean(t["bytes_solicitados"] for t in obt), 1) if obt else None}
        r["por_nivel"] = dict(collections.Counter(t["nivel"] for t in tx))
        r["por_bloque"] = dict(collections.Counter(t["bloque_id"] for t in tx))
        ttl = {t.get("dns_ttl") for t in tx if t["accion"] == "dns"}
        r["dns_ttl"] = sorted(x for x in ttl if x is not None)
        if perfil == "P2":
            paginas = collections.defaultdict(list)
            for t in tx:
                if t["accion"] == "obtener":
                    paginas[t["secuencia_id"]].append(t)
            r["paginas"] = len(paginas)
            r["secundarios_por_pagina"] = [sum(1 for t in v if t["tipo_objeto"] == "secundario") for v in paginas.values()]
            r["protocolo_por_pagina"] = [v[0]["protocolo"] for v in paginas.values()]
            r["una_conexion_por_pagina"] = all(len({(t["conexion_n"], t["origen_puerto"]) for t in v}) == 1
                                               for v in paginas.values())
            r["peticion_en_conexion_ok"] = all([t["peticion_en_conexion"] for t in v] == list(range(1, len(v) + 1))
                                               for v in paginas.values())
        if perfil == "P4":
            seq = collections.defaultdict(list)
            for t in tx:
                if t["accion"] != "dns":
                    seq[t["secuencia_id"]].append(t["accion"])
            r["secuencias"] = dict(collections.Counter("-".join(v) for v in seq.values()))
        if perfil == "P6":
            on, off = cfg.get("on_s", 60), cfg.get("off_s", 120)
            r["iniciadas_en_off"] = sum(1 for t in tx if t["inicio_t_s"] % (on + off) >= on)
            r["cruzan_borde_on"] = sum(1 for t in tx if t.get("cruza_borde_on"))
        out["perfiles"][perfil] = r
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("generador", type=Path)
    ap.add_argument("--salida", type=Path)
    a = ap.parse_args()
    r = resumen(a.generador)
    texto = json.dumps(r, indent=1, ensure_ascii=False)
    if a.salida:
        a.salida.write_text(texto + "\n", encoding="utf-8")
    print(texto)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
