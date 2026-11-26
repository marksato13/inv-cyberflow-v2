#!/usr/bin/env python3
"""Reproduce el contraste DNS de las cinco ejecuciones solo con lo publicado.

Entradas:
- paquete del release `bloque1-cierre-2026-11-26` (extracto de Sensor1 por ejecución);
- `evidencias/bloque1/dns-entradas/` (transacciones del generador, registro de DC1 y,
  para E3, el PCAP de DC1 saneado).

Compara el resultado con el que se obtuvo en el laboratorio (`reanalisis/dns-<ID>.json` y,
para E3 con PCAP, `dns-entradas/dns-e3-pcap/`) en todo salvo `parametros`, y escribe un
resumen. Uso:

    python operacion/reproducir_dns.py --paquete <dir con paquete/> --salida <dir>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
ENTRADAS = RAIZ / "evidencias/bloque1/dns-entradas"
REANALISIS = RAIZ / "evidencias/bloque1/reanalisis"
EJECUCIONES = {
    "V2-T1-20261125T062528Z": "V2-T1-20261125T062528Z",
    "V2-T2-20261125T070500Z": "V2-T2-20261125T070500Z",
    "V2-E1-20261125T185323Z": "V2-E1-20261125T185323Z.original-cd06fcf",
    "V2-E2-20261125T194609Z": "V2-E2-20261125T194609Z",
    "V2-E3-20261125T230032Z": "V2-E3-20261125T230032Z",
}
PCAP_DC1 = {"V2-E3-20261125T230032Z": ENTRADAS / "dns-e3-pcap/dns-dc1-V2-E3-20261125T230032Z.saneado.pcap"}
# Registros de sondas reconstruidos (segunda revisión del 26-nov) y la clasificación que dio el
# laboratorio con ellos: la reproducción debe dar la misma relación evento -> sonda.
SONDAS = RAIZ / "evidencias/bloque1/sonda-preflight-v2"


def sin_parametros(d):
    # `parametros` lleva rutas y conteos de entrada; `tramas_recortadas_no_dns` solo existe con el
    # extracto (la gestión va recortada a 96 B) y se informa aparte.
    # `sin_transaccion_clasificacion` es posterior a los resultados del laboratorio (26-nov).
    return {k: v for k, v in d.items()
            if k not in ("parametros", "tramas_recortadas_no_dns", "sin_transaccion_clasificacion")}


def contrastar(paquete: Path, salida: Path, ide: str, carpeta: str, pcap: Path | None):
    base = ENTRADAS / carpeta
    trans = sorted((base / "generador" / ide).glob("transacciones-*.jsonl"))
    destino = salida / ("dns-%s%s.json" % (ide, "-pcap" if pcap else ""))
    cmd = [sys.executable, "-I", str(RAIZ / "captura/contraste_dns.py"),
           "--transacciones", *map(str, trans),
           "--dc1", str(base / "registros" / ("dns-%s.jsonl" % ide)),
           "--capturas", str(paquete / ide), "--salida", str(destino)]
    if pcap:
        cmd += ["--pcap", str(pcap)]
    registro = SONDAS / ("sondas-reconstruidas-%s.jsonl" % ide)
    if registro.exists():
        cmd += ["--sondas", str(registro)]
    rc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL).returncode
    return rc, json.loads(destino.read_text(encoding="utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--paquete", required=True, help="directorio que contiene las carpetas V2-*")
    ap.add_argument("--salida", required=True)
    a = ap.parse_args(argv)
    paquete, salida = Path(a.paquete), Path(a.salida)
    salida.mkdir(parents=True, exist_ok=True)
    filas, todo_igual = [], True
    for ide, carpeta in EJECUCIONES.items():
        variantes = [(None, REANALISIS / ("dns-%s.json" % ide))]
        if ide in PCAP_DC1:
            variantes.append((PCAP_DC1[ide], ENTRADAS / "dns-e3-pcap" / ("dns-%s-pcap-saneado.json" % ide)))
        for pcap, referencia in variantes:
            rc, r = contrastar(paquete, salida, ide, carpeta, pcap)
            lab = json.loads(referencia.read_text(encoding="utf-8"))
            igual = sin_parametros(r) == sin_parametros(lab)
            # Clasificación de los eventos sin transacción frente a la del laboratorio con el mismo
            # registro reconstruido (sonda-preflight-v2/dns-<ID>-{sin,con}-pcap.json).
            ref_clas = SONDAS / ("dns-%s-%s.json" % (ide, "con-pcap" if pcap else "sin-pcap"))
            clas_igual = None
            if ref_clas.exists():
                k = lambda c: {x: c.get(x) for x in ("explicados", "no_explicados", "inciertos", "por_motivo",
                                                      "por_fuente_registro", "claves_explicadas")}
                clas_igual = k(r["sin_transaccion_clasificacion"]) == k(
                    json.loads(ref_clas.read_text(encoding="utf-8"))["sin_transaccion_clasificacion"])
                igual &= clas_igual
            todo_igual &= igual
            filas.append({"ejecucion": ide, "pcap_dc1": r["parametros"]["pcap_dc1"], "rc": rc,
                          "total": r["total"], "sin_transaccion": r["sin_transaccion"]["total"],
                          "tramas_ilegibles": r["tramas_ilegibles"]["total"],
                          "sin_transaccion_clasificacion": r["sin_transaccion_clasificacion"],
                          "tramas_recortadas_no_dns": r.get("tramas_recortadas_no_dns", 0),
                          "clasificacion_igual_al_laboratorio": clas_igual,
                          "igual_al_laboratorio": igual, "referencia": referencia.relative_to(RAIZ).as_posix()})
    (salida / "reproduccion-dns.json").write_text(
        json.dumps({"filas": filas, "todo_igual": todo_igual}, ensure_ascii=False, indent=1), encoding="utf-8")
    for f in filas:
        print(f["ejecucion"], "pcap_dc1=%s" % f["pcap_dc1"], "rc=%d" % f["rc"],
              "%d/%d" % (f["total"]["sin_discrepancias"], f["total"]["transacciones"]),
              "sin_tx=%d" % f["sin_transaccion"], "igual=%s" % f["igual_al_laboratorio"])
    return 0 if todo_igual else 1


if __name__ == "__main__":
    sys.exit(main())
