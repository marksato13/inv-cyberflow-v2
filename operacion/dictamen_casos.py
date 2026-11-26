#!/usr/bin/env python3
"""Dictamen de una ejecución real con evidencia correcta, con pérdida inyectada y con evidencia ausente.

    python3 dictamen_casos.py --pruebas ~/cyberflow-v2/pruebas/<ID> --capturas ~/cyberflow-v2/capturas/<ID> \
        --salida <carpeta nueva> <ID>

No escribe en la ejecución: copia a <salida>/<caso>/ los ficheros que lee estado_global.evaluar()
(JSON, JSONL y CSV; sin PCAP) y modifica la copia. Casos:

  correcta                 la copia tal cual (debe dar el mismo dictamen que resultado-global.json)
  perdida_extremo          una conexión que vio srv-dmz y Sensor1 no (conexiones_solo_extremo = 1)
  perdida_copias           una copia de la población que falta (falta_copia en la VLAN de la población)
  contaminacion_sonda      una ventana útil con la sonda en su historia
  extremo_ausente          sin calidad-extremo.json ni extremo-captura.json
  sonda_ausente            sin calidad-sonda.json
  dns_ausente              sin calidad-contraste-dns.json
  extremo_con_descartes    tcpdump de srv-dmz con descartes del núcleo (la referencia no es completa)
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import estado_global as eg  # noqa: E402


def comprobar_salida(origen: Path, salida: Path) -> None:
    """Rechaza, con rutas resueltas y ANTES de copiar nada, una salida igual al origen o dentro de él:
    copiar `origen` en una carpeta suya hace que rglob recorra lo que se va copiando y la copia se
    anida sin fin (reanálisis r5, 26-nov: --salida dentro de --pruebas). También una salida que ya
    existe, para no mezclar casos con una ejecución anterior."""
    o, s = origen.resolve(), salida.resolve()
    if s == o or o in s.parents:
        raise SystemExit("la salida %s está dentro de las pruebas %s (o es la misma carpeta): se "
                         "copiaría a sí misma" % (s, o))
    if s.exists():
        raise SystemExit("la carpeta de salida ya existe: %s" % s)


def copiar(origen: Path, destino: Path):
    comprobar_salida(origen, destino)
    for f in origen.rglob("*"):
        # .csv: el dictamen exige entradas_if.csv y ventanas_meta.csv como evidencia del análisis
        if f.is_file() and f.suffix in (".json", ".jsonl", ".csv") and f.stat().st_size < 200_000_000:
            d = destino / f.relative_to(origen)
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, d)


def cargar(p):
    return json.loads(p.read_text(encoding="utf-8"))


def guardar(p, d):
    p.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def inyectar(caso: str, p: Path):
    if caso == "perdida_extremo":
        r = cargar(p / "calidad-extremo.json")
        r["conexiones_solo_extremo"] = {"total": 1, "inyectado": True}
        guardar(p / "calidad-extremo.json", r)
    elif caso == "perdida_copias":
        r = cargar(p / "calidad-copias-espejo.json")
        den = r.setdefault("denominadores", {}).setdefault("eventos_por_clase", {})
        den["falta_copia"] = den.get("falta_copia", 0) + 1
        guardar(p / "calidad-copias-espejo.json", r)
    elif caso == "contaminacion_sonda":
        r = cargar(p / "calidad-sonda.json")
        r["estado"], r["tocadas_utiles"] = "contaminacion_en_periodo_util", 1
        guardar(p / "calidad-sonda.json", r)
    elif caso == "extremo_ausente":
        for f in (p / "calidad-extremo.json", p / "registros" / "extremo-captura.json"):
            f.unlink(missing_ok=True)
    elif caso == "sonda_ausente":
        (p / "calidad-sonda.json").unlink(missing_ok=True)
    elif caso == "dns_ausente":
        (p / "calidad-contraste-dns.json").unlink(missing_ok=True)
    elif caso == "extremo_con_descartes":
        f = p / "registros" / "extremo-captura.json"
        r = cargar(f)
        r["descartados_nucleo"] = 3
        guardar(f, r)


CASOS = ("correcta", "perdida_extremo", "perdida_copias", "contaminacion_sonda", "extremo_ausente",
         "sonda_ausente", "dns_ausente", "extremo_con_descartes")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ejecucion")
    ap.add_argument("--pruebas", required=True, type=Path)
    ap.add_argument("--capturas", required=True, type=Path)
    ap.add_argument("--salida", required=True, type=Path)
    a = ap.parse_args(argv)
    comprobar_salida(a.pruebas, a.salida)
    filas = []
    original = (eg.leer(a.pruebas / "resultado-global.json") or {}).get("global")
    for caso in CASOS:
        d = a.salida / caso / "pruebas" / a.ejecucion
        copiar(a.pruebas, d)
        inyectar(caso, d)
        r = eg.evaluar(a.ejecucion, d, None, a.capturas)
        filas.append({"caso": caso, "global": r["global"], "codigo_salida": r["codigo_salida"],
                      "calidad": {k: r.get(k) for k in ("calidad_copias", "calidad_dns", "calidad_extremo",
                                                        "calidad_sonda")},
                      "motivos": [m for m in r["motivos"] if not m.startswith("falta:criterio")]})
        print(caso, r["global"], filas[-1]["calidad"], ",".join(filas[-1]["motivos"]))
    out = {"ejecucion": a.ejecucion, "dictamen_original": original, "casos": filas}
    guardar(a.salida / "dictamen-casos.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
