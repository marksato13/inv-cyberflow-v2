#!/usr/bin/env python3
"""Recalcula, desde los PCAP/EVE publicados, lo que el dictamen toma de las capturas, y lo compara
con el resultado del laboratorio (Bloque 1, revisión 4).

    python3 -X utf8 operacion/recalcular_desde_capturas.py DIR_PAQUETES [--salida informe.json] [--id ID …]

DIR_PAQUETES contiene una carpeta `<ID>/` por ejecución, tal como sale de los paquetes de la
release: `pruebas/<ID>/` (entradas de texto saneadas y resultados del laboratorio) y
`capturas/<ID>/{pcap,eve}` (anillo de Sensor1 filtrado al tráfico experimental), con
`pruebas/<ID>/registros/{extremo,dns}-<ID>.pcap` (srv-dmz y DC1).

Para cada ejecución vuelve a ejecutar, en una carpeta temporal y con el código de este repositorio:
cobertura_v2 (C7), comparar_extremo (calidad_extremo), contraste_dns (calidad_dns), copias_espejo
(calidad_copias) y extraer_v2 (C11). Compara cada salida con la del laboratorio campo a campo.

Cada campo que difiere se clasifica:
- «esperada»: el campo cuenta tráfico que NO es experimental (gestión, equipos ajenos), que el
  extracto quitó a propósito. Esos campos están listados en DEPENDEN_DEL_TRAFICO_AJENO, con el
  motivo; no intervienen en el dictamen.
- «inesperada»: cualquier otra diferencia. Una sola, o una entrada ausente, o un programa que
  falla, hace que el resultado global sea NO SATISFACTORIO (rc 1).
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POBLACION = "10.10.20.21,10.10.20.22,10.10.20.23,10.10.20.24,10.10.20.25,10.10.20.26"

# campo (ruta con «/») -> por qué depende del tráfico que el extracto quitó
DEPENDEN_DEL_TRAFICO_AJENO = {
    "copias": {
        "denominadores/tramas_leidas": "cuenta todas las tramas del anillo, también gestión y ajenas",
        "denominadores/tramas_en_ventana": "ídem, dentro de la ventana",
        "bytes_por_vlan": "volumen de todas las VLAN del espejo, no solo el experimental",
        "por_segundo": "tramas y bytes de todo el anillo por segundo",
        "pico_1s": "pico de todo el anillo",
        "pico_10ms": "pico de todo el anillo",
    },
    "extraccion": {
        "resumen/copias_espejo_quitadas": "copias de espejo de todo el anillo (población y no población)",
        "resumen/paquetes_descartados_poblacion": "paquetes ajenos a la población que el extractor descarta",
        "resumen/eventos_descartados_poblacion": "eventos EVE ajenos a la población",
        "verificacion/copias_espejo_quitadas": "como en el resumen",
        "verificacion/paquetes_descartados_poblacion": "como en el resumen",
        "inventario_ips": "inventario de todas las IP vistas (las ajenas, sustituidas en la referencia)",
        "resumen/orden_pcap": "reordenaciones contadas sobre todos los paquetes del anillo, no solo los experimentales",
        "resumen/orden_eve": "reordenaciones contadas sobre todos los eventos del EVE completo",
    },
}


def dec(p):
    return json.JSONDecoder().raw_decode(Path(p).read_text(encoding="utf-8"))[0]


def diferencias(a, b, ruta="", out=None, limite=1_000_000):
    out = [] if out is None else out
    if len(out) >= limite:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            r = (ruta + "/" + str(k)).lstrip("/")
            if k not in a or k not in b:
                out.append((r, a.get(k), b.get(k)))
            else:
                diferencias(a[k], b[k], r, out, limite)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            diferencias(x, y, "%s[%d]" % (ruta, i), out, limite)
    elif isinstance(a, float) and isinstance(b, float):
        if abs(a - b) > 1e-9 * max(1.0, abs(a), abs(b)):
            out.append((ruta, a, b))
    elif a != b:
        out.append((ruta, a, b))
    return out


def ruta_local(a, b):
    """Dos rutas de fichero que solo difieren en la carpeta (laboratorio frente a carpeta temporal)."""
    if not (isinstance(a, str) and isinstance(b, str) and ("/" in a + b or "\\" in a + b)):
        return False
    base = lambda x: x.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return base(a) == base(b)


def clasificar(check, difs):
    esp = DEPENDEN_DEL_TRAFICO_AJENO.get(check, {})
    e, i = [], []
    for d in difs:
        if isinstance(d, str):                       # diferencia ya descrita (CSV, fichero ausente)
            i.append(d)
            continue
        ruta, a, b = d
        base = ruta.split("[")[0]
        clave = next((k for k in esp if base == k or base.startswith(k + "/")), None)
        if clave:
            e.append("%s: %s" % (ruta, esp[clave]))
        elif ruta_local(a, b):
            e.append("%s: ruta del fichero (misma base, otra carpeta)" % ruta)
        else:
            i.append("%s: laboratorio %s, recalculado %s" % (ruta, json.dumps(a, ensure_ascii=False)[:80],
                                                             json.dumps(b, ensure_ascii=False)[:80]))
    return e, i


def filas_csv(p):
    """Cabecera y filas ordenadas (el orden de escritura no es parte del resultado)."""
    with open(p, encoding="utf-8", newline="") as f:
        filas = list(csv.reader(f))
    return filas[:1], sorted(filas[1:])


def ejecutar(cmd, cwd):
    r = subprocess.run([sys.executable, "-X", "utf8"] + [str(c) for c in cmd], cwd=cwd,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, (r.stdout + r.stderr)[-2000:]


def una(base: Path, ID: str):
    P0, K0 = base / "pruebas" / ID, base / "capturas" / ID
    res = {"ejecucion": ID, "comprobaciones": {}, "entradas_ausentes": []}
    necesarias = [K0 / "pcap", K0 / "eve" / ("eve-%s.json" % ID), P0 / "registros" / ("extremo-%s.pcap" % ID),
                  P0 / "registros" / ("dns-%s.pcap" % ID), P0 / "registros" / ("dns-%s.jsonl" % ID),
                  P0 / "fronteras.json", P0 / "generador" / ID / "preflight.jsonl", K0 / "inventario.jsonl",
                  P0 / "conciliacion" / "conciliacion.jsonl"]
    res["entradas_ausentes"] = [str(p.relative_to(base)) for p in necesarias if not p.exists()]
    tx = sorted((P0 / "generador" / ID).glob("transacciones-*.jsonl"))
    if not tx:
        res["entradas_ausentes"].append("pruebas/%s/generador/%s/transacciones-*.jsonl" % (ID, ID))
    if res["entradas_ausentes"]:
        res["satisfactorio"] = False
        return res
    cap, ext, gen = REPO / "captura", REPO / "extraccion", P0 / "generador" / ID
    with tempfile.TemporaryDirectory() as t:
        T = Path(t)

        def registrar(nombre, rc, salida, ref, nuevo, difs_extra=None):
            if rc != 0:
                res["comprobaciones"][nombre] = {"rc": rc, "salida": salida, "reproducido": False,
                                                 "diferencias_inesperadas": ["el programa terminó con rc %d" % rc]}
                return
            difs = []
            for r, n in zip(ref, nuevo):
                if not Path(r).exists():
                    difs.append("referencia ausente: %s" % Path(r).name)
                    continue
                if not Path(n).exists():
                    difs.append("salida recalculada ausente: %s" % Path(n).name)
                    continue
                if str(r).endswith(".csv"):
                    (ca, a), (cb, b) = filas_csv(r), filas_csv(n)
                    if ca != cb:
                        difs.append("%s: cabecera distinta" % Path(r).name)
                    elif a != b:
                        solo = len(set(map(tuple, a)) ^ set(map(tuple, b)))
                        difs.append("%s: %d filas en el laboratorio, %d recalculadas, %d sin pareja" % (
                            Path(r).name, len(a), len(b), solo))
                else:
                    pref = Path(r).stem if nombre == "extraccion" else ""
                    difs += [((pref + "/" + d).lstrip("/"), x, y) for d, x, y in diferencias(dec(r), dec(n))]
            difs += difs_extra or []
            e, i = clasificar(nombre, difs)
            res["comprobaciones"][nombre] = {"rc": 0, "reproducido": not i, "diferencias_esperadas": e,
                                             "diferencias_inesperadas": i}

        rc, s = ejecutar([cap / "cobertura_v2.py", "--capturas", K0, "--transacciones", *tx,
                          "--salida", T / "cobertura.json", "--csv", T / "cobertura.csv"], T)
        registrar("cobertura", rc, s, [P0 / "cobertura" / "cobertura.json", P0 / "cobertura" / "cobertura.csv"],
                  [T / "cobertura.json", T / "cobertura.csv"])
        rc, s = ejecutar([cap / "comparar_extremo.py", "--extremo", P0 / "registros" / ("extremo-%s.pcap" % ID),
                          "--sensor", K0 / "pcap", "--salida", T / "extremo.json"], T)
        registrar("extremo", rc, s, [P0 / "calidad-extremo.json"], [T / "extremo.json"])
        rc, s = ejecutar([cap / "contraste_dns.py", "--transacciones", *tx, "--dc1", P0 / "registros" / ("dns-%s.jsonl" % ID),
                          "--capturas", K0, "--pcap", P0 / "registros" / ("dns-%s.pcap" % ID),
                          "--sondas", gen / "preflight.jsonl", "--salida", T / "dns.json", "--csv", T / "dns.csv"], T)
        registrar("dns", rc, s, [P0 / "calidad-contraste-dns.json"], [T / "dns.json"])
        rc, s = ejecutar([cap / "copias_espejo.py", K0 / "pcap", "--salida", T / "copias.json", "--detalle-umbral", "0.4"], T)
        registrar("copias", rc, s, [P0 / "calidad-copias-espejo.json"], [T / "copias.json"])
        E = T / "extraccion"
        # El primer paquete del anillo (inicio de la captura) suele ser tráfico no experimental, que el
        # extracto no lleva; el inventario publicado registra su instante.
        inicio = min(json.loads(l)["primer_paquete_epoch"]
                     for l in (K0 / "inventario.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())
        rc, s = ejecutar([ext / "extraer_v2.py", K0, "--salida", E, "--fronteras", P0 / "fronteras.json",
                          "--inicio-captura-epoch", repr(inicio)], T)
        if rc == 0:
            rc, s = ejecutar([ext / "verificar_v2.py", K0, "--salida", E, "--fronteras", P0 / "fronteras.json",
                              "--max-filas", "40", "--historia-s", "230"], T)
        if rc == 0:      # metadatos de ventana (los usa calidad_sonda), con la cobertura recalculada
            rc, s = ejecutar([ext / "metadatos_v2.py", "metadatos", "--capturas", K0, "--extraccion", E,
                              "--generador", gen, "--cobertura", T / "cobertura.csv",
                              "--conciliacion", P0 / "conciliacion" / "conciliacion.jsonl"], T)
        X = P0 / "extraccion"
        nombres = ["resumen.json", "verificacion.json", "filas.csv", "entradas_if.csv", "ventanas_meta.csv"]
        registrar("extraccion", rc, s, [X / n for n in nombres], [E / n for n in nombres])
    res["satisfactorio"] = all(c["reproducido"] for c in res["comprobaciones"].values())
    return res


def p2(D: Path):
    """Extracto de P2: 6 conexiones persistentes y sus 45 transacciones. Compara TODOS los campos de
    cada transacción con la cobertura del laboratorio."""
    res = {"extracto": D.name, "ausentes": [], "diferencias": []}
    caps = sorted(p for p in (D / "capturas").glob("V2-*") if p.is_dir())
    tx, ref = D / "transacciones-P2-extracto.jsonl", D / "cobertura-referencia.json"
    for f in [tx, ref] + ([] if caps else [D / "capturas" / "V2-*"]):
        if not f.exists():
            res["ausentes"].append(str(f.relative_to(D.parent)))
    if res["ausentes"]:
        res["satisfactorio"] = False
        return res
    with tempfile.TemporaryDirectory() as t:
        rc, s = ejecutar([REPO / "captura" / "cobertura_v2.py", "--capturas", caps[0], "--transacciones", tx,
                          "--salida", Path(t) / "c.json"], t)
        if rc != 0:
            res["diferencias"].append("cobertura_v2 rc %d: %s" % (rc, s[-300:]))
        else:
            a = {r["transaccion_id"]: r for r in dec(ref)}
            b = {r["transaccion_id"]: r for r in dec(Path(t) / "c.json")["por_transaccion"]}
            res["transacciones"] = len(a)
            for i in sorted(set(a) | set(b)):
                if i not in a or i not in b:
                    res["diferencias"].append("%s: solo en %s" % (i, "laboratorio" if i in a else "recalculado"))
                    continue
                for k in sorted(set(a[i]) | set(b[i])):
                    if a[i].get(k) != b[i].get(k):
                        res["diferencias"].append("%s.%s: laboratorio %s, recalculado %s" % (i, k, a[i].get(k), b[i].get(k)))
            res["campos_comparados"] = sorted(set().union(*(r.keys() for r in a.values())))
    res["satisfactorio"] = not res["diferencias"]
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paquetes", type=Path)
    ap.add_argument("--id", action="append", help="limitar a estas ejecuciones")
    ap.add_argument("--salida", type=Path)
    ap.add_argument("--p2", type=Path, help="carpeta del extracto de P2 (se comprueba además de las ejecuciones)")
    a = ap.parse_args(argv)
    a.paquetes = a.paquetes.resolve()          # los programas se ejecutan en una carpeta temporal
    a.p2 = a.p2.resolve() if a.p2 else None
    ids = a.id or sorted(p.name for p in a.paquetes.iterdir() if p.is_dir() and p.name.startswith("V2-"))
    if not ids:
        print("NO SATISFACTORIO: no hay ejecuciones en %s" % a.paquetes)
        return 1
    informe = {"version": 1, "codigo": (REPO / "VERSION").read_text().strip() if (REPO / "VERSION").exists() else None,
               "ejecuciones": []}
    for ID in ids:
        r = una(a.paquetes / ID, ID)
        informe["ejecuciones"].append(r)
        print(ID, "SATISFACTORIO" if r["satisfactorio"] else "NO SATISFACTORIO",
              {k: ("reproducido" if v["reproducido"] else "DIFIERE") + " (%d esperadas, %d inesperadas)" % (
                  len(v.get("diferencias_esperadas", [])), len(v["diferencias_inesperadas"]))
               for k, v in r["comprobaciones"].items()}, r["entradas_ausentes"] or "")
        for k, v in r["comprobaciones"].items():
            for d in v["diferencias_inesperadas"][:8]:
                print("   inesperada", k, d)
    informe["satisfactorio"] = all(r["satisfactorio"] for r in informe["ejecuciones"])
    if a.p2:
        r = p2(a.p2)
        informe["p2"] = r
        informe["satisfactorio"] &= r["satisfactorio"]
        print("P2", r["extracto"], "SATISFACTORIO" if r["satisfactorio"] else "NO SATISFACTORIO",
              "%s transacciones, %d diferencias" % (r.get("transacciones"), len(r["diferencias"])), r["ausentes"] or "")
        for d in r["diferencias"][:10]:
            print("   ", d)
    if a.salida:
        a.salida.write_text(json.dumps(informe, ensure_ascii=False, indent=1), encoding="utf-8")
    print("GLOBAL", "SATISFACTORIO" if informe["satisfactorio"] else "NO SATISFACTORIO")
    return 0 if informe["satisfactorio"] else 1


if __name__ == "__main__":
    sys.exit(main())
