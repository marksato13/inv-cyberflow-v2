#!/usr/bin/env python3
"""Ficha de trazabilidad de una ejecución V2 (punto 8 del Bloque 1).

    python3 trazabilidad.py ejecuciones/<ID> [--programas codigo/programas] \
        [--version-inferida a5c70ab --fuente-version "despliegue 25-nov 06:10Z"] > traza.json

Reúne en un JSON, sin recalcular nada, lo que la ejecución dejó escrito:
identificadores, versión del código (registrada o inferida, y se dice cuál), horas planificadas y
reales, márgenes antes y después del generador, fases del programa con su hora UTC, referencia
temporal (NTP de cada equipo), inventario de PCAP/EVE con sus sha256, huecos, sondeo del
espejo, pasos del análisis y dictamen.

Estos campos son de trazabilidad: NO son atributos del modelo (IF) ni deben entrar en la
extracción como columnas de entrenamiento.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


def leer_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def leer_jsonl(p: Path):
    if not p.exists():
        return []
    filas = []
    for linea in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            filas.append(json.loads(linea))
        except ValueError:
            filas.append({"ilegible": linea[:200]})
    return filas


def utc(epoch):
    if epoch in (None, 0, 0.0):
        return None
    return dt.datetime.fromtimestamp(float(epoch), dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(p: Path):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def reloj(p: Path):
    """Extrae lo comparable de relojes-*.txt (timedatectl + chronyc/timesyncd)."""
    if not p.exists():
        return None
    t = p.read_text(encoding="utf-8", errors="replace")
    r = {"fichero": p.name, "marca_utc": t.splitlines()[0].strip() if t else None}
    for clave, patron in (("ntp_sincronizado", r"NTPSynchronized=(\w+)"),
                          ("referencia", r"Reference ID\s*:\s*(.+)"),
                          ("desfase_sistema", r"System time\s*:\s*(.+)"),
                          ("estrato", r"Stratum\s*:\s*(\d+)"),
                          ("servidor", r"Server:\s*(.+)"),
                          ("desfase", r"Offset:\s*(.+)")):
        m = re.search(patron, t)
        if m:
            r[clave] = m.group(1).strip()
    return r


def fases(programa, inicio_gen):
    if not programa:
        return None
    salida = []
    for b in programa.get("bloques", []):
        f = {k: b.get(k) for k in ("id", "jornada", "particion", "inicio_s", "fin_s")}
        if inicio_gen:
            f["inicio_utc"] = utc(inicio_gen + b.get("inicio_s", 0))
            f["fin_utc"] = utc(inicio_gen + b.get("fin_s", 0))
        for clave in ("nivel", "niveles", "perfiles", "factor"):
            if clave in b:
                f[clave] = b[clave]
        salida.append(f)
    return salida


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ejecucion", type=Path)
    ap.add_argument("--programas", type=Path)
    ap.add_argument("--version-inferida")
    ap.add_argument("--fuente-version")
    a = ap.parse_args()
    d = a.ejecucion
    lz = leer_json(d / "lanzamiento.json") or {}
    ma = leer_json(d / "manifiesto-archivador.json") or {}
    mg = leer_json(d / "manifiesto-generador.json") or {}
    rg = leer_json(d / "resultado-global.json") or {}
    plan, real = lz.get("planificado", {}), lz.get("real", {})
    programa = None
    if a.programas and lz.get("programa"):
        pp = a.programas / lz["programa"]
        if pp.exists():
            programa = leer_json(pp)
            if programa is not None and sha256(pp) != lz.get("programa_sha256"):
                programa = {"aviso": "el programa actual no coincide con el sha256 registrado", **programa}
    gi, gf = real.get("generador_inicio_epoch"), real.get("generador_fin_epoch")
    pp_, up = real.get("primer_paquete_epoch") or ma.get("primer_paquete_epoch"), \
        real.get("ultimo_paquete_epoch") or ma.get("ultimo_paquete_epoch")

    def leer_intervalo(nombre):
        p = d / nombre
        if not p.exists():
            return None
        x = p.read_text().split()
        return {"desde_epoch": float(x[0]), "hasta_epoch": float(x[1]),
                "desde_utc": utc(x[0]), "hasta_utc": utc(x[1])} if len(x) >= 2 else None

    version = lz.get("codigo_version")
    traza = {
        "nota": "campos de trazabilidad; no son atributos del IF",
        "ids": {"ejecucion": lz.get("ejecucion") or d.name, "programa": lz.get("programa"),
                "programa_sha256": lz.get("programa_sha256"), "dns_unidad": lz.get("dns_unidad")},
        "codigo": {"version": version or a.version_inferida,
                   "fuente": "lanzamiento.json" if version else
                             (("inferida: " + (a.fuente_version or "sin fuente")) if a.version_inferida else "no registrada"),
                   "generador_sha256": (mg.get("entorno_fin") or {}).get("codigo")},
        "tiempos": {
            "planificado": {k: {"epoch": v, "utc": utc(v)} for k, v in plan.items()},
            "real": {k: {"epoch": v, "utc": utc(v)} for k, v in real.items()},
            "desvio_inicio_generador_s": round(gi - plan["generador_inicio_epoch"], 3) if gi and plan.get("generador_inicio_epoch") else None,
            "desvio_fin_generador_s": round(gf - plan["generador_fin_epoch"], 3) if gf and plan.get("generador_fin_epoch") else None,
            "margen_captura_antes_s": round(gi - pp_, 3) if gi and pp_ else None,
            "margen_captura_despues_s": round(up - gf, 3) if gf and up else None,
            "intervalo_captura": leer_intervalo("intervalo-captura.txt"),
            "intervalo_servidor": leer_intervalo("intervalo-servidor.txt"),
            "intervalo_exclusion_v1": leer_intervalo("intervalo-exclusion.txt"),
        },
        "fases": fases(programa, gi),
        "referencia_temporal": {
            "regla": "UTC; NTP en cada equipo; el reloj del switch NO es autoritativo",
            "relojes": [reloj(p) for p in sorted(d.glob("relojes-*.txt"))],
            "generador_fin": {k: (mg.get("entorno_fin") or {}).get(k) for k in ("ntp_sincronizado", "utc", "timesync")},
            "desfases_supervision_s": [
                {k: f.get(k) for k in ("utc", "desfase_clientes_s", "desfase_sensor1_s")}
                for f in leer_jsonl(d / "supervision.jsonl")],
        },
        "inventario": {
            "pcap": {k: ma.get(k) for k in ("pcap_ficheros", "pcap_bytes", "pcap_completo", "pcap_huecos", "inventario_sha256", "ubicacion")},
            "eve": {k: ma.get(k) for k in ("eve_bytes", "eve_completo", "eve_huecos", "eve_corruptas", "eve_sha256")},
            "nic": {k: ma.get(k) for k in ("delta_nic_rx_packets", "delta_nic_rx_dropped")},
            "archivador": {k: ma.get(k) for k in ("estado", "motivo", "inicio", "fin")},
            "generador": {"estado": mg.get("estado"), "motivo": mg.get("motivo"), "codigos": mg.get("codigos"),
                          "ficheros_sha256": mg.get("ficheros")},
            "ficheros_ejecucion_sha256": {p.name: sha256(p) for p in sorted(d.iterdir())
                                          if p.is_file() and p.stat().st_size < 512 * 1024 * 1024},
        },
        "huecos": {"pcap": ma.get("pcap_huecos"), "eve": ma.get("eve_huecos")},
        "sondeo_espejo": leer_json(d / "calidad-espejo-sondeo.json"),
        "pasos_analisis": leer_jsonl(d / "pasos-analisis.jsonl"),
        "dictamen": {k: rg.get(k) for k in ("global", "dictamen", "codigo_salida", "motivos", "fuente_pasos")},
    }
    print(json.dumps(traza, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
