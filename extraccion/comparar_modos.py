#!/usr/bin/env python3
"""Compara las 28 variables con estado continuo y por bloque."""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

try:
    from . import extraer_v2 as ex
except ImportError:
    import extraer_v2 as ex


def comparar(continuo: Path, por_bloque: Path, fronteras: list[float], salida: Path,
             guarda_s: float = ex.GUARDA_ESTADO_S) -> dict:
    columnas = Counter()
    identicas = distintas = fuera = 0
    distancia_maxima = None
    salida.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=salida, suffix=".sqlite", delete=False) as temp:
        db_path = Path(temp.name)
    db = sqlite3.connect(db_path)
    try:
        db.execute("CREATE TABLE filas (ip TEXT, fin TEXT, datos TEXT, PRIMARY KEY(ip, fin))")
        with continuo.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                db.execute("INSERT INTO filas VALUES (?,?,?)",
                           (row["ip"], row["ventana_fin"],
                            json.dumps([row[c] for c in ex.v2.FEATURE_NAMES])))
        db.commit()
        with por_bloque.open(newline="", encoding="utf-8") as handle:
            for rb in csv.DictReader(handle):
                clave = rb["ip"], rb["ventana_fin"]
                encontrado = db.execute("SELECT datos FROM filas WHERE ip=? AND fin=?", clave).fetchone()
                if encontrado is None:
                    raise ValueError("filas no emparejadas por (ip, ventana_fin)")
                db.execute("DELETE FROM filas WHERE ip=? AND fin=?", clave)
                cambios = [c for c, valor in zip(ex.v2.FEATURE_NAMES, json.loads(encontrado[0]))
                           if float(valor) != float(rb[c])]
                if not cambios:
                    identicas += 1
                    continue
                distintas += 1
                columnas.update(cambios)
                anchor = ex.v2.parse_eve_timestamp(rb["ventana_fin"])
                distancias = [anchor - f for f in fronteras if f <= anchor]
                distancia = min(distancias, default=None)
                if distancia is None or distancia >= guarda_s:
                    fuera += 1
                if distancia is not None:
                    distancia_maxima = max(distancia_maxima or 0, distancia)
        if db.execute("SELECT 1 FROM filas LIMIT 1").fetchone():
            raise ValueError("filas no emparejadas por (ip, ventana_fin)")
    finally:
        db.close()
        db_path.unlink()
    resultado = {"filas_totales": identicas + distintas, "filas_identicas": identicas,
                 "filas_distintas": distintas, "columnas_afectadas": dict(sorted(columnas.items())),
                 "distintas_fuera_de_guarda": fuera,
                 "distancia_maxima_frontera_ancla_s": distancia_maxima,
                 "guarda_estado_s": guarda_s}
    (salida / "comparacion_modos.json").write_text(
        json.dumps(resultado, indent=2, ensure_ascii=False), encoding="utf-8")
    return resultado


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("captura", type=Path, nargs="?")
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--poblacion", type=Path)
    ap.add_argument("--fronteras", type=Path)
    ap.add_argument("--continuo", type=Path, help="filas.csv ya calculado")
    ap.add_argument("--por-bloque", type=Path, help="filas.csv ya calculado")
    args = ap.parse_args()
    if bool(args.continuo) != bool(args.por_bloque):
        ap.error("--continuo y --por-bloque deben usarse juntos")
    fronteras = ex.fronteras_desde(args.fronteras)
    if args.continuo:
        rutas = args.continuo, args.por_bloque
        resumen_path = args.continuo.parent / "resumen.json"
        guarda = json.loads(resumen_path.read_text(encoding="utf-8")).get("guarda_estado_s", ex.GUARDA_ESTADO_S) if resumen_path.exists() else ex.GUARDA_ESTADO_S
        if not fronteras and resumen_path.exists():
            fronteras = [ex.v2.parse_eve_timestamp(f) for f in json.loads(resumen_path.read_text(encoding="utf-8")).get("fronteras_utc", [])]
    else:
        if args.captura is None:
            ap.error("se requiere captura o los dos CSV")
        poblacion = ex.poblacion_desde(args.poblacion)
        rutas = args.salida / "continuo" / "filas.csv", args.salida / "por-bloque" / "filas.csv"
        ex.procesar(args.captura, rutas[0].parent, poblacion, fronteras, estado_modo="continuo")
        ex.procesar(args.captura, rutas[1].parent, poblacion, fronteras, estado_modo="por-bloque")
        guarda = ex.GUARDA_ESTADO_S
    print(json.dumps(comparar(*rutas, fronteras, args.salida, guarda), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
