#!/usr/bin/env python3
"""Audita el CSV V2 contra el contrato y recalcula cada cierre sin futuro."""
# derivado de origen_v1/scripts/features/extract_multilayer_v2.py y
# origen_v1/scripts/engine/motor_decision.py @ d2c9772;
# cambios: comprobación independiente de esquema, población y prefijos temporales.
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import ipaddress
import json
import math
import tempfile
from collections import Counter
from pathlib import Path

try:
    from . import extraer_v2 as ex
except ImportError:
    import extraer_v2 as ex

v2 = ex.v2
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "origen_v1" / "configs" / "features" / "multilayer-v2.json"
SOURCE = ROOT / "origen_v1" / "scripts" / "features" / "extract_multilayer_v2.py"
MOTOR = ROOT / "origen_v1" / "scripts" / "engine" / "motor_decision.py"


def formulas():
    """Extrae expresiones reales del literal row de build_rows, sin duplicarlas."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_rows")
    row = next(n.value for n in ast.walk(fn) if isinstance(n, ast.AnnAssign)
               and isinstance(n.target, ast.Name) and n.target.id == "row")
    return {key.value: ast.unparse(value) for key, value in zip(row.keys, row.values)
            if isinstance(key, ast.Constant) and key.value in v2.FEATURE_NAMES}


def denominador(expr):
    node = ast.parse(expr, mode="eval").body
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "safe_ratio":
        return ast.unparse(node.args[1])
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "min":
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "safe_ratio":
                return ast.unparse(sub.args[1])
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"mean", "shannon_entropy_bits"}:
        return "cantidad de valores de " + ast.unparse(node.args[0])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return ast.unparse(node.right)
    return "según expresión"


def referencia(archivo, ip, anchor, poblacion, fronteras, temp_dir=None,
               historia_s=ex.HORIZONTE_MOTOR_S, estado="continuo"):
    """Prefijo PCAP/EVE hasta t_fin; camino de funciones usado por motor_decision.

    Con historia_s (el motor V1 usa --history-seconds 230) solo se usa [t_fin − historia, t_fin]
    sin recortar el contexto por fronteras ni por nombres de PCAP.
    """
    piso = max((f for f in fronteras if f <= anchor), default=float("-inf")) if estado == "por-bloque" else float("-inf")
    rutas = ex.rutas_pcap(archivo)
    if historia_s is not None:
        piso = max(piso, anchor - historia_s)
    inv = {}
    contextos = []
    for ctx in ex.leer_contextos_crudos(rutas, inv):
        if ctx.packet.timestamp > anchor:
            break
        if ctx.packet.timestamp >= piso:
            contextos.append(ctx)
    deduplicados, _ = ex.dv2.deduplicar_espejo_v2(contextos)
    packets = [p for p in deduplicados if p.src_ip in poblacion or p.dst_ip in poblacion]
    obs = [o for o in v2.attribute_packets(packets, ipaddress.ip_network("0.0.0.0/0"))
           if o.entity_ip == ip]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", dir=temp_dir or Path.cwd(), delete=False) as handle:
        for ts, line, event in ex.leer_eve(archivo):
            if ts > anchor + ex.VENTANA_ORDEN_EVE_S:
                break
            if piso <= ts <= anchor and (event.get("src_ip") in poblacion or event.get("dest_ip") in poblacion):
                handle.write(line)
        path = Path(handle.name)
    try:
        apps = [a for a in v2.load_app_observations(path, ipaddress.ip_network("0.0.0.0/0"))
                if a.entity_ip == ip]
    finally:
        path.unlink()
    if not obs and not apps:
        return dict.fromkeys(v2.FEATURE_NAMES, 0.0)
    base = v2.build_rows(archivo.name, obs, apps, capture_start=min(
        [piso] if math.isfinite(piso) else [min([o.timestamp for o in obs] + [a.timestamp for a in apps])]))
    encontrado = next((r for r in base if r["entity_ip"] == ip and r["window_end_utc"] == ex.utc(anchor)), None)
    return encontrado or dict.fromkeys(v2.FEATURE_NAMES, 0.0)


def muestra(filas: list, n: int | None) -> list:
    """n filas repartidas a lo largo de la ejecución (no las n primeras), incluidas la primera y la última."""
    if n is None or n >= len(filas):
        return filas
    if n <= 1:
        return filas[:n]
    return [filas[round(i * (len(filas) - 1) / (n - 1))] for i in range(n)]


def verificar(archivo: Path, salida: Path, poblacion: set[str], fronteras: list[float], max_filas: int | None = None,
              historia_s: float = ex.HORIZONTE_MOTOR_S, estado: str = "continuo"):
    contrato = json.loads(SCHEMA.read_text(encoding="utf-8"))
    nombres = [f["name"] for f in contrato["features"]]
    expr = formulas()
    with (salida / "filas.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        cabecera = reader.fieldnames
        filas = list(reader)
    esquema_ok = nombres == list(v2.FEATURE_NAMES) == cabecera[len(ex.CONTROL):]
    tabla = [{"orden": f["order"], "nombre": f["name"], "formula_codigo": expr[f["name"]],
              "unidad": f["unit"], "denominador": denominador(expr[f["name"]]),
              "ventana_s": f["window_seconds"], "sin_datos": "0; V1 no emite NaN"}
             for f in contrato["features"]]
    constantes = []
    for name in nombres:
        valores = {r[name] for r in filas}
        if len(valores) <= 1:
            causa = ("sin eventos EVE de ese tipo o sin señal en los perfiles" if name.startswith(("http", "dns", "tls"))
                     else "sin actividad observable o tráfico homogéneo en esta población")
            constantes.append({"columna": name, "valor": next(iter(valores), None), "todo_cero": valores <= {"0", "0.0"},
                               "causa_probable": causa})
    conteos = Counter((r["ip"], r["bloque"]) for r in filas)
    errores = []
    verificadas = 0
    for row in muestra(filas, max_filas):
        anchor = v2.parse_eve_timestamp(row["ventana_fin"])
        esperado = referencia(archivo, row["ip"], anchor, poblacion, fronteras, salida, historia_s, estado)
        diferentes = [n for n in nombres if float(row[n]) != float(esperado[n])]
        verificadas += 1
        if diferentes:
            errores.append({"ip": row["ip"], "ventana_fin": row["ventana_fin"], "columnas": diferentes})
    motor = MOTOR.read_text(encoding="utf-8")
    funciones_motor = all(s in motor for s in ("import extract_multilayer_v2 as extractor", "extractor.build_rows",
                                               "extractor.attribute_packets"))
    # Deduplicación: el extractor usa deduplicar_v2; la paridad exige que el motor de referencia
    # (origen_v1, copia sin modificar del producto) use la misma función y un módulo idéntico.
    copia_motor = MOTOR.parents[1] / "features" / "deduplicar_v2.py"
    sha_ext = hashlib.sha256(Path(ex.dv2.__file__).read_bytes()).hexdigest()
    sha_motor = hashlib.sha256(copia_motor.read_bytes()).hexdigest() if copia_motor.exists() else None
    usa_v2 = "deduplicar_espejo_v2" in motor and "parse_con_contexto_v2" in motor
    deduplicacion = {"extractor": "deduplicar_v2.deduplicar_espejo_v2", "sha256_extractor": sha_ext,
                     "motor_referencia": ("deduplicar_v2.deduplicar_espejo_v2" if usa_v2 else
                                          "v3.deduplicar_espejo" if "v3.deduplicar_espejo" in motor else "desconocida"),
                     "sha256_motor": sha_motor, "motor_misma_funcion": bool(usa_v2 and sha_motor == sha_ext),
                     # el motor la usa solo con esta opción; sin ella sigue con la de V1 (modelo actual)
                     "motor_opcion": "--deduplicacion v2" if '"--deduplicacion"' in motor else None}
    resumen = json.loads((salida / "resumen.json").read_text(encoding="utf-8"))
    informe = {"esquema_ok": esquema_ok, "columnas": tabla, "constantes": constantes,
               "sin_futuro_ok": not errores, "paridad_motor_ok": funciones_motor and not errores,
               "camino_motor_mismas_funciones": funciones_motor,
               "deduplicacion": deduplicacion,
               "referencia": ("prefijo completo hasta t_fin" if historia_s is None else
                              "solo [t_fin - %g s, t_fin], como el motor en operación" % historia_s),
               "filas_muestreadas": "repartidas a lo largo de la ejecución" if max_filas else "todas",
               "filas_verificadas": verificadas, "filas_totales": len(filas), "diferencias": errores,
               "filas_por_ip_bloque": [{"ip": ip, "bloque": bloque, "filas": n}
                                       for (ip, bloque), n in sorted(conteos.items())],
               "copias_espejo_quitadas": resumen.get("copias_espejo_quitadas", 0),
               "paquetes_descartados_poblacion": resumen.get("paquetes_descartados_poblacion", 0)}
    (salida / "verificacion.json").write_text(json.dumps(informe, indent=2, ensure_ascii=False), encoding="utf-8")
    md = ["# Verificación V2", "", f"Esquema: {esquema_ok}. Sin futuro: {not errores}. Paridad motor: {informe['paridad_motor_ok']}.",
          f"Filas verificadas: {verificadas}/{len(filas)}. Copias quitadas: {informe['copias_espejo_quitadas']}.",
          f"Paquetes descartados: {informe['paquetes_descartados_poblacion']}.", "",
          "| # | Columna | Fórmula del código | Unidad | Denominador | Ventana s | Sin datos |",
          "|---:|---|---|---|---|---:|---|"]
    for c in tabla:
        md.append(f"| {c['orden']} | {c['nombre']} | `{c['formula_codigo']}` | {c['unidad']} | `{c['denominador']}` | {c['ventana_s']} | 0 |")
    md.extend(["", "## Constantes", ""])
    md.extend(f"- {c['columna']}: {c['valor']}; {c['causa_probable']}" for c in constantes)
    md.extend(["", "## Filas por IP y bloque", ""])
    md.extend(f"- {c['ip']} / {c['bloque']}: {c['filas']}" for c in informe["filas_por_ip_bloque"])
    (salida / "verificacion.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return informe


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archivo", type=Path)
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--poblacion", type=Path)
    ap.add_argument("--fronteras", type=Path)
    ap.add_argument("--max-filas", type=int, help="n filas repartidas a lo largo de la ejecución")
    ap.add_argument("--historia-s", type=float, default=ex.HORIZONTE_MOTOR_S,
                    help="horizonte del motor V1 (por omisión: 230 s)")
    ap.add_argument("--estado", choices=("continuo", "por-bloque"), default="continuo")
    a = ap.parse_args()
    resultado = verificar(a.archivo, a.salida, ex.poblacion_desde(a.poblacion), ex.fronteras_desde(a.fronteras), a.max_filas,
                          a.historia_s, a.estado)
    print(json.dumps({k: resultado[k] for k in ("esquema_ok", "sin_futuro_ok", "paridad_motor_ok", "filas_verificadas")}, ensure_ascii=False))
    return 0 if resultado["esquema_ok"] and resultado["sin_futuro_ok"] and resultado["paridad_motor_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
