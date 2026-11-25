#!/usr/bin/env python3
"""Concilia cada intercambio v3 del cliente con HTTP/HTTPS o DNS.

HTTP se empareja por IP y puerto origen, ventana temporal y, para P2,
peticion_en_conexion. DNS añade el identificador de consulta.
Una parada o correspondencia ambigua queda no verificable.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import json
from pathlib import Path

MARGEN_S = 5.0
HTTP = {"obtener", "consulta", "envio"}
DNS = {"dns"}
INTENCIONAL = set()


def ts(s: str) -> float:
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def leer_jsonl(rutas):
    errores = []
    for r in rutas:
        with open(r, encoding="utf-8") as f:
            for n, linea in enumerate(f, 1):
                if not linea.strip():
                    continue
                try:
                    yield json.loads(linea)
                except json.JSONDecodeError as e:
                    errores.append({"fichero": str(r), "linea": n, "error": str(e)})
    leer_jsonl.errores = errores


def indice_http(registros):
    idx = collections.defaultdict(list)
    for r in registros:
        if "cliente" in r and "inicio_utc" in r:
            idx[(r["cliente"], int(r["puerto_cliente"]))].append(r)
    return idx


def indice_dns(registros):
    idx = collections.defaultdict(list)
    for r in registros:
        if "cliente" in r and "id" in r:
            idx[(r["cliente"], int(r["puerto_cliente"]), int(r["id"]))].append(r)
    return idx


def cobertura_registro(registros) -> tuple[float, float] | None:
    """Intervalo [primer, último] evento del registro: fuera de él no se puede afirmar ausencia."""
    t = [ts(r["utc"] if "utc" in r else r["inicio_utc"]) for r in registros if ("utc" in r or "inicio_utc" in r)]
    return (min(t), max(t)) if t else None


def candidatos(lista, ini, fin, campo_i, campo_f=None):
    out = []
    for r in lista:
        a = ts(r[campo_i])
        b = ts(r[campo_f]) if campo_f else a
        if b >= ini - MARGEN_S and a <= fin + MARGEN_S:
            out.append(r)
    return out


def conciliar_tx(t: dict, ihttp, idns, cub_http, cub_dns) -> dict:
    acc = t["accion"]
    ini, fin = ts(t["inicio_utc"]), ts(t["fin_utc"])
    out = {"transaccion_id": t["transaccion_id"], "perfil": t["perfil"], "accion": acc,
           "clase_cliente": t.get("clase"), "inicio_utc": t["inicio_utc"]}
    if t.get("clase") == "incompleta_no_verificable":
        return out | {"clase": "incompleta_no_verificable", "motivo": "parada_durante_accion"}
    if acc not in HTTP and acc not in DNS:
        clase = "fallo_imprevisto" if t.get("clase") == "fallo_inesperado" else (
            "error_intencional" if acc in INTENCIONAL else "correcto")
        return out | {"clase": clase, "motivo": "sin_registro_por_diseno"}
    puerto = t.get("origen_puerto")
    if puerto is None:
        # Falló antes de tener socket: solo cuenta el cliente.
        return out | {"clase": "fallo_imprevisto", "motivo": "sin_puerto_origen", "excepcion": t.get("excepcion")}
    if acc in HTTP:
        cub = cub_http
        c = candidatos(ihttp.get((t["origen_ip"], int(puerto)), []), ini, fin, "inicio_utc", "fin_utc")
        if t.get("perfil") == "P2" and t.get("peticion_en_conexion") is not None:
            c = [r for r in c if r.get("peticion_en_conexion") == t["peticion_en_conexion"]]
    else:
        cub = cub_dns
        c = candidatos(idns.get((t["origen_ip"], int(puerto), int(t.get("dns_id", -1))), []), ini, fin, "utc")
    if not c:
        dentro = cub is not None and cub[0] <= ini and fin <= cub[1]
        if not dentro:
            return out | {"clase": "incompleta_no_verificable", "motivo": "fuera_del_registro_servidor"}
        return out | {"clase": "fallo_imprevisto", "motivo": "sin_registro_servidor"}
    if acc in DNS:
        consultas = [r for r in c if r.get("sentido") == "consulta"]
        resp = [r for r in c if r.get("sentido") == "respuesta"]
        if len(consultas) != 1 or len(resp) != 1:
            return out | {"clase": "incompleta_no_verificable", "motivo": "dns_ambiguo_%d_%d" % (len(consultas), len(resp))}
        rc = resp[0].get("rcode")
        out["servidor_rcode"] = rc
        esperado = "NOERROR"
        concuerda = rc == esperado and t.get("dns_rcode") == 0
        if not concuerda or t.get("clase") == "fallo_inesperado":
            return out | {"clase": "fallo_imprevisto", "motivo": "dns_discrepa"}
        return out | {"clase": "error_intencional" if acc in INTENCIONAL else "correcto", "motivo": "conciliada"}
    if len(c) != 1:
        return out | {"clase": "incompleta_no_verificable", "motivo": "http_ambiguo_%d" % len(c)}
    s = c[0]
    out.update(servidor_codigo=s.get("codigo"), servidor_resultado=s.get("resultado"),
               peticion_en_conexion=s.get("peticion_en_conexion"))
    cod_cli = t.get("http_codigo")
    if s.get("codigo") != cod_cli:
        return out | {"clase": "fallo_imprevisto", "motivo": "codigo_discrepa"}
    if s.get("resultado") != "completa" or t.get("incompleta"):
        return out | {"clase": "fallo_imprevisto", "motivo": "transferencia_incompleta"}
    if t.get("clase") == "fallo_inesperado":
        return out | {"clase": "fallo_imprevisto", "motivo": "cliente_fallo"}
    return out | {"clase": "correcto", "motivo": "conciliada"}


def conciliar(transacciones, http, dns) -> dict:
    ihttp, idns = indice_http(http), indice_dns(dns)
    cub_http, cub_dns = cobertura_registro(http), cobertura_registro(dns)
    filas = [conciliar_tx(t, ihttp, idns, cub_http, cub_dns) for t in transacciones]
    resumen = collections.Counter(f["clase"] for f in filas)
    por_perfil = collections.defaultdict(collections.Counter)
    por_accion = collections.defaultdict(collections.Counter)
    motivos = collections.Counter()
    for f in filas:
        por_perfil[f["perfil"]][f["clase"]] += 1
        por_accion[f["accion"]][f["clase"]] += 1
        if f["clase"] in ("fallo_imprevisto", "incompleta_no_verificable"):
            motivos[f["motivo"]] += 1
    usados = {(f["accion"]) for f in filas}
    return {"filas": filas,
            "resumen": {"total": len(filas), "clases": dict(resumen), "motivos_no_ok": dict(motivos),
                        "por_perfil": {k: dict(v) for k, v in sorted(por_perfil.items())},
                        "por_accion": {k: dict(v) for k, v in sorted(por_accion.items())},
                        "acciones": sorted(usados),
                        "registro_http_eventos": len(http), "registro_dns_eventos": len(dns)}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transacciones", nargs="+", required=True)
    ap.add_argument("--servidor", nargs="*", default=[], help="JSONL de servidor_lab_v2 (http y https)")
    ap.add_argument("--dns", nargs="*", default=[], help="JSONL de registro_dns_v2")
    ap.add_argument("--salida", required=True, help="directorio de salida")
    a = ap.parse_args()
    tx = list(leer_jsonl(a.transacciones)); e1 = leer_jsonl.errores
    http = list(leer_jsonl(a.servidor)); e2 = leer_jsonl.errores
    dns = list(leer_jsonl(a.dns)); e3 = leer_jsonl.errores
    r = conciliar(tx, http, dns)
    r["resumen"]["errores_lectura"] = e1 + e2 + e3
    if r["resumen"]["errores_lectura"]:
        r["resumen"]["veredicto"] = "no_verificable_por_errores_de_lectura"
    sal = Path(a.salida)
    sal.mkdir(parents=True, exist_ok=True)
    with open(sal / "conciliacion.jsonl", "w", encoding="utf-8") as f:
        for fila in r["filas"]:
            f.write(json.dumps(fila, sort_keys=True, ensure_ascii=False) + "\n")
    (sal / "conciliacion-resumen.json").write_text(json.dumps(r["resumen"], indent=1, sort_keys=True, ensure_ascii=False))
    print(json.dumps({k: r["resumen"][k] for k in ("total", "clases", "motivos_no_ok")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
