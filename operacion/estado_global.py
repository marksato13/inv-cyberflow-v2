#!/usr/bin/env python3
"""Consolida evidencias de una ejecución V2 sin aprobar datos ausentes."""
from __future__ import annotations

import argparse
import collections
import json
import re
from pathlib import Path


def leer(ruta: Path):
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def lineas(ruta: Path):
    try:
        return [json.loads(l) for l in ruta.read_text(encoding="utf-8").splitlines() if l.strip()]
    except (OSError, ValueError):
        return None


def evaluar(identificador: str, pruebas: Path, ejecucion: Path | None = None,
            captura: Path | None = None) -> dict:
    e = ejecucion or pruebas / "registros"
    c = captura or pruebas.parent.parent / "capturas" / identificador
    g = pruebas / "generador" / identificador
    man_g = leer(g / "manifiesto-fin.json")
    man_a = leer(c / "manifiesto.json")
    if man_g is None:
        man_g = leer(e / "manifiesto-fin.json")
    estados = {
        "generador": man_g.get("estado", "incompleta") if man_g else "ausente",
        "archivador": man_a.get("estado", "incompleta") if man_a else "ausente",
    }
    vigia = lineas(e / "vigia.jsonl")
    if vigia is None:
        estados["vigia"] = "ausente"
    elif any(x.get("tipo") in ("parada", "parada_fallida") for x in vigia):
        estados["vigia"] = "paro"
    elif any(x.get("tipo") == "archivador_terminado" for x in vigia):
        estados["vigia"] = "sin_paradas"
    else:
        estados["vigia"] = "ausente"
    supervision = lineas(e / "supervision.jsonl")
    invalidaciones = lineas(e / "invalidaciones.jsonl")
    completos = bool(supervision) and (
        invalidaciones is not None or not (e / "invalidaciones.jsonl").exists()) and all(
        x.get("enlace_valido") is True and
        x.get("output_drops") is not None and
        x.get("kernel_drops") is not None and
        x.get("libre_gb") is not None and
        x.get("eve_huecos") is not None and x.get("pcap_huecos") is not None and
        all(x.get("desfase_" + h + "_s") is not None for h in ("sensor1", "clientes"))
        for x in supervision)
    estados["supervision"] = (
        "con_invalidaciones" if invalidaciones else
        "sin_invalidaciones" if completos else "sin_datos")
    # Sondeo del destino del SPAN (analizar_sondeo.py sobre el periodo de captura). Que no haya
    # sondeo, o que haya huecos, NUNCA se lee como «sin pérdidas»: es «sin_datos»/«indeterminado».
    sondeo = leer(e / "calidad-espejo-sondeo.json")
    if not isinstance(sondeo, dict) or "error" in sondeo or not sondeo.get("intervalos"):
        estados["espejo"] = "sin_datos"
    else:
        seg = collections.Counter()
        for iv in sondeo["intervalos"]:
            seg[iv.get("clase")] += max(0.0, float(iv["hasta"]) - float(iv["desde"]))
        estados["espejo"] = ("con_descartes" if seg["con_descartes"] > 0 else
                             "indeterminado" if seg["indeterminado"] > 0 or set(seg) - {"sin_descartes", "con_descartes", "indeterminado"}
                             else "sin_descartes")
    estados["calidad_copias"] = calidad_copias(leer(pruebas / "calidad-copias-espejo.json"))
    estados["calidad_dns"] = calidad_dns(leer(pruebas / "calidad-contraste-dns.json"),
                                         lineas(e / ("dns-%s.jsonl" % identificador)))
    evidencias = [
        pruebas / "extraccion" / "resumen.json",
        pruebas / "extraccion" / "verificacion.json",
        pruebas / "extraccion" / "trazabilidad.json",
        pruebas / "extraccion" / "entradas_if.csv",
        pruebas / "extraccion" / "ventanas_meta.csv",
        pruebas / "conciliacion" / "conciliacion-resumen.json",
        pruebas / "conciliacion" / "conciliacion.jsonl",
    ]
    presentes = [p.exists() for p in evidencias]
    # Pasos del análisis. Desde el cierre de bloque 1 (26-nov) cerrar_v2.sh escribe un registro
    # estructurado (pasos-analisis.jsonl, una línea por paso con rc). Las ejecuciones anteriores solo
    # tienen el texto «paso rc=N» de analisis-salida.txt, que se lee como antes (fuente_pasos lo dice).
    reg_pasos = lineas(e / "pasos-analisis.jsonl")
    if reg_pasos:
        rcs = {x["paso"]: str(x.get("rc")) for x in reg_pasos if "paso" in x}
        fuente_pasos = "pasos-analisis.jsonl"
        pasos = PASOS_OBLIGATORIOS
    else:
        sal = e / "analisis-salida.txt"
        rcs = dict(re.findall(r"([a-z]+) rc=(\d+)", sal.read_text(encoding="utf-8", errors="replace"))) if sal.exists() else {}
        fuente_pasos = "analisis-salida.txt" if sal.exists() else None
        pasos = ("conciliar", "extraer", "verificar", "metadatos")
    if not any(presentes) and not rcs:
        estados["analisis"] = "ausente"
    elif all(presentes) and all(rcs.get(p) == "0" for p in pasos) and (
            leer(pruebas / "extraccion" / "trazabilidad.json") or {}).get("trazabilidad_ok") is True:
        estados["analisis"] = "completo"
    else:
        estados["analisis"] = "incompleto"
    excl = leer(e / "exclusion-v1.json")
    estados["exclusion_v1"] = (
        "cubre" if excl and excl.get("cubierto") is True else
        "no_cubre" if excl and excl.get("cubierto") is False else "desconocido")
    criterios = leer(pruebas / "criterios.json")
    claves = [f"C{i}" for i in range(1, 14)] + ["C11b"]
    motivos = []
    fallos = {
        "generador": ("incompleta",),
        "archivador": ("incompleta",),
        "vigia": ("paro",),
        "supervision": ("con_invalidaciones",),
        "exclusion_v1": ("no_cubre",),
        "espejo": ("con_descartes",),
        # Política de calidad (docs/BLOQUE1-POLITICA-CALIDAD.md): la evidencia existe y muestra un
        # defecto ⇒ fallo. La evidencia falta o no decide ⇒ indeterminación (ver «faltantes»).
        "calidad_copias": ("perdida", "entrada_danada"),
        "calidad_dns": ("discrepancia", "entrada_danada"),
    }
    for nombre, valores in fallos.items():
        if estados[nombre] in valores:
            motivos.append("%s:%s" % (nombre, estados[nombre]))
    fallidos = [p for p in pasos if rcs.get(p) not in (None, "0")]
    if fallidos:
        motivos.append("analisis:fallo")
        motivos.extend("analisis:fallo:%s" % p for p in fallidos)
    ausentes = [p for p in pasos if p not in rcs] if rcs else list(pasos)
    for p in ausentes:
        motivos.append("falta:paso:%s" % p)
    if (leer(pruebas / "extraccion" / "trazabilidad.json") or {}).get("trazabilidad_ok") is False:
        motivos.append("analisis:trazabilidad_fallida")
    if criterios:
        for clave in claves:
            dato = criterios.get(clave)
            if isinstance(dato, dict) and dato.get("ok") is False:
                motivos.append("criterio:%s" % clave)
    prueba = lineas(e / "prueba-parada.jsonl")
    if prueba:
        motivos.append("prueba_parada:%s" % prueba[-1].get("provocado", "desconocido"))
    faltantes = [k for k, v in estados.items() if v in
                 ("ausente", "sin_datos", "desconocido", "indeterminado",
                  "sin_eventos", "falta_pcap_dc1", "sin_transacciones")]
    if estados["analisis"] == "incompleto":
        faltantes.append("analisis")
    if not criterios:
        faltantes.append("criterios")
    else:
        faltantes += ["criterio:%s" % k for k in claves
                      if k not in criterios or not isinstance(criterios[k], dict)
                      or criterios[k].get("ok") is not True and criterios[k].get("ok") is not False]
    if not (e / "lanzamiento.json").exists():
        faltantes.append("lanzamiento")
    motivos.extend("falta:%s" % k for k in faltantes)
    global_estado = "no_aprobada" if any(not m.startswith("falta:") for m in motivos) else (
        "indeterminada" if any(m.startswith("falta:") for m in motivos) else "aprobada")
    return {"ejecucion": identificador, **estados, "global": global_estado,
            "dictamen": DICTAMEN[global_estado], "codigo_salida": CODIGO[global_estado],
            "motivos": motivos, "pasos": rcs, "fuente_pasos": fuente_pasos}


PASOS_OBLIGATORIOS = ("conciliar", "cobertura", "fronteras", "extraer", "verificar", "metadatos")

# Clases de copias_espejo.py para la población (docs/BLOQUE1-POLITICA-CALIDAD.md §2).
COPIAS_PERDIDA = ("falta_copia", "vlan_incorrecta")
COPIAS_INDETERMINADO = ("ambiguo", "copias_de_mas", "inesperado", "no_determinable")


def calidad_copias(r) -> str:
    """completo | perdida | entrada_danada | indeterminado | sin_eventos | sin_datos."""
    if not isinstance(r, dict) or "denominadores" not in r:
        return "sin_datos"
    if r.get("entrada_completa") is not True or r.get("resultado_global") != "examinado_completo":
        return "entrada_danada"
    clases = r["denominadores"].get("eventos_por_clase") or {}
    if any(clases.get(c, 0) for c in COPIAS_PERDIDA):
        return "perdida"
    if any(clases.get(c, 0) for c in COPIAS_INDETERMINADO) or set(clases) - set(
            COPIAS_PERDIDA + COPIAS_INDETERMINADO + ("completo",)):
        return "indeterminado"
    return "completo" if r["denominadores"].get("eventos", 0) > 0 else "sin_eventos"


def calidad_dns(r, registro_dc1) -> str:
    """completo | discrepancia | entrada_danada | indeterminado | falta_pcap_dc1 |
    sin_transacciones | sin_datos.

    El PCAP de DC1 es obligatorio cuando el registrador declara que lo escribe (registro 2.x,
    campo `pcap` en el arranque): sin él, la tercera fuente queda sin contrastar."""
    if not isinstance(r, dict) or "total" not in r:
        return "sin_datos"
    if "error" in r:
        return "entrada_danada"
    t = r["total"]
    if t.get("discrepancias"):
        return "discrepancia"
    if not t.get("transacciones"):
        return "sin_transacciones"
    clasif = r.get("sin_transaccion_clasificacion")
    no_explicados = (clasif or {}).get("no_explicados") if clasif else r.get("sin_transaccion", {}).get("total", 0)
    if (t.get("no_determinables") or t.get("indeterminado_dc1") or t.get("ambiguas")
            or t.get("comprobadas", 0) != t.get("transacciones") or no_explicados
            or (r.get("tramas_ilegibles") or {}).get("total")):
        return "indeterminado"
    declara_pcap = any(x.get("evento") == "arranque" and x.get("pcap") for x in (registro_dc1 or []))
    if declara_pcap and not (r.get("parametros") or {}).get("pcap_dc1"):
        return "falta_pcap_dc1"
    return "completo"
DICTAMEN = {"aprobada": "aprobado", "no_aprobada": "fallido", "indeterminada": "indeterminado"}
CODIGO = {"aprobada": 0, "no_aprobada": 1, "indeterminada": 2}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("ejecucion")
    p.add_argument("--pruebas", required=True, type=Path)
    p.add_argument("--ejecucion-dir", type=Path)
    p.add_argument("--captura-dir", type=Path)
    p.add_argument("--codigo-salida", action="store_true", help="sale con 0/1/2 según el dictamen")
    a = p.parse_args()
    resultado = evaluar(a.ejecucion, a.pruebas, a.ejecucion_dir, a.captura_dir)
    (a.pruebas / "resultado-global.json").write_text(
        json.dumps(resultado, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(resultado, ensure_ascii=False))
    # 0 aprobado, 1 fallido, 2 indeterminado: el mismo dictamen que queda escrito.
    return resultado["codigo_salida"] if a.codigo_salida else 0


if __name__ == "__main__":
    raise SystemExit(main())
