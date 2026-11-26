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


# Qué exige el dictamen a cada tipo de ejecución, además de lo común (generador, archivador, vigía,
# supervisión, exclusión V1, espejo, calidad_*, referencias, transferencias, análisis y criterios):
#  - prolongadas: comprobaciones que solo una captura larga puede hacer (rotación, deriva, 49 h…);
#  - otra_comprobacion: lo que depende de otro bloque aún abierto (deduplicación, relojes de DC1,
#    kernel_drops de Suricata). Pendiente => indeterminada, nunca aprobada.
REQUISITOS = {
    "verificacion_dirigida": {"prolongadas": False, "otra_comprobacion": False},
    "piloto_final": {"prolongadas": False, "otra_comprobacion": True},
    "captura_definitiva": {"prolongadas": True, "otra_comprobacion": True},
}


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
    # Referencia independiente del extremo (srv-dmz) y sondas del preflight: obligatorias desde la
    # revisión del 26-nov. Sin ellas la ejecución no puede aprobarse (indeterminada).
    estados["calidad_extremo"] = calidad_extremo(
        leer(pruebas / "calidad-extremo.json"), leer(e / "extremo-captura.json"),
        (e / ("extremo-%s.pcap.danado" % identificador)).exists())
    estados["calidad_sonda"] = calidad_sonda(leer(pruebas / "calidad-sonda.json"))
    # Desde la 3.ª revisión (27-nov) el lanzador declara la vigilancia de las referencias y la
    # coordinación de copias; si las declara, su evidencia es obligatoria. Las ejecuciones
    # anteriores no las tienen y se evalúan como antes (no se les inventa un requisito).
    lz = leer(e / "lanzamiento.json") or {}
    if "vigilancia_referencias" in lz:
        ref = leer(e / "calidad-referencias.json")
        estados["referencias"] = ("sin_datos" if not isinstance(ref, dict) else
                                  "completo" if ref.get("estado") == "completo" else
                                  "referencia_incompleta" if ref.get("estado") == "incompleta" else "sin_datos")
    if "coordinacion_transferencias" in lz:
        tr = leer(e / "transferencias.json")
        estados["transferencias"] = ("sin_datos" if not isinstance(tr, dict) or not tr.get("registro_existe") else
                                     tr.get("estado") if tr.get("estado") in ("sin_copias", "copias_durante_captura")
                                     else "sin_datos")
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
    # C7 y C9–C13 los deja evaluar_piloto en revisión manual (ok None); revisar_criterios.py los
    # revisa con evidencia. Lo que requiere duración prolongada se conserva APARTE: en una
    # verificación corta no cuenta; en una ejecución de >= 24 h sigue pendiente (falta).
    revisados = (leer(pruebas / "criterios-revisados.json") or {}).get("criterios") or {}
    prolongada, otra = {}, {}
    if criterios:
        criterios = dict(criterios)
        for k, v in revisados.items():
            if isinstance(criterios.get(k), dict) and criterios[k].get("ok") is None and isinstance(v, dict):
                criterios[k] = dict(criterios[k], ok=v.get("ok"), revisado=True)
            if v.get("requiere_duracion_prolongada"):
                prolongada[k] = v["requiere_duracion_prolongada"]
            if v.get("pendiente_otra_comprobacion"):
                otra[k] = v["pendiente_otra_comprobacion"]
    # Requisitos por TIPO de ejecución (Bloque 1, r4; docs/BLOQUE1-REVISION-4 §6). Lanzamientos
    # anteriores a r4 no declaran tipo: se infiere de la duración y se dice que es inferido.
    tipo, tipo_inferido = lz.get("tipo_ejecucion"), False
    if tipo is None:
        tipo, tipo_inferido = ("captura_definitiva" if (lz.get("duracion_s") or 0) >= 86400
                               else "verificacion_dirigida"), True
    req = REQUISITOS.get(tipo)
    larga = bool(req and req["prolongadas"]) or (lz.get("duracion_s") or 0) >= 86400 or req is None
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
        "calidad_extremo": ("perdida", "entrada_danada"),
        # La sonda dentro del periodo útil es un incidente comprobado: con el margen planificado
        # (v2ctl.MARGEN_SONDA_S) no debe ocurrir; si ocurre, la ejecución no se aprueba.
        "calidad_sonda": ("contaminacion",),
        # Una copia de gestión dentro del intervalo de captura incumple la coordinación (VD3).
        "transferencias": ("copias_durante_captura",),
    }
    for nombre, valores in fallos.items():
        if estados.get(nombre) in valores:
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
                  "sin_eventos", "falta_pcap_dc1", "sin_transacciones", "referencia_incompleta")]
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
    if req is None:
        faltantes.append("tipo_ejecucion")           # tipo desconocido: se exige todo y no se aprueba
    if larga:
        faltantes += ["prolongada:%s" % k for k in sorted(prolongada)]
    if req is None or req["otra_comprobacion"]:
        faltantes += ["otra:%s" % k for k in sorted(otra)]
    motivos.extend("falta:%s" % k for k in faltantes)
    global_estado = "no_aprobada" if any(not m.startswith("falta:") for m in motivos) else (
        "indeterminada" if any(m.startswith("falta:") for m in motivos) else "aprobada")
    return {"ejecucion": identificador, **estados, "global": global_estado,
            "dictamen": DICTAMEN[global_estado], "codigo_salida": CODIGO[global_estado],
            "alcance": ("ejecucion_prolongada" if larga else
                        "piloto_final: requisitos de una ejecución corta y las comprobaciones de otros "
                        "bloques; las de duración prolongada siguen pendientes aparte" if req["otra_comprobacion"] else
                        "verificacion_corta: aprobada se refiere SOLO a los requisitos aplicables; "
                        "las comprobaciones de duración prolongada siguen pendientes aparte"),
            "tipo_ejecucion": tipo, "tipo_inferido_por_duracion": tipo_inferido,
            "requisitos": req or "tipo desconocido: se exigen todos",
            "motivos": motivos, "pasos": rcs, "fuente_pasos": fuente_pasos,
            "criterios_revisados": bool(revisados),
            "pendientes_duracion_prolongada": prolongada,
            "pendientes_otra_comprobacion": otra,
            "exclusiones": exclusiones(pruebas, invalidaciones)}


# Reglas de exclusión de metadatos_v2.py. Las guardas planificadas se fijan antes de capturar y no
# dependen de lo que pase; las exclusiones por incidente responden a algo observado. Se informan por
# separado y NINGUNA convierte una pérdida experimental o una evidencia ausente en aprobada.
GUARDAS_PLANIFICADAS = ("E1", "E5")
EXCLUSIONES_INCIDENTE = ("E2", "E3", "E4")


def exclusiones(pruebas: Path, invalidaciones) -> dict:
    traz = leer(pruebas / "extraccion" / "trazabilidad.json") or {}
    por_regla = traz.get("exclusion_por_regla") or {}
    plan = {k: v for k, v in por_regla.items() if k.split(":")[0] in GUARDAS_PLANIFICADAS}
    inc = {k: v for k, v in por_regla.items() if k.split(":")[0] in EXCLUSIONES_INCIDENTE}
    otras = {k: v for k, v in por_regla.items() if k not in plan and k not in inc}
    return {"ventanas": traz.get("ventanas"), "excluidas": traz.get("excluidas"),
            "guardas_planificadas": plan, "por_incidente": inc, "otras_reglas": otras,
            "invalidaciones_supervision": len(invalidaciones or [])}


def calidad_extremo(r, captura, copia_danada=False) -> str:
    """completo | perdida | entrada_danada | indeterminado | sin_datos.

    `captura` es extremo-captura.json (cerrar_v2: estadísticas de tcpdump en srv-dmz y sha256).
    Pérdida = algo que el extremo vio y Sensor1 no (conexiones o eventos sin_sensor). Lo que la
    referencia no vio, descartes del núcleo en el extremo o falta de periodo común no deciden."""
    if copia_danada:
        return "entrada_danada"
    if not isinstance(captura, dict) or captura.get("estado") == "sin_captura":
        return "sin_datos"
    if not isinstance(r, dict) or "por_clase" not in r:
        return "sin_datos"
    if captura.get("estado") != "ok" or captura.get("descartados_nucleo") != 0:
        return "indeterminado"
    if r.get("sin_periodo_comun"):
        return "indeterminado"
    total = lambda x: (x or {}).get("total", 0) if isinstance(x, dict) else len(x or [])
    sin_sensor = sum(total(c.get("sin_sensor")) for c in r["por_clase"].values())
    if total(r.get("conexiones_solo_extremo")) or sin_sensor:
        return "perdida"
    sin_extremo = sum(total(c.get("sin_extremo")) for c in r["por_clase"].values())
    if (total(r.get("conexiones_solo_sensor")) or sin_extremo or r.get("discrepancias")
            or (r.get("retransmisiones") or {}).get("coinciden") is False):
        return "indeterminado"
    return "completo"


def calidad_sonda(r) -> str:
    """completo | contaminacion | indeterminado | sin_datos (ventanas_sonda.py v2 o v3; la v3 solo
    cambia el recuento a ventanas distintas, el estado se decide igual)."""
    if not isinstance(r, dict) or r.get("version") not in (2, 3):
        return "sin_datos"
    if r.get("estado") == "contaminacion_en_periodo_util":
        return "contaminacion"
    if r.get("estado") == "sin_registro":
        return "sin_datos"
    if r.get("estado") != "sin_contaminacion":
        return "indeterminado"
    # Un registro reconstruido (ejecuciones antiguas) no acredita el instante exacto de la sonda.
    return "completo" if r.get("fuentes_registro") == ["v2ctl"] else "indeterminado"


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
    # Solo vale la clasificación por registro de sondas (con «relaciones»). La de la primera revisión
    # (id + prefijo) ya no explica nada: todos sus eventos sueltos cuentan como no explicados.
    if clasif and "relaciones" in clasif:
        no_explicados = clasif.get("no_explicados")
        reconstruidas = (clasif.get("por_fuente_registro") or {}).get("reconstruido", 0)
    else:
        no_explicados = r.get("sin_transaccion", {}).get("total", 0)
        reconstruidas = 0
    if (t.get("no_determinables") or t.get("indeterminado_dc1") or t.get("ambiguas")
            or t.get("comprobadas", 0) != t.get("transacciones") or no_explicados or reconstruidas
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
