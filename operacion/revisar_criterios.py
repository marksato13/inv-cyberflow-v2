#!/usr/bin/env python3
"""Revisión con evidencia de los criterios que evaluar_piloto.py deja «para revisar» (C7, C9–C13).

    python3 revisar_criterios.py --pruebas pruebas/<ID> --capturas capturas/<ID> [--salida criterios-revisados.json]

evaluar_piloto.py los extrae en bruto con `ok: None, revisar: True`: NO es que no se puedan evaluar
en una ejecución corta, sino que estaban pendientes de revisión manual. Aquí se revisa cada uno con
las reglas de PROTOCOLO §10 y se separa, por criterio:

  comprobaciones                 lo que esta ejecución permite comprobar, con su valor y su fuente
  falta_evidencia                lo que debería estar registrado y no lo está (deja ok = None)
  requiere_duracion_prolongada   lo que solo una captura larga puede comprobar (rotación del EVE,
                                 deriva de relojes, volumen real de 49 h…): no cuenta en una corta
  pendiente_otra_comprobacion    defectos conocidos con su propio bloque (deduplicación, DC1)

ok = False si alguna comprobación falla; None si falta evidencia; True si todo lo aplicable cumple.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import suricata_stats  # noqa: E402

UMBRAL_BYTES = 0.95
DESFASE_MAX_S = 0.005


def cargar(p):
    p = Path(p)
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except ValueError:
        return None


def jsonl(p):
    p = Path(p)
    if not p.exists():
        return None
    salida = []
    for linea in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            salida.append(json.loads(linea))
        except ValueError:
            pass
    return salida


def texto(p):
    p = Path(p)
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else None


def criterio(comprobaciones, falta=(), prolongada=(), otra=()):
    oks = [c["ok"] for c in comprobaciones]
    ok = False if False in oks else None if (falta or None in oks or not oks) else True
    return {"ok": ok, "revision": "automatica (revisar_criterios.py)", "comprobaciones": comprobaciones,
            "falta_evidencia": list(falta), "requiere_duracion_prolongada": list(prolongada),
            "pendiente_otra_comprobacion": list(otra)}


def c(que, ok, valor=None, fuente=None):
    return {"que": que, "ok": ok, "valor": valor, "fuente": fuente}


# ---------------------------------------------------------------- C7 cobertura
def c7(P, txs):
    cob = cargar(P / "cobertura" / "cobertura.json")
    if not cob:
        return criterio([], falta=["cobertura/cobertura.json"])
    filas = {r["transaccion_id"]: r for r in cob.get("por_transaccion", [])}
    clase = {t["transaccion_id"]: t.get("clase") for t in txs}
    aplica = [r for i, r in filas.items() if clase.get(i) == "ok"]
    tcp = [r for r in aplica if r.get("protocolo") in ("http", "https", "tcp")]
    udp = [r for r in aplica if r.get("protocolo") == "dns"]
    sin = lambda campo, grupo: [r["transaccion_id"] for r in grupo if not r.get(campo)]
    comp = [
        c("transacciones del generador presentes en la cobertura", len(filas) == len(txs), [len(filas), len(txs)]),
        c("conexión vista (TCP con clase ok)", not sin("conexion", tcp), {"aplica": len(tcp), "sin": sin("conexion", tcp)[:10]}),
        c("petición vista (clase ok)", not sin("peticion", tcp + udp), {"aplica": len(tcp + udp), "sin": sin("peticion", tcp + udp)[:10]}),
        c("respuesta vista (clase ok)", not sin("respuesta", tcp + udp), {"aplica": len(tcp + udp), "sin": sin("respuesta", tcp + udp)[:10]}),
        c("0 no verificables", cob.get("total", {}).get("no_verificables") == 0, cob.get("total", {}).get("no_verificables")),
        c("cobertura versión 2 (reparto por conexión persistente)", cob.get("version") == 2, cob.get("version")),
    ]
    for nombre, grupo in [("total", {"total": cob.get("total", {})}), ("acción", cob.get("por_accion", {})),
                          ("perfil", cob.get("por_perfil", {}))]:
        for k, v in grupo.items():
            if v.get("fraccion") is not None:
                comp.append(c("bytes vistos / esperados >= %.2f en %s %s" % (UMBRAL_BYTES, nombre, k),
                              v["fraccion"] >= UMBRAL_BYTES, round(v["fraccion"], 6)))
    r = criterio(comp, prolongada=["cobertura a través de la rotación del EVE a las 00:00 UTC (bloque 4)"])
    # No decide C7 (el umbral es el agregado): las incompletas las excluye metadatos_v2 como E3.
    incompletas = [x["transaccion_id"] for x in aplica if x.get("transferencia") == "incompleta"]
    r["informativo"] = {"transferencias_incompletas": len(incompletas), "ejemplos": incompletas[:5]}
    return r


# ---------------------------------------------------------------- C9 pérdidas
def bloque(t, cabecera):
    if t is None:
        return None
    m = re.search(r"=== %s\n(.*?)(?:\n=== |\Z)" % re.escape(cabecera), t, re.S)
    return m.group(1) if m else None


def drops(t, interfaz):
    b = bloque(t, "switch " + interfaz)
    m = re.search(r"Total output drops: (\d+)", b or "")
    return int(m.group(1)) if m else None


def valor(t, nombre):
    m = re.search(r"^%s (\d+)" % re.escape(nombre), bloque(t, "sensor1") or "", re.M)
    return int(m.group(1)) if m else None


def tcpdump_kernel(t):
    v = re.findall(r"(\d+) packets dropped by kernel", bloque(t, "sensor1") or "")
    return int(v[-1]) if v else None


def perdida(que, a, b, c7_ok, fuente):
    """PROTOCOLO §10 (C9): Δ = 0 se acepta; si no, se cuantifica y decide la cobertura (C7). La
    política de calidad del espejo (estado_global «espejo») sigue aparte y no se relaja aquí."""
    if None in (a, b):
        return c(que, None, None, fuente)
    d = b - a
    x = c(que, True if d == 0 else c7_ok, [a, b, d], fuente)
    if d:
        x["nota"] = "Δ %d cuantificado; decide C7 (%s)" % (d, c7_ok)
    return x


def periodo_captura(CAP):
    """[inicio, fin] del archivador (capturas/<ID>/manifiesto.json): el intervalo que C9 certifica."""
    m = cargar(Path(CAP) / "manifiesto.json") or {}
    try:
        return suricata_stats.epoch(m["inicio"]), suricata_stats.epoch(m["fin"])
    except (KeyError, TypeError, ValueError):
        return None, None


def suricata(CAP, c7_ok=None, P=None):
    """capture.kernel_drops de Suricata en el periodo de captura, desde los eventos stats de:
      - capturas/<ID>/eve/*.json: el recorte del archivador (muestras interiores);
      - capturas/<ID>/eve/suricata-stats-*.jsonl: los mismos stats publicados aparte (el EVE
        publicado va filtrado y no los lleva);
      - pruebas/<ID>/registros/suricata-stats-ventana*.jsonl: la EVE dedicada COMPLETA en
        [inicio − 30 s, fin + 30 s], que aporta las muestras que ACOTAN el periodo (cerrar_v2.sh).
    Un evento repetido se cuenta una vez.

    Conciliación (revisión 6, PROTOCOLO §10): un Δ > 0 es pérdida en el procesamiento de Suricata y
    es FALLO; C7 NO lo decide. C7 (cobertura) se mide en el PCAP del anillo (tcpdump), con bytes ≥ 95 %,
    y no dice nada de los paquetes que Suricata dejó de procesar, que son los que forman el EVE que usa
    el extractor (C11). Es lo mismo que hace el vigía: un aumento invalida la supervisión
    (perdida_en_sensor) y el dictamen sale no_aprobada. c7_ok se conserva solo como información."""
    rutas = sorted(glob.glob(str(Path(CAP) / "eve" / "*.json"))) + \
        sorted(glob.glob(str(Path(CAP) / "eve" / "suricata-stats-*.jsonl")))
    if P is not None:
        rutas += sorted(glob.glob(str(Path(P) / "registros" / "suricata-stats-ventana*.jsonl")))
    vistos, ev = set(), []
    for e in suricata_stats.eventos_stats(rutas):
        k = (e.get("timestamp"), (e.get("stats") or {}).get("uptime"))
        if k not in vistos:
            vistos.add(k)
            ev.append(e)
    desde, hasta = periodo_captura(CAP)
    r = suricata_stats.evaluar(ev, desde, hasta)
    que = "Suricata capture.kernel_drops (eventos stats de la EVE dedicada)"
    fuente = "capturas/<ID>/eve (stats), registros/suricata-stats-ventana, manifiesto.json"
    if r["estado"] == "presente":
        return c(que, True, r, fuente)
    if r["estado"] == "perdida":
        x = c(que, False, r, fuente)
        x["nota"] = ("Δ %d descartes de Suricata atribuibles al periodo: fallo (no lo decide C7, que mide el "
                     "PCAP; C7 = %s)%s" % (r["delta_kernel_drops"], c7_ok,
                                           ("; además falta: " + ", ".join(r["falta_evidencia"])) if r.get("falta_evidencia") else ""))
        return x
    if r["estado"] == "reinicio":
        x = c(que, False, r, fuente)
        x["nota"] = "Suricata se reinició durante la captura: pérdida no cuantificable"
        return x
    x = c(que, None, r, fuente)       # pérdida no localizada, ausente, sin eventos o insuficiente
    if r["estado"] == "perdida_no_localizada":
        x["nota"] = ("%d descartes en intervalos que cruzan un borde del periodo: no se puede atribuir al "
                     "periodo ni descartar; falta evidencia" % r["delta_kernel_drops_ampliado"])
    else:
        x["nota"] = "contador %s%s: falta evidencia" % (r["estado"], (" (%s)" % r["motivo"]) if r.get("motivo") else "")
    return x

def c9(P, E, c7_ok=None, CAP=None):
    ini, fin = texto(E / "contadores-lab-inicio.txt"), texto(E / "contadores-lab-fin.txt")
    if ini is None or fin is None:
        return criterio([], falta=["registros/contadores-lab-inicio.txt / -fin.txt"])
    comp = []
    son = cargar(E / "calidad-espejo-sondeo.json") or {}
    seg = son.get("segundos_por_clase") or {}
    sondeo_limpio = bool(seg) and seg.get("indeterminado", 0) == 0 and seg.get("con_descartes", 0) == 0
    for i in ("GigabitEthernet2/0/19", "GigabitEthernet1/0/23", "GigabitEthernet2/0/23"):
        x = perdida("Δ output drops %s" % i, drops(ini, i), drops(fin, i), c7_ok, "contadores-lab-*")
        if i == "GigabitEthernet2/0/19" and x["valor"] and x["valor"][2] and sondeo_limpio:
            # contadores-lab-* abarcan más que la captura (lanzamiento y copias del cierre); el
            # sondeo del destino cada 2 s cubre TODA la captura y vio 0: el Δ cae fuera de ella.
            x["ok"] = True
            x["nota"] = ("Δ %d fuera del intervalo de captura: el sondeo cubre toda la captura sin "
                         "descartes (informativo)" % x["valor"][2])
        comp.append(x)
    for n in ("ens37_rx_missed_errors", "ens37_rx_errors", "softnet_dropped"):
        comp.append(perdida("Δ %s" % n, valor(ini, n), valor(fin, n), c7_ok, "contadores-lab-*"))
    a, b = tcpdump_kernel(ini), tcpdump_kernel(fin)
    comp.append(perdida("tcpdump del anillo: descartados por el núcleo", a, b, c7_ok,
                        "journal de tcpdump en contadores-lab-*"))
    if not seg or seg.get("indeterminado", 0) > 0:
        ok = None                       # segundos sin sondeo: falta evidencia, no es un fallo
    else:
        ok = True if seg.get("con_descartes", 0) == 0 else c7_ok
    comp.append(c("sondeo del destino del SPAN durante toda la captura", ok, seg or None, "calidad-espejo-sondeo.json"))
    ext = cargar(E / "extremo-captura.json") or {}
    comp.append(perdida("tcpdump de srv-dmz: descartados por el núcleo", 0, ext.get("descartados_nucleo"),
                        c7_ok, "extremo-captura.json"))
    comp.append(suricata(CAP if CAP is not None else Path(P).parent.parent / "capturas" / Path(P).name, c7_ok, P))
    return criterio(comp, prolongada=["contadores a lo largo de 49 h (supervisión prolongada, bloque 4)"])


# ---------------------------------------------------------------- C10 relojes
def ntp_txt(t):
    if t is None:
        return None
    m = re.search(r"NTPSynchronized=(\w+)", t)
    return (m.group(1) == "yes") if m else None


def c10(P, E, G):
    comp, falta = [], []
    pre = {x.get("comprobacion"): x.get("resultado") for x in (jsonl(E / "preflight-lab.jsonl") or [])}
    for h in ("sensor1", "clientes", "srvdmz", "dc1"):
        v = pre.get("ntp_" + h)
        comp.append(c("NTP sincronizado al inicio en %s" % h, None if v is None else v == "ok", v, "preflight-lab.jsonl"))
    fin = {"srvdmz": ntp_txt(texto(E / "relojes-fin-srvdmz.txt")),
           "dc1": ntp_txt(texto(E / "relojes-fin-10.10.10.20.txt")),
           "sensor1": ntp_txt(texto(E / "relojes-fin-sensor1.txt"))}
    man = cargar(G / "manifiesto-fin.json") or {}
    v = (man.get("entorno_fin") or {}).get("ntp_sincronizado")
    fin["clientes"] = None if v is None else v == "yes"
    for h, v in fin.items():
        if v is None:
            falta.append("NTP al final en %s (no registrado)" % h)
        else:
            comp.append(c("NTP sincronizado al final en %s" % h, v, v, "relojes-fin / manifiesto-fin"))
    cob = cargar(P / "cobertura" / "cobertura.json") or {}
    d = [abs(r["desfase_aparente_s"]) for r in cob.get("por_transaccion", []) if r.get("desfase_aparente_s") is not None]
    if d:
        med = statistics.median(d)
        comp.append(c("|desfase aparente| mediano <= 5 ms", med <= DESFASE_MAX_S, round(med, 6), "cobertura.json"))
    else:
        falta.append("desfase aparente (cobertura)")
    return criterio(comp, falta, prolongada=["deriva de los relojes a lo largo de 49 h (bloque 4)"],
                    otra=["DC1 unos 6,5–7 ms por detrás (bloque 4)"])


# ---------------------------------------------------------------- C11 extracción
def c11(P, E):
    pasos = {x.get("paso"): x.get("rc") for x in (jsonl(E / "pasos-analisis.jsonl") or [])}
    ver = cargar(P / "extraccion" / "verificacion.json")
    res = cargar(P / "extraccion" / "resumen.json")
    inv = cargar(P / "extraccion" / "inventario_ips.json")
    falta = [f for f, x in (("pasos-analisis.jsonl", pasos), ("extraccion/verificacion.json", ver),
                            ("extraccion/resumen.json", res), ("extraccion/inventario_ips.json", inv)) if not x]
    comp = []
    for p in ("extraer", "verificar"):
        if pasos:
            comp.append(c("%s rc 0" % p, pasos.get(p) == 0, pasos.get(p), "pasos-analisis.jsonl"))
    if ver:
        comp += [c("verificación 40/40 filas", ver.get("filas_verificadas") == 40, ver.get("filas_verificadas")),
                 c("verificación sin diferencias", ver.get("diferencias") == [], len(ver.get("diferencias") or [])),
                 c("historia del motor 230 s, sin futuro", ver.get("sin_futuro_ok") is True, ver.get("referencia")),
                 c("paridad con el motor", ver.get("paridad_motor_ok") is True, ver.get("paridad_motor_ok")),
                 c("constantes justificadas", all(k.get("causa_probable") for k in ver.get("constantes") or []),
                   [k.get("columna") for k in ver.get("constantes") or []])]
    if res:
        comp += [c("tardías EVE descartadas = 0", (res.get("orden_eve") or {}).get("tardios_descartados") == 0,
                   (res.get("orden_eve") or {}).get("tardios_descartados")),
                 c("tardías PCAP descartadas = 0", (res.get("orden_pcap") or {}).get("tardias_descartadas") == 0,
                   (res.get("orden_pcap") or {}).get("tardias_descartadas"))]
    if inv:
        sin_regla = [x.get("ip") for x in inv if not x.get("regla")]
        comp.append(c("inventario: todas las IP con regla", not sin_regla, {"ip": len(inv), "sin_regla": len(sin_regla)}))
    # Deduplicación (Bloque 3): con deduplicar_v2 el extractor ya no funde transmisiones ni deja copias
    # a > 5 ms; queda pendiente que el motor de producción use la misma función (paridad
    # entrenamiento/operación), lo que se exige al piloto final. Sin el dato (extracción anterior a
    # deduplicar_v2), el defecto de V1 sigue pendiente.
    d = (ver or {}).get("deduplicacion")
    if not d:
        otra = ["deduplicación del extractor: RST idénticos y copias a >5 ms (bloque 3)"]
    elif d.get("motor_misma_funcion") is True:
        otra = []
    else:
        otra = ["paridad de la deduplicación: el motor de referencia usa %s; adoptar deduplicar_v2 en el "
                "motor del producto antes de operar el modelo V2" % d.get("motor_referencia")]
    return criterio(comp, falta, prolongada=["orden del EVE a través de su rotación a las 00:00 UTC (bloque 4)"],
                    otra=otra)


# ---------------------------------------------------------------- C12 volumen
def c12(P, E, CAP):
    vol = jsonl(CAP / "volumen.jsonl")
    man = cargar(CAP / "manifiesto.json") or {}
    lz = cargar(E / "lanzamiento.json") or {}
    if not vol or not man:
        return criterio([], falta=["capturas/volumen.jsonl y manifiesto.json"])
    pp, up = man.get("primer_paquete_epoch"), man.get("ultimo_paquete_epoch")
    dur = (up - pp) if pp and up else None
    gen = lz.get("real") or {}
    fases = {}
    for nombre, (a, b) in {"previa": (pp, gen.get("generador_inicio_epoch")),
                           "generacion": (gen.get("generador_inicio_epoch"), gen.get("generador_fin_epoch")),
                           "margen_final": (gen.get("generador_fin_epoch"), up)}.items():
        if a is None or b is None:
            continue
        filas = [x for x in vol if a <= x["minuto_epoch"] + 60 and x["minuto_epoch"] < b]
        fases[nombre] = {"minutos": len(filas), "pcap_mb": round(sum(x["pcap_bytes"] for x in filas) / 1e6, 3),
                         "eve_mb": round(sum(x["eve_bytes"] for x in filas) / 1e6, 3)}
    comp = [c("volumen por minuto durante toda la captura", dur is not None and len(vol) >= int(dur // 60),
              {"minutos": len(vol), "captura_s": round(dur, 1) if dur else None}, "volumen.jsonl"),
            c("volumen medido por fase", {"previa", "generacion", "margen_final"} <= set(fases), fases)]
    if dur:
        gbh = (man.get("pcap_bytes", 0) + man.get("eve_bytes", 0)) / 1e9 / (dur / 3600)
        comp.append(c("GB/h de PCAP comprimido + EVE de esta ejecución", True, round(gbh, 4), "manifiesto.json"))
    return criterio(comp, prolongada=["volumen real de 49 h frente a la proyección (otro programa y carga nocturna)"])


# ---------------------------------------------------------------- C13 aislamiento V1
def c13(P, E):
    pre = {x.get("comprobacion"): x for x in (jsonl(E / "preflight-lab.jsonl") or [])}
    fin = texto(E / "contadores-lab-fin.txt")
    ex = cargar(E / "exclusion-v1.json") or {}
    comp, falta = [], []
    for k in ("exclusion_v1", "srvdmz_sets_vacios", "agente_v1_sombra", "dc1_sin_restricciones"):
        x = pre.get(k)
        if x is None:
            falta.append("preflight %s" % k)
        else:
            comp.append(c("al inicio: %s" % k, x.get("resultado") == "ok", x.get("detalle"), "preflight-lab.jsonl"))
    b = bloque(fin, "aislamiento_v1") if fin else None
    if b is None:
        falta.append("aislamiento al final (contadores-lab-fin.txt)")
    else:
        for n in ("srvdmz_limitados", "srvdmz_bloqueados", "agente_aplicar", "dc1_nft_lineas"):
            m = re.search(r"^%s (\d+)" % n, b, re.M)
            comp.append(c("al final: %s = 0" % n, None if not m else int(m.group(1)) == 0, m and int(m.group(1))))
    comp.append(c("la regla *@ cubre la ejecución real", ex.get("cubierto") is True, ex.get("regla"), "exclusion-v1.json"))
    return criterio(comp, falta, prolongada=["aislamiento mantenido durante 49 h (supervisión prolongada)"])


def revisar(P, CAP):
    P, CAP = Path(P), Path(CAP)
    ID = P.name
    E, G = P / "registros", P / "generador" / ID
    txs = [t for f in sorted(glob.glob(str(G / "transacciones-*.jsonl"))) for t in (jsonl(f) or [])]
    r7 = c7(P, txs)
    R = {"C7": r7, "C9": c9(P, E, r7["ok"], CAP),"C10": c10(P, E, G), "C11": c11(P, E), "C12": c12(P, E, CAP), "C13": c13(P, E)}
    return {"version": 1, "ejecucion": ID,
            "generado_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "nota": ("evaluar_piloto.py deja estos criterios en revisión manual (ok None); aquí se revisan "
                     "con evidencia. «requiere_duracion_prolongada» no cuenta en una verificación corta "
                     "y se conserva aparte; «falta_evidencia» deja ok = None."),
            "criterios": R}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pruebas", required=True)
    ap.add_argument("--capturas", required=True)
    ap.add_argument("--salida")
    a = ap.parse_args(argv)
    r = revisar(a.pruebas, a.capturas)
    salida = Path(a.salida) if a.salida else Path(a.pruebas) / "criterios-revisados.json"
    salida.write_text(json.dumps(r, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v["ok"] for k, v in r["criterios"].items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
