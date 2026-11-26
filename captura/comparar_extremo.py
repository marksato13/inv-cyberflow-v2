#!/usr/bin/env python3
"""Contraste por conexión y evento entre srv-dmz y Sensor1."""
from __future__ import annotations

import argparse
import collections
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lector_pcap import PcapDañado, tcp, tramas  # noqa: E402

CLASES = ("syn", "syn_ack", "fin", "rst", "ack_puro", "datos")
LIMITE = 20


@dataclass
class Evento:
    p: object
    copias: int = 1
    vlan: set = field(default_factory=set)

    @property
    def ts(self):
        return self.p.ts


def clase(p):
    if p.flags & 2:
        return "syn_ack" if p.flags & 16 else "syn"
    if p.flags & 4:
        return "rst"
    if p.flags & 1:
        return "fin"
    if p.carga:
        return "datos"
    return "ack_puro" if p.flags == 16 else "otro"


def detalle(e):
    p = e.p
    return {"ts": p.ts, "origen": p.origen, "destino": p.destino,
            "puerto_origen": p.puerto_origen, "puerto_destino": p.puerto_destino,
            "ipid": p.ipid, "longitud_ip": p.longitud_ip, "seq": p.seq,
            "ack": p.ack, "flags": p.flags, "carga": p.carga,
            "copias": e.copias, "vlan": sorted(v for v in e.vlan if v is not None)}


def lista(xs):
    return {"total": len(xs), "detalles": xs[:LIMITE]}


def cargar(rutas, servidor):
    paquetes, tiempos = [], []
    for ruta in rutas:
        for ts, trama, _ in tramas(ruta):
            tiempos.append(ts)
            p = tcp(ts, trama)
            if p and ((p.destino == servidor and p.puerto_destino in (80, 443)) or
                      (p.origen == servidor and p.puerto_origen in (80, 443))):
                paquetes.append(p)
    return paquetes, tiempos


def agrupar(paquetes, ventana):
    por_identidad = collections.defaultdict(list)
    eventos = []
    for p in sorted(paquetes, key=lambda x: x.ts):
        # una copia del espejo nunca se repite en la misma VLAN: si ya está, es otra transmisión
        previos = por_identidad[p.identidad]
        e = next((x for x in previos if p.ts - x.ts <= ventana and p.vlan not in x.vlan), None)
        if e is not None:
            e.copias += 1
            e.vlan.add(p.vlan)
        else:
            e = Evento(p, vlan={p.vlan})
            previos.append(e)
            eventos.append(e)
    return sorted(eventos, key=lambda x: x.ts)


def base_y_sentido(p, servidor):
    if p.destino == servidor:
        return (p.origen, p.puerto_origen, p.puerto_destino), "c2s"
    return (p.destino, p.puerto_destino, p.puerto_origen), "s2c"


def separar(eventos, servidor, inicio, fin, adelanto_syn=0.0):
    """adelanto_syn: el espejo puede entregar el SYN después del SYN-ACK (E2: 0,85 ms); el SYN se
    ordena como si llegara adelanto_syn s antes para que abra su conexión."""
    por_base = collections.defaultdict(list)
    for e in eventos:
        base, sentido = base_y_sentido(e.p, servidor)
        por_base[base].append((e, sentido))
    conexiones = collections.defaultdict(list)
    parciales, fuera = collections.defaultdict(list), []
    for base, filas in por_base.items():
        isn, syn_dentro = None, False
        for e, sentido in sorted(filas, key=lambda x: x[0].ts - (
                adelanto_syn if x[1] == "c2s" and clase(x[0].p) == "syn" else 0)):
            dentro = inicio <= e.ts <= fin
            if sentido == "c2s" and clase(e.p) == "syn":
                if isn != e.p.seq:
                    isn, syn_dentro = e.p.seq, dentro
                elif dentro:
                    syn_dentro = True
            if not dentro:
                fuera.append(detalle(e))
            elif isn is None or not syn_dentro:
                parciales[(*base, isn)].append(detalle(e))
            else:
                conexiones[(*base, isn)].append((e, sentido))
    parciales_lista = [{"cliente": k[0], "puerto_cliente": k[1],
                       "puerto_servidor": k[2], "isn_conocido": k[3],
                       "eventos": lista(v)} for k, v in parciales.items()]
    return conexiones, parciales_lista, fuera


def estimar(ext, sen):
    difs = []
    for clave in ext.keys() & sen.keys():
        a, b = collections.defaultdict(list), collections.defaultdict(list)
        for e, sentido in ext[clave]:
            a[(sentido, e.p.identidad)].append(e.ts)
        for e, sentido in sen[clave]:
            b[(sentido, e.p.identidad)].append(e.ts)
        for ident in a.keys() & b.keys():
            difs.extend(y - x for x, y in zip(sorted(a[ident]), sorted(b[ident])))
    return statistics.mean(difs) if difs else 0.0


def emparejar(ext, sen, desfase, margen):
    candidatos = collections.defaultdict(list)
    for i, (e, sentido) in enumerate(sen):
        candidatos[(sentido, e.p.identidad)].append(i)
    usados, pares, falta_ext = set(), [], []
    for e, sentido in sorted(ext, key=lambda x: x[0].ts):
        libres = [i for i in candidatos[(sentido, e.p.identidad)]
                  if i not in usados and abs(sen[i][0].ts - e.ts - desfase) <= margen]
        if not libres:
            falta_ext.append((e, sentido))
            continue
        i = min(libres, key=lambda j: abs(sen[j][0].ts - e.ts - desfase))
        usados.add(i)
        pares.append((e, sen[i][0], i))
    return pares, falta_ext, [fila for i, fila in enumerate(sen) if i not in usados]


def unir(rangos, base):
    intervalos = []
    for seq, n in rangos:
        a = (seq - base) % (1 << 32)
        if a < 1 << 31:
            intervalos.append((a, a + n))
    resultado = []
    for a, b in sorted(intervalos):
        if resultado and a <= resultado[-1][1]:
            resultado[-1][1] = max(resultado[-1][1], b)
        else:
            resultado.append([a, b])
    return resultado


def restar(a, b):
    faltan = []
    for inicio, fin in a:
        actual = inicio
        for x, y in b:
            if y <= actual:
                continue
            if x >= fin:
                break
            if x > actual:
                faltan.append([actual, x])
            actual = max(actual, y)
        if actual < fin:
            faltan.append([actual, fin])
    return faltan


def percentil(xs, q):
    if not xs:
        return None
    v = sorted(xs)
    pos = (len(v) - 1) * q
    i = int(pos)
    return v[i] + (v[min(i + 1, len(v) - 1)] - v[i]) * (pos - i)


def resumen_tiempo(pares, desfase):
    orden = sorted(pares, key=lambda x: x[0].ts)
    ds = [s.ts - e.ts for e, s, _ in orden]
    instantes_sensor = [s.ts for _, s, _ in orden]
    return {"pares": len(ds), "estimado_s": desfase,
            "medio_s": statistics.mean(ds) if ds else None,
            "p50_s": percentil(ds, .5), "p99_s": percentil(ds, .99),
            "max_abs_s": max((abs(x) for x in ds), default=None),
            "residual_p99_s": percentil([abs(x - desfase) for x in ds], .99),
            "deriva_s": ds[-1] - ds[0] if len(ds) > 1 else 0.0,
            "orden_conservado": instantes_sensor == sorted(instantes_sensor)}


def comparar(ext, sen, modo, desfase, margen):
    solo_ext = [list(k) for k in sorted(ext.keys() - sen.keys())]
    solo_sen = [list(k) for k in sorted(sen.keys() - ext.keys())]
    diferencias = len(solo_ext) + len(solo_sen)
    por_clase = {c: {"extremo": 0, "sensor": 0, "sin_sensor": [], "sin_extremo": []}
                 for c in CLASES}
    pares_todos, rangos = [], []
    transmisiones_verificadas = 0
    retrans = {"extremo": 0, "sensor": 0, "coinciden": True, "por_conexion": []}
    for claves, origen, ausente in ((ext.keys() - sen.keys(), ext, "sin_sensor"),
                                    (sen.keys() - ext.keys(), sen, "sin_extremo")):
        lado = "extremo" if ausente == "sin_sensor" else "sensor"
        for clave in claves:
            for ev, _ in origen[clave]:
                c = clase(ev.p)
                if c in por_clase:
                    por_clase[c][lado] += 1
                    por_clase[c][ausente].append(detalle(ev))
    for clave in sorted(ext.keys() & sen.keys()):
        for sentido in ("c2s", "s2c"):
            e = [(v, d) for v, d in ext[clave] if d == sentido]
            s = [(v, d) for v, d in sen[clave] if d == sentido]
            for c in CLASES:
                ee = [fila for fila in e if clase(fila[0].p) == c]
                ss = [fila for fila in s if clase(fila[0].p) == c]
                r = por_clase[c]
                r["extremo"] += len(ee)
                r["sensor"] += len(ss)
                if c == "datos" and modo == "rangos":
                    continue
                pares, fe, fs = emparejar(ee, ss, desfase, margen)
                pares_todos.extend(pares)
                r["sin_sensor"].extend(detalle(v) for v, _ in fe)
                r["sin_extremo"].extend(detalle(v) for v, _ in fs)
                diferencias += len(fe) + len(fs)
            ed = [v.p for v, _ in e if v.p.carga]
            sd = [v.p for v, _ in s if v.p.carga]
            if modo == "rangos":
                # Solo una transmisión sin repetición y con segmentación conservada
                # permite certificar una correspondencia individual.
                ce = collections.Counter((p.seq, p.carga) for p in ed)
                cs = collections.Counter((p.seq, p.carga) for p in sd)
                ee = [(v, d) for v, d in e if v.p.carga and ce[v.p.seq, v.p.carga] == 1]
                ss = [(v, d) for v, d in s if v.p.carga and cs[v.p.seq, v.p.carga] == 1]
                verificadas, _, _ = emparejar(ee, ss, desfase, margen)
                transmisiones_verificadas += len(verificadas)
            base = next((v.p.seq + 1 for v, _ in e if clase(v.p) in ("syn", "syn_ack")),
                        min((p.seq for p in ed), default=0)) % (1 << 32)
            re = unir([(p.seq, p.carga) for p in ed], base)
            rs = unir([(p.seq, p.carga) for p in sd], base)
            fe, fs = restar(re, rs), restar(rs, re)
            rangos.append({"conexion": list(clave), "sentido": sentido,
                           "bytes_extremo": sum(b - a for a, b in re),
                           "bytes_sensor": sum(b - a for a, b in rs),
                           "bytes_sin_sensor": sum(b - a for a, b in fe),
                           "bytes_sin_extremo": sum(b - a for a, b in fs),
                           "rangos_sin_sensor": lista(fe), "rangos_sin_extremo": lista(fs)})
            diferencias += bool(fe or fs)
            if modo == "paquetes":
                conteo = {"conexion": list(clave), "sentido": sentido,
                          "extremo": 0, "sensor": 0}
                for filas, lado in ((e, "extremo"), (s, "sensor")):
                    vistos = collections.Counter()
                    for v, _ in sorted(filas, key=lambda x: x[0].ts):
                        p = v.p
                        if p.carga:
                            conteo[lado] += vistos[p.seq] > 0
                            vistos[p.seq] += 1
                    retrans[lado] += conteo[lado]
                conteo["coinciden"] = conteo["extremo"] == conteo["sensor"]
                retrans["por_conexion"].append(conteo)
    if modo == "paquetes":
        retrans["coinciden"] = all(x["coinciden"] for x in retrans["por_conexion"])
        diferencias += sum(not x["coinciden"] for x in retrans["por_conexion"])
    retrans["por_conexion"] = lista(retrans["por_conexion"])
    for r in por_clase.values():
        r["sin_sensor"] = lista(r["sin_sensor"])
        r["sin_extremo"] = lista(r["sin_extremo"])
    tamaños = [s.p.longitud_ip - e.p.longitud_ip for e, s, _ in pares_todos]
    diferencias += sum(x != 0 for x in tamaños)
    return {"conexiones_solo_extremo": lista(solo_ext),
            "conexiones_solo_sensor": lista(solo_sen), "por_clase": por_clase,
            "rangos": lista(rangos),
            "transmisiones_verificadas_en_rangos": transmisiones_verificadas,
            "tamaños": {"pares": len(tamaños),
                                          "diferencias": sum(x != 0 for x in tamaños)},
            "desfases": resumen_tiempo(pares_todos, desfase),
            "retransmisiones": retrans, "discrepancias": diferencias}


def fuentes_sensor(ruta):
    if ruta.is_file():
        return [ruta]
    return sorted(p for p in ruta.iterdir() if p.is_file() and
                  (p.name.endswith(".pcap") or p.name.endswith(".pcap.gz")))


def ejecutar(a):
    ep, et = cargar([a.extremo], a.servidor)
    rutas = fuentes_sensor(a.sensor)
    sp, st = cargar(rutas, a.servidor)
    eventos = agrupar(sp, a.ventana_copia_s)
    offload = any(p.longitud_ip > 1500 for p in ep)
    modo = "rangos" if offload else "paquetes"
    inicio = max(min(et), min(st)) + a.margen_s if et and st else None
    fin = min(max(et), max(st)) - a.margen_s if et and st else None
    sin_periodo = inicio is None or inicio > fin
    if sin_periodo:
        inicio, fin = float("inf"), float("-inf")
    ext, pe, fe = separar([Evento(p) for p in ep], a.servidor, inicio, fin)
    sen, ps, fs = separar(eventos, a.servidor, inicio, fin, a.margen_par_s)
    desfase = estimar(ext, sen)
    r = comparar(ext, sen, modo, desfase, a.margen_par_s)
    if sin_periodo:
        r["discrepancias"] += 1
    comprobado = ["conexiones por tupla e ISN", "eventos de control uno a uno",
                  "cobertura de bytes por conexión y sentido"]
    no_comprobado = []
    if modo == "paquetes":
        comprobado += ["paquetes de datos uno a uno", "tamaños IP por paquete",
                       "desfases y orden relativos", "retransmisiones por transmisión"]
    else:
        no_comprobado += [
            {"aspecto": x, "motivo": "TSO/GSO/GRO altera la segmentación observada en el extremo"}
            for x in ("número de paquetes de datos", "tamaños de datos por paquete",
                      "transmisiones originales perdidas y luego retransmitidas",
                      "tiempos por paquete de datos")]
    no_comprobado.append({"aspecto": "tráfico fuera del periodo común y conexiones parciales",
                         "motivo": "observación incompleta en ambas capturas"})
    r.update({"version": 2, "parametros": {"servidor": a.servidor,
        "margen_s": a.margen_s, "ventana_copia_s": a.ventana_copia_s,
        "margen_par_s": a.margen_par_s},
        "captura_extremo": {"fichero": str(a.extremo), "paquetes": len(et),
            "primer_instante": min(et) if et else None,
            "ultimo_instante": max(et) if et else None,
            "offload_detectado": offload,
            "tamaño_maximo_ip": max((p.longitud_ip for p in ep), default=0)},
        "sensor": {"ficheros": [str(p) for p in rutas], "paquetes": len(st),
                   "eventos": len(eventos), "copias": sum(v.copias for v in eventos)},
        "periodo_comun": {"inicio": inicio if inicio != float("inf") else None,
                           "fin": fin if fin != float("-inf") else None},
        "modo": modo, "sin_periodo_comun": sin_periodo,
        "denominadores": {"conexiones_extremo": len(ext),
            "conexiones_sensor": len(sen), "eventos_extremo": sum(map(len, ext.values())),
            "eventos_sensor": sum(map(len, sen.values()))},
        "parciales_extremo": lista(pe), "parciales_sensor": lista(ps),
        "fuera_de_periodo_comun": {"extremo": lista(fe), "sensor": lista(fs)},
        "comprobado": comprobado, "no_comprobado": no_comprobado})
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--extremo", type=Path, required=True)
    ap.add_argument("--sensor", type=Path, required=True)
    ap.add_argument("--servidor", default="10.10.30.10")
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--margen-s", type=float, default=2.0)
    ap.add_argument("--ventana-copia-s", type=float, default=.02)
    ap.add_argument("--margen-par-s", type=float, default=.05)
    a = ap.parse_args(argv)
    if min(a.margen_s, a.ventana_copia_s, a.margen_par_s) < 0:
        ap.error("los márgenes deben ser no negativos")
    try:
        r = ejecutar(a)
    except (PcapDañado, OSError, ValueError) as exc:
        print(f"entrada dañada: {exc}", file=sys.stderr)
        return 3
    a.salida.write_text(json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"modo": r["modo"], "discrepancias": r["discrepancias"]}, ensure_ascii=False))
    return 1 if r["discrepancias"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
