#!/usr/bin/env python3
"""Copias del espejo por paquete y carga del destino SPAN en una captura V2.

    python3 copias_espejo.py <dir_pcap> --salida copias.json [--ips 10.10.20.21,...] [--desde E --hasta E]

Por qué: con la sesión SPAN actual (fuentes Gi1/0/23 y Gi2/0/23 en ambos sentidos) cada paquete
experimental que atraviesa el cortafuegos se ve en el espejo una vez por cada tramo de VLAN que
recorre (p. ej. VLAN 20 hacia el cortafuegos y VLAN 30 desde él). Si el destino SPAN descarta,
algún paquete llega con menos copias de las que tienen sus iguales. Esto es una evidencia directa,
en el propio sensor, de pérdida ANTES del sensor que afecta al tráfico experimental; no la detecta
el «100 % de bytes de aplicación» porque las copias se unen al deduplicar.

Qué mide (solo biblioteca estándar, en flujo, memoria proporcional al tráfico experimental):
- paquetes experimentales (IP origen o destino en --ips) agrupados por identidad
  (origen, destino, proto, puertos, ipid, seq, ack, flags, largo); para cada uno, las VLAN vistas;
- patrón esperado por par de VLAN (el patrón más frecuente de cada flujo dirigido);
- paquetes con menos copias que el patrón de su flujo, con su instante (copia faltante);
- carga total del destino por 1 s y por 10 ms (bytes de trama + 20 B de preámbulo/IFG por trama):
  un intervalo de 10 ms con ≥ 1 250 000 B equivale a ≥ 1 Gb/s ofrecido en el puerto destino;
- desglose de bytes por VLAN y experimental/no experimental.
Limitación: un paquete que pierde TODAS sus copias no aparece aquí; eso solo se ve contrastando con
los extremos (capturas en clientes/servidor) o por huecos TCP no retransmitidos.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import json
import socket
import struct
from pathlib import Path

LINEA_BPS = 1e9
EXTRA_TRAMA = 20  # preámbulo + SFD + IFG
EXPERIMENTALES = ("10.10.20.21,10.10.20.22,10.10.20.23,10.10.20.24,10.10.20.25,10.10.20.26,"
                  "10.10.30.10")


def tramas(ruta: Path):
    magic = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    with (gzip.open(ruta, "rb") if ruta.name.endswith(".gz") else ruta.open("rb")) as f:
        cab = f.read(24)
        if len(cab) < 24 or cab[:4] not in magic:
            return
        orden, escala = magic[cab[:4]]
        while True:
            c = f.read(16)
            if len(c) < 16:
                return
            s, sub, incl, orig = struct.unpack(orden + "IIII", c)
            d = f.read(incl)
            if len(d) < incl:
                return
            yield s + sub / escala, orig, d


def identidad(d: bytes):
    """(vlan, clave, origen, destino) de un IPv4 TCP/UDP/ICMP; None si no aplica."""
    if len(d) < 14:
        return None
    tipo, pos, vlan = struct.unpack_from("!H", d, 12)[0], 14, None
    while tipo in (0x8100, 0x88a8) and len(d) >= pos + 4:
        vlan = struct.unpack_from("!H", d, pos)[0] & 4095
        tipo = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    if tipo != 0x0800 or len(d) < pos + 20:
        return vlan, None, None, None
    ihl = (d[pos] & 15) * 4
    largo, ipid = struct.unpack_from("!HH", d, pos + 2)
    proto = d[pos + 9]
    o, de = socket.inet_ntoa(d[pos + 12:pos + 16]), socket.inet_ntoa(d[pos + 16:pos + 20])
    c = pos + ihl
    extra = ()
    if proto == 6 and len(d) >= c + 14:
        po, pd, seq, ack = struct.unpack_from("!HHII", d, c)
        extra = (po, pd, seq, ack, d[c + 13])
    elif proto == 17 and len(d) >= c + 8:
        extra = struct.unpack_from("!HH", d, c)
    elif proto == 1 and len(d) >= c + 8:
        extra = struct.unpack_from("!BBHH", d, c)
    return vlan, (o, de, proto, ipid, largo) + extra, o, de


def analizar(carpeta: Path, ips: set, desde=None, hasta=None) -> dict:
    ficheros = sorted(p for p in carpeta.iterdir() if p.name.startswith("live-") and ".pcap" in p.name)
    vistos = {}                                  # clave -> [ts_primero, [vlans]]
    por_s = collections.defaultdict(lambda: [0, 0, 0, 0])   # s -> [tramas, bytes, exp_tramas, exp_bytes]
    por_10ms = collections.Counter()
    por_vlan = collections.Counter()
    por_vlan_exp = collections.Counter()
    total = exp = 0
    for f in ficheros:
        for ts, orig, d in tramas(f):
            if (desde and ts < desde) or (hasta and ts > hasta):
                continue
            b = orig + EXTRA_TRAMA
            r = identidad(d)
            vlan = r[0] if r else None
            es_exp = bool(r and r[1] and (r[2] in ips or r[3] in ips))
            s = int(ts)
            a = por_s[s]
            a[0] += 1
            a[1] += b
            por_10ms[int(ts * 100)] += b
            por_vlan[str(vlan)] += b
            total += 1
            if es_exp:
                exp += 1
                a[2] += 1
                a[3] += b
                por_vlan_exp[str(vlan)] += b
                e = vistos.get(r[1])
                if e is None:
                    vistos[r[1]] = [ts, [vlan]]
                else:
                    e[1].append(vlan)
    # patrón esperado por flujo dirigido (origen, destino, proto, puertos)
    def flujo(k):
        return k[:3] + (k[5:7] if len(k) > 6 else ())
    patrones = collections.defaultdict(collections.Counter)
    for k, (ts, vl) in vistos.items():
        patrones[flujo(k)][tuple(sorted(vl, key=str))] += 1
    esperado = {fl: c.most_common(1)[0][0] for fl, c in patrones.items()}
    distribucion = collections.Counter()
    faltantes, sobrantes = [], 0
    for k, (ts, vl) in vistos.items():
        esp = esperado[flujo(k)]
        distribucion[len(vl)] += 1
        if len(vl) < len(esp):
            falta = sorted((collections.Counter(esp) - collections.Counter(vl)).elements(), key=str)
            faltantes.append({"ts": round(ts, 6), "flujo": "%s>%s/%s" % k[:3], "vlans_vistas": vl,
                              "vlans_faltan": falta, "largo_ip": k[4]})
        elif len(vl) > len(esp):
            sobrantes += 1
    faltantes.sort(key=lambda x: x["ts"])
    pico_s = max(por_s.items(), key=lambda kv: kv[1][1], default=(None, [0, 0, 0, 0]))
    pico_10 = max(por_10ms.items(), key=lambda kv: kv[1], default=(None, 0))
    umbral_10ms = LINEA_BPS / 8 / 100
    saturados = sorted(k / 100 for k, v in por_10ms.items() if v >= umbral_10ms)
    return {
        "carpeta": str(carpeta), "ficheros": len(ficheros), "desde": desde, "hasta": hasta,
        "tramas_total": total, "tramas_experimentales": exp,
        "paquetes_experimentales_distintos": len(vistos),
        "copias_por_paquete": dict(sorted(distribucion.items())),
        "patron_esperado_por_flujo": {"%s>%s/%s" % fl[:3] + ("" if len(fl) < 4 else ":%s>%s" % fl[3:5]): list(v)
                                      for fl, v in list(esperado.items())[:40]},
        "patrones_distintos": dict(collections.Counter(str(v) for v in esperado.values())),
        "paquetes_con_copia_faltante": len(faltantes),
        "copia_faltante_por_segundo": dict(sorted(collections.Counter(str(int(x["ts"])) for x in faltantes).items())),
        "copia_faltante_por_vlan": dict(collections.Counter(str(v) for x in faltantes for v in x["vlans_faltan"])),
        "paquetes_con_copias_de_mas": sobrantes,
        "faltantes": faltantes[:20000],
        "bytes_por_vlan": dict(por_vlan.most_common()),
        "bytes_por_vlan_experimental": dict(por_vlan_exp.most_common()),
        "pico_1s": {"s": pico_s[0], "tramas": pico_s[1][0], "bytes": pico_s[1][1],
                    "mbps": round(pico_s[1][1] * 8 / 1e6, 2)},
        "pico_10ms": {"t": (pico_10[0] / 100) if pico_10[0] else None, "bytes": pico_10[1],
                      "mbps_equivalentes": round(pico_10[1] * 8 * 100 / 1e6, 1)},
        "intervalos_10ms_a_linea": len(saturados), "intervalos_10ms_a_linea_primeros": saturados[:200],
        "por_segundo": {str(k): v for k, v in sorted(por_s.items())},
        "nota": "pérdida total de un paquete (todas sus copias) no es observable aquí",
    }


def detallar(carpeta: Path, ips: set, umbral_bytes_10ms: float, desde=None, hasta=None, maximo=60) -> list:
    """Segunda pasada: composición (VLAN, experimental o no, top de pares IP) de los intervalos de
    10 ms con carga ≥ umbral. Los pares IP ajenos al estudio se devuelven solo como recuento."""
    ficheros = sorted(p for p in carpeta.iterdir() if p.name.startswith("live-") and ".pcap" in p.name)
    carga = collections.Counter()
    for f in ficheros:
        for ts, orig, d in tramas(f):
            if (desde and ts < desde) or (hasta and ts > hasta):
                continue
            carga[int(ts * 100)] += orig + EXTRA_TRAMA
    elegidos = {k for k, v in carga.items() if v >= umbral_bytes_10ms}
    det = {k: {"vlan": collections.Counter(), "exp": collections.Counter(), "pares_exp": collections.Counter(),
               "pares_ajenos": set()} for k in elegidos}
    for f in ficheros:
        for ts, orig, d in tramas(f):
            k = int(ts * 100)
            if k not in det:
                continue
            r = identidad(d)
            b = orig + EXTRA_TRAMA
            x = det[k]
            x["vlan"][str(r[0] if r else None)] += b
            es_exp = bool(r and r[1] and (r[2] in ips or r[3] in ips))
            x["exp"]["experimental" if es_exp else "no_experimental"] += b
            if es_exp:
                x["pares_exp"]["%s>%s" % (r[2], r[3])] += b
            elif r and r[1]:
                x["pares_ajenos"].add((r[2], r[3]))
    salida = []
    for k in sorted(det, key=lambda k: -carga[k])[:maximo]:
        x = det[k]
        salida.append({"t": k / 100, "bytes": carga[k], "mbps_equivalentes": round(carga[k] * 8 * 100 / 1e6, 1),
                       "por_vlan": dict(x["vlan"].most_common()), "por_tipo": dict(x["exp"]),
                       "pares_experimentales": dict(x["pares_exp"].most_common(5)),
                       "pares_ajenos_distintos": len(x["pares_ajenos"])})
    return salida


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("carpeta", type=Path)
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--ips", default=EXPERIMENTALES)
    ap.add_argument("--desde", type=float)
    ap.add_argument("--hasta", type=float)
    ap.add_argument("--detalle-umbral", type=float, default=0.5,
                    help="fracción de línea en 10 ms a partir de la cual se detalla el intervalo (0 = no)")
    a = ap.parse_args()
    r = analizar(a.carpeta, set(a.ips.split(",")), a.desde, a.hasta)
    if a.detalle_umbral > 0:
        r["detalle_10ms"] = detallar(a.carpeta, set(a.ips.split(",")), a.detalle_umbral * LINEA_BPS / 8 / 100,
                                     a.desde, a.hasta)
        r["intervalos_10ms_sobre_umbral_detalle"] = len(r["detalle_10ms"])
    a.salida.write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    resumen = {k: r[k] for k in ("tramas_total", "tramas_experimentales", "paquetes_experimentales_distintos",
                                 "copias_por_paquete", "patrones_distintos", "paquetes_con_copia_faltante",
                                 "paquetes_con_copias_de_mas", "pico_1s", "pico_10ms", "intervalos_10ms_a_linea",
                                 "bytes_por_vlan")}
    print(json.dumps(resumen, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
