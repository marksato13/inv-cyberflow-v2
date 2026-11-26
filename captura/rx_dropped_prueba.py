#!/usr/bin/env python3
"""Prueba dirigida: ¿qué tramas cuenta el núcleo como rx_dropped en la interfaz del espejo?

    python3 rx_dropped_prueba.py --interfaz ens37 --segundos 120 --pcap-dir /var/lib/ppi-motor-capture --salida r.json

1. Lee cada segundo /sys/class/net/<if>/statistics/{rx_packets,rx_dropped,rx_nohandler} con su instante.
2. Al terminar, lee los PCAP del anillo de captura (tcpdump en la misma interfaz) que cubren el
   periodo y clasifica cada trama por tipo (etiqueta VLAN y ethertype interior, o trama 802.3/LLC).
3. Compara, en el periodo completo y por segundo, el incremento de rx_dropped con el recuento de
   cada clase de trama. Si una clase coincide trama a trama con rx_dropped, ese es el origen del
   contador; la prueba lo dice con los números, no por semejanza de porcentajes.

Solo lectura: no cambia la interfaz ni la captura. Necesita leer los PCAP del anillo (grupo m4rk).
Contexto (núcleo Linux, net/core/dev.c, __netif_receive_skb_core): una trama que ningún
manejador de protocolo acepta se cuenta en rx_dropped (o en rx_nohandler en algunos casos) aunque
los sockets de captura (tcpdump, ptype ALL) ya la hayan recibido; los manejadores registrados en
esta máquina se listan en /proc/net/ptype (se copian a la salida).
"""
from __future__ import annotations

import argparse
import collections
import glob
import gzip
import json
import os
import struct
import time


def leer_contadores(interfaz):
    base = "/sys/class/net/%s/statistics/" % interfaz
    r = {}
    for k in ("rx_packets", "rx_dropped", "rx_nohandler", "rx_missed_errors", "rx_fifo_errors"):
        try:
            r[k] = int(open(base + k).read())
        except OSError:
            r[k] = None
    return r


def tramas(ruta):
    abrir = gzip.open if ruta.endswith(".gz") else open
    with abrir(ruta, "rb") as f:
        cab = f.read(24)
        if len(cab) < 24:
            raise ValueError("cabecera corta: %s" % ruta)
        magia = struct.unpack("<I", cab[:4])[0]
        if magia == 0xA1B2C3D4:
            div, end = 1e6, "<"
        elif magia == 0xA1B23C4D:
            div, end = 1e9, "<"
        elif magia == 0xD4C3B2A1:
            div, end = 1e6, ">"
        elif magia == 0x4D3CB2A1:
            div, end = 1e9, ">"
        else:
            raise ValueError("magia desconocida %x: %s" % (magia, ruta))
        while True:
            h = f.read(16)
            if not h:
                return
            if len(h) < 16:
                yield None, "truncado", b""
                return
            s, fr, incl, _orig = struct.unpack(end + "IIII", h)
            d = f.read(incl)
            if len(d) < incl:
                yield None, "truncado", b""
                return
            yield s + fr / div, "ok", d


def clase(d: bytes) -> str:
    if len(d) < 14:
        return "corta"
    et, pos, vlans = struct.unpack_from("!H", d, 12)[0], 14, []
    while et in (0x8100, 0x88A8) and len(d) >= pos + 4:
        vlans.append(struct.unpack_from("!H", d, pos)[0] & 0x0FFF)
        et = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    etiqueta = "vlan" if vlans else "sin_vlan"
    if et < 0x0600:
        tipo = "802.3_llc"
        if len(d) >= pos + 3:
            dsap = d[pos]
            tipo += {0x42: "_stp", 0xAA: "_snap", 0xFE: "_osi"}.get(dsap, "_%02x" % dsap)
    else:
        tipo = {0x0800: "ipv4", 0x0806: "arp", 0x86DD: "ipv6", 0x88CC: "lldp", 0x8809: "lacp_slow",
                0x9000: "loopback", 0x88E5: "macsec", 0x8100: "vlan_anidada"}.get(et, "et_%04x" % et)
    return "%s/%s" % (etiqueta, tipo)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interfaz", default="ens37")
    ap.add_argument("--segundos", type=int, default=120)
    ap.add_argument("--pcap-dir", default="/var/lib/ppi-motor-capture")
    ap.add_argument("--salida", required=True)
    a = ap.parse_args()
    muestras = []
    fin = time.time() + a.segundos
    while True:
        t = time.time()
        muestras.append({"t": t, **leer_contadores(a.interfaz)})
        if t >= fin:
            break
        time.sleep(1 - (time.time() % 1) + 0.0005)
    time.sleep(12)                       # deja cerrar el fichero del anillo en curso (-G 5)
    t0, t1 = muestras[0]["t"], muestras[-1]["t"]
    total = collections.Counter()
    por_seg = collections.defaultdict(collections.Counter)
    ficheros, incidencias = [], []
    for ruta in sorted(glob.glob(os.path.join(a.pcap_dir, "live-*.pcap*"))):
        if os.path.getmtime(ruta) < t0 - 10:
            continue
        ficheros.append(os.path.basename(ruta))
        try:
            for ts, est, d in tramas(ruta):
                if est != "ok":
                    incidencias.append({"fichero": os.path.basename(ruta), "estado": est})
                    continue
                if t0 <= ts < t1:
                    c = clase(d)
                    total[c] += 1
                    por_seg[int(ts - t0)][c] += 1
        except (OSError, ValueError, EOFError) as e:
            incidencias.append({"fichero": os.path.basename(ruta), "error": str(e)})
    d_drop = muestras[-1]["rx_dropped"] - muestras[0]["rx_dropped"]
    d_pk = muestras[-1]["rx_packets"] - muestras[0]["rx_packets"]
    sin_manejador = {c for c in total if not c.endswith(("/ipv4", "/arp", "/ipv6"))}
    # serie por segundo: incremento de rx_dropped en [m_i, m_i+1) frente a tramas de cada clase en ese segundo
    serie = []
    for i in range(len(muestras) - 1):
        seg = int(muestras[i]["t"] - t0)
        # «s» se repite cuando dos muestras caen en el mismo segundo entero: «desde»/«hasta» son los
        # instantes reales del intervalo de la muestra.
        serie.append({"s": seg, "desde": muestras[i]["t"], "hasta": muestras[i + 1]["t"],
                      "rx_dropped": muestras[i + 1]["rx_dropped"] - muestras[i]["rx_dropped"],
                      "rx_packets": muestras[i + 1]["rx_packets"] - muestras[i]["rx_packets"],
                      "clases": dict(por_seg.get(seg, {}))})
    try:
        ptype = open("/proc/net/ptype").read()
    except OSError:
        ptype = None
    candidatas = {}
    for c in sorted(total):
        candidatas[c] = total[c]
    out = {"version": "1.0", "interfaz": a.interfaz, "desde_epoch": t0, "hasta_epoch": t1,
           "incremento": {"rx_packets": d_pk, "rx_dropped": d_drop,
                          "rx_nohandler": (muestras[-1]["rx_nohandler"] or 0) - (muestras[0]["rx_nohandler"] or 0)},
           "tramas_en_pcap": sum(total.values()), "por_clase": candidatas,
           "clases_sin_manejador_ipv4_arp_ipv6": sorted(sin_manejador),
           "tramas_sin_manejador": sum(total[c] for c in sin_manejador),
           "ficheros": ficheros, "incidencias": incidencias, "proc_net_ptype": ptype, "serie": serie}
    json.dump(out, open(a.salida, "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("incremento", "tramas_en_pcap", "por_clase", "tramas_sin_manejador")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
