#!/usr/bin/env python3
"""Extracto publicable de la prueba de rx_dropped: solo las tramas sin manejador de protocolo.

    python3 extracto_rx_dropped.py --prueba rx-dropped-r2.json --pcap-dir pcap/ \
        --salida-pcap extracto-sin-manejador.pcap --salida-csv extracto-sin-manejador.csv \
        --salida-json extracto-sin-manejador.json

Del periodo [desde, hasta) de la prueba toma cada trama cuya clase (rx_dropped_prueba.clase) no sea
IPv4, ARP ni IPv6 (las que el núcleo cuenta en rx_dropped) y la escribe:
  - en un PCAP con la cabecera Ethernet, las etiquetas VLAN y la cabecera LLC/SNAP intactas (es lo
    que decide la clase), la MAC de destino conservada solo si es multicast de protocolo
    (p. ej. 01:00:0c:cc:cc:cd, PVST+) y la de origen sustituida por un seudónimo estable dentro del
    extracto (02:00:00:xx:xx:xx); el resto de la trama (BPDU, TLV de CDP: identificadores de puente,
    nombres, versiones, direcciones) a ceros, conservando la longitud;
  - en un CSV con instante, segundo de la prueba, VLAN, clase, OUI/PID SNAP y longitud.
El JSON resume recuentos por clase y PID y dice qué clase iguala el incremento de rx_dropped. Con el extracto, `rx_dropped_prueba.clase()` da las mismas clases que el original.
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rx_dropped_prueba as rx  # noqa: E402

CON_MANEJADOR = ("/ipv4", "/arp", "/ipv6")
PID = {0x010B: "pvst+", 0x2000: "cdp", 0x2003: "vtp", 0x2004: "dtp", 0x0104: "pagp", 0x0111: "udld"}


def cabecera(d: bytes):
    """(vlans, ethertype/longitud, posición tras las etiquetas)."""
    et, pos, vlans = struct.unpack_from("!H", d, 12)[0], 14, []
    while et in (0x8100, 0x88A8) and len(d) >= pos + 4:
        vlans.append(struct.unpack_from("!H", d, pos)[0] & 0x0FFF)
        et = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    return vlans, et, pos


def sanear(d: bytes, seud: dict) -> tuple[bytes, dict]:
    vlans, et, pos = cabecera(d)
    info = {"vlan": vlans[0] if vlans else None, "snap_oui": "", "snap_pid": "", "protocolo": ""}
    fin_cab = pos
    if et < 0x0600 and len(d) >= pos + 3:
        fin_cab = pos + 3
        if d[pos] == 0xAA and len(d) >= pos + 8:
            fin_cab = pos + 8
            oui, pid = d[pos + 3:pos + 6].hex(), struct.unpack_from("!H", d, pos + 6)[0]
            info.update(snap_oui=oui, snap_pid="%04x" % pid, protocolo=PID.get(pid, "pid_%04x" % pid))
    dst, src = d[0:6], d[6:12]
    if not dst[0] & 1:                                   # unicast: no se publica
        dst = seud.setdefault(bytes(dst), bytes([2, 0, 0]) + len(seud).to_bytes(3, "big"))
    src = seud.setdefault(bytes(src), bytes([2, 0, 0]) + len(seud).to_bytes(3, "big"))
    nueva = dst + src + d[12:fin_cab] + b"\x00" * (len(d) - fin_cab)
    return nueva, info


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prueba", required=True)
    ap.add_argument("--pcap-dir", required=True)
    ap.add_argument("--salida-pcap", required=True)
    ap.add_argument("--salida-csv", required=True)
    ap.add_argument("--salida-json", required=True)
    a = ap.parse_args(argv)
    p = json.load(open(a.prueba, encoding="utf-8"))
    t0, t1 = p["desde_epoch"], p["hasta_epoch"]
    seud, total, por_pid = {}, collections.Counter(), collections.Counter()
    rutas = [os.path.join(a.pcap_dir, f) for f in p["ficheros"]]
    faltan = [r for r in rutas if not os.path.exists(r)]
    with open(a.salida_pcap, "wb") as fp, open(a.salida_csv, "w", newline="", encoding="utf-8") as fc:
        fp.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        w = csv.writer(fc)
        w.writerow(["epoch", "segundo", "vlan", "clase", "snap_oui", "snap_pid", "protocolo", "longitud"])
        for ruta in sorted(set(rutas) - set(faltan)):
            for ts, est, d in rx.tramas(ruta):
                if est != "ok" or not (t0 <= ts < t1):
                    continue
                c = rx.clase(d)
                if c.endswith(CON_MANEJADOR):
                    continue
                nueva, info = sanear(d, seud)
                s, us = int(ts), int(round((ts - int(ts)) * 1e6))
                if us == 1_000_000:
                    s, us = s + 1, 0
                fp.write(struct.pack("<IIII", s, us, len(nueva), len(nueva)) + nueva)
                seg = int(ts - t0)
                w.writerow(["%.6f" % ts, seg, info["vlan"], c, info["snap_oui"], info["snap_pid"],
                            info["protocolo"], len(d)])
                total[c] += 1
                por_pid[info["protocolo"] or c] += 1
    d_drop = p["incremento"]["rx_dropped"]
    # La serie de rx_dropped_prueba 1.0 indexa por int(t − t0) de la muestra, y las muestras no caen
    # en fronteras exactas de segundo (índices repetidos): solo se compara el total por clase.
    out = {"version": 2, "prueba": os.path.basename(a.prueba), "desde_epoch": t0, "hasta_epoch": t1,
           "incremento_prueba": p["incremento"], "tramas_sin_manejador": sum(total.values()),
           "por_clase": dict(sorted(total.items())), "por_protocolo": dict(sorted(por_pid.items())),
           "clases_iguales_a_rx_dropped": sorted(c for c, n in total.items() if n == d_drop),
           "snap_802_3_igual_a_rx_dropped": sum(n for c, n in total.items() if "802.3_llc_snap" in c) == d_drop,
           "ficheros_faltan": [os.path.basename(r) for r in faltan],
           "macs_seudonimizadas": len(seud),
           "saneado": "MAC unicast -> 02:00:00:xx:xx:xx; contenido tras LLC/SNAP a ceros; longitud conservada"}
    json.dump(out, open(a.salida_json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: out[k] for k in ("tramas_sin_manejador", "por_protocolo", "clases_iguales_a_rx_dropped",
                                           "snap_802_3_igual_a_rx_dropped")}, ensure_ascii=False))
    return 0 if not faltan else 2


if __name__ == "__main__":
    raise SystemExit(main())
