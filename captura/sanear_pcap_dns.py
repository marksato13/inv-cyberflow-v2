#!/usr/bin/env python3
"""Sanea el PCAP DNS de DC1 para publicarlo (Bloque 1, revisión del 26-nov).

Conserva solo las tramas IPv4/UDP con puerto 53 entre un cliente de la población
(10.10.20.21-26 por omisión) y el servidor DNS (10.10.10.20). Todo lo demás (otros
equipos que consultan a DC1, otros protocolos) se descarta y se cuenta por motivo.
La carga de lo conservado es sintética (zona del laboratorio), así que se publica entera.

Además lista las transacciones DNS conservadas con su id y nombre consultado, para que
los eventos `sin_transaccion` de contraste_dns.py se puedan identificar sin el original.

Formatos: pcap clásico (µs o ns, ambos órdenes de bytes); enlaces Ethernet (1),
Linux SLL (113) y SLL2 (276). Un pcapng o un enlace desconocido es un error (rc 3).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import sys
from collections import Counter

POBLACION = [f"10.10.20.{i}" for i in range(21, 27)]
SERVIDOR = "10.10.10.20"


def sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cabecera_ip(trama: bytes, enlace: int):
    """Devuelve el desplazamiento de la cabecera IPv4 o None."""
    if enlace == 1:
        i, tipo = 12, struct.unpack("!H", trama[12:14])[0]
        while tipo in (0x8100, 0x88A8):          # 802.1Q / QinQ
            i += 4
            tipo = struct.unpack("!H", trama[i:i + 2])[0]
        return i + 2 if tipo == 0x0800 else None
    if enlace == 113:
        return 16 if struct.unpack("!H", trama[14:16])[0] == 0x0800 else None
    if enlace == 276:
        return 20 if struct.unpack("!H", trama[0:2])[0] == 0x0800 else None
    raise ValueError("enlace %d no soportado" % enlace)


def nombre_dns(m: bytes, i: int) -> str:
    partes, saltos = [], 0
    while i < len(m) and saltos < 20:
        n = m[i]
        if n == 0:
            break
        if n & 0xC0 == 0xC0:
            i = ((n & 0x3F) << 8) | m[i + 1]
            saltos += 1
            continue
        partes.append(m[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(partes)


def sanear(entrada, salida, poblacion=POBLACION, servidor=SERVIDOR):
    pobl = set(poblacion)
    motivos = Counter()
    transacciones = []
    with open(entrada, "rb") as f:
        glob = f.read(24)
        if len(glob) < 24:
            raise ValueError("cabecera global truncada")
        magia = glob[:4]
        if magia in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magia in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        else:
            raise ValueError("no es pcap clásico (¿pcapng?)")
        ns = magia in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        enlace = struct.unpack(e + "I", glob[20:24])[0]
        conservadas = leidas = 0
        with open(salida, "wb") as o:
            o.write(glob)
            while True:
                cab = f.read(16)
                if not cab:
                    break
                if len(cab) < 16:
                    motivos["cabecera_truncada"] += 1
                    break
                seg, frac, incl, orig = struct.unpack(e + "IIII", cab)
                trama = f.read(incl)
                leidas += 1
                if len(trama) < incl:
                    motivos["trama_truncada"] += 1
                    break
                ip = cabecera_ip(trama, enlace)
                if ip is None:
                    motivos["no_ipv4"] += 1
                    continue
                ihl = (trama[ip] & 15) * 4
                if trama[ip + 9] != 17:
                    motivos["no_udp"] += 1
                    continue
                src = socket.inet_ntoa(trama[ip + 12:ip + 16])
                dst = socket.inet_ntoa(trama[ip + 16:ip + 20])
                sp, dp = struct.unpack("!HH", trama[ip + ihl:ip + ihl + 4])
                if 53 not in (sp, dp):
                    motivos["udp_no_dns"] += 1
                    continue
                par = {src, dst}
                if servidor not in par or not (par - {servidor}) <= pobl or len(par) != 2:
                    motivos["dns_fuera_de_la_poblacion"] += 1
                    continue
                o.write(cab + trama)
                conservadas += 1
                dns = trama[ip + ihl + 8:]
                if len(dns) >= 12:
                    tid, flags = struct.unpack("!HH", dns[:4])
                    cliente, puerto = (src, sp) if dp == 53 else (dst, dp)
                    transacciones.append({
                        "t": seg + frac / (1e9 if ns else 1e6),
                        "sentido": "respuesta" if flags & 0x8000 else "consulta",
                        "cliente": cliente, "puerto": puerto, "id": tid,
                        "nombre": nombre_dns(dns, 12), "rcode": flags & 15,
                    })
    return {
        "entrada": {"ruta": entrada, "sha256": sha256(entrada), "tramas": leidas},
        "salida": {"ruta": salida, "sha256": sha256(salida), "tramas": conservadas},
        "enlace": enlace, "precision": "ns" if ns else "us",
        "criterio": "IPv4/UDP puerto 53 entre %s y %s" % (servidor, ",".join(poblacion)),
        "descartadas_por_motivo": dict(motivos),
        "tramas_conservadas_por_cliente": dict(Counter(t["cliente"] for t in transacciones)),
        "transacciones": transacciones,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("entrada")
    ap.add_argument("salida")
    ap.add_argument("--informe", required=True)
    ap.add_argument("--poblacion", default=",".join(POBLACION))
    ap.add_argument("--servidor", default=SERVIDOR)
    a = ap.parse_args(argv)
    try:
        r = sanear(a.entrada, a.salida, a.poblacion.split(","), a.servidor)
    except (OSError, ValueError, struct.error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 3
    with open(a.informe, "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: r[k] for k in ("entrada", "salida", "descartadas_por_motivo")}, ensure_ascii=False))
    return 3 if {"cabecera_truncada", "trama_truncada"} & set(r["descartadas_por_motivo"]) else 0


if __name__ == "__main__":
    sys.exit(main())
