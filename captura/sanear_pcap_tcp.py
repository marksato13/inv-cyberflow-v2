#!/usr/bin/env python3
"""Extracto saneado de conexiones TCP concretas para publicarlo (Bloque 1, 3.ª revisión).

    python3 sanear_pcap_tcp.py ENTRADA.pcap SALIDA.pcap --informe informe.json \
        --conexion 10.10.20.22:41234 [--conexion …] [--servidor 10.10.30.10]

Conserva solo las tramas IPv4/TCP entre el servidor y los pares (IP, puerto) de cliente dados:
las conexiones persistentes de P2 que se quieren contrastar. Todo lo demás se descarta y se cuenta
por motivo. Las MAC de Ethernet se sustituyen por 02:00:00:00:xx:yy de forma consistente. Las
etiquetas 802.1Q (VLAN) se conservan porque la cobertura las usa para distinguir las dos copias
del espejo. La carga es la del servidor sintético del laboratorio (HTTP) o TLS cifrado (HTTPS).

Formatos: pcap clásico (µs o ns, ambos órdenes de bytes); enlace Ethernet (1). Otro formato
devuelve rc 3.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sanear_pcap_dns import cabecera_ip, sha256  # noqa: E402


def sanear(entrada, salida, conexiones, servidor="10.10.30.10"):
    clientes = {(ip, int(p)) for ip, p in (c.rsplit(":", 1) for c in conexiones)}
    macs, motivos, por_conexion = {}, Counter(), Counter()

    def mac(b):
        if b not in macs:
            n = len(macs) + 1
            macs[b] = bytes([2, 0, 0, 0, n >> 8, n & 255])
        return macs[b]

    with open(entrada, "rb") as f, open(salida, "wb") as o:
        glob = f.read(24)
        magia = glob[:4]
        if magia in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magia in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        else:
            raise ValueError("no es pcap clásico (¿pcapng?)")
        enlace = struct.unpack(e + "I", glob[20:24])[0]
        if enlace != 1:
            raise ValueError("enlace %d no soportado (solo Ethernet)" % enlace)
        o.write(glob)
        leidas = conservadas = 0
        while True:
            cab = f.read(16)
            if len(cab) < 16:
                if cab:
                    motivos["cabecera_truncada"] += 1
                break
            incl = struct.unpack(e + "IIII", cab)[2]
            t = f.read(incl)
            leidas += 1
            if len(t) < incl:
                motivos["trama_truncada"] += 1
                break
            ip = cabecera_ip(t, enlace)
            if ip is None or t[ip + 9] != 6:
                motivos["no_ipv4_tcp"] += 1
                continue
            ihl = (t[ip] & 15) * 4
            src, dst = socket.inet_ntoa(t[ip + 12:ip + 16]), socket.inet_ntoa(t[ip + 16:ip + 20])
            sp, dp = struct.unpack("!HH", t[ip + ihl:ip + ihl + 4])
            par = (dst, dp) if src == servidor else (src, sp) if dst == servidor else None
            if par is None or par not in clientes:
                motivos["fuera_de_las_conexiones"] += 1
                continue
            o.write(cab + mac(t[0:6]) + mac(t[6:12]) + t[12:])
            conservadas += 1
            por_conexion["%s:%d" % par] += 1
    return {"entrada": {"sha256": sha256(entrada), "tramas": leidas},
            "salida": {"ruta": Path(salida).name, "sha256": sha256(salida), "tramas": conservadas},
            "criterio": "IPv4/TCP entre %s y los pares de cliente dados; MAC seudonimizadas" % servidor,
            "conexiones": sorted(clientes), "tramas_por_conexion": dict(por_conexion),
            "mac_sustituidas": len(macs), "descartadas_por_motivo": dict(motivos)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("entrada")
    ap.add_argument("salida")
    ap.add_argument("--informe", required=True)
    ap.add_argument("--conexion", action="append", required=True)
    ap.add_argument("--servidor", default="10.10.30.10")
    a = ap.parse_args(argv)
    try:
        r = sanear(a.entrada, a.salida, a.conexion, a.servidor)
    except (OSError, ValueError, struct.error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 3
    Path(a.informe).write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: r[k] for k in ("salida", "mac_sustituidas", "descartadas_por_motivo")}))
    return 3 if {"cabecera_truncada", "trama_truncada"} & set(r["descartadas_por_motivo"]) else 0


if __name__ == "__main__":
    sys.exit(main())
