#!/usr/bin/env python3
"""Registro independiente, en el propio servidor DNS (DC1), de las consultas y respuestas de los perfiles V2.

Lee los paquetes UDP/53 de la interfaz con un socket AF_PACKET (solo lectura; necesita root) y escribe
una línea JSONL por consulta o respuesta en la que participe una IP de la población. No modifica el
servidor DNS ni su configuración. Registra: instante UTC, sentido, cliente y puerto, id DNS, nombre,
tipo, rcode, número de respuestas y direcciones A. Sin contenido sensible (solo DNS de la zona del
laboratorio).

Uso (DC1, root):  python3 registro_dns_v2.py --interfaz ens18 --salida /var/log/cyberflow-v2/dns.jsonl \
                     --poblacion 10.10.20.21,10.10.20.22,10.10.20.23,10.10.20.24,10.10.20.25,10.10.20.26
Para: SIGTERM (cierra y escribe un resumen final).
"""
from __future__ import annotations

import argparse
import datetime
import json
import signal
import socket
import struct
import sys

ETH_P_ALL = 0x0003
TIPOS = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA", 12: "PTR", 33: "SRV"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def _nombre(msg: bytes, off: int, saltos: int = 0) -> tuple[str, int]:
    partes, fin = [], None
    while True:
        if off >= len(msg) or saltos > 20:
            raise ValueError("nombre DNS fuera de rango")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if fin is None:
                fin = off + 2
            sub, _ = _nombre(msg, ptr, saltos + 1)
            partes.append(sub)
            off = fin
            return ".".join(p for p in partes if p), off
        partes.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(partes), (fin if fin is not None else off)


def analizar_dns(msg: bytes) -> dict:
    if len(msg) < 12:
        raise ValueError("DNS corto")
    ident, banderas, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    off = 12
    nombre, qtipo = None, None
    if qd:
        nombre, off = _nombre(msg, off)
        qtipo = struct.unpack("!H", msg[off:off + 2])[0]
        off += 4
        for _ in range(qd - 1):
            _, off = _nombre(msg, off)
            off += 4
    a = []
    for _ in range(an):
        _, off = _nombre(msg, off)
        tipo, _clase, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if tipo == 1 and rdlen == 4:
            a.append(socket.inet_ntoa(msg[off:off + 4]))
        off += rdlen
    return {"id": ident, "respuesta": bool(banderas & 0x8000), "rcode": RCODES.get(banderas & 0xF, banderas & 0xF),
            "nombre": nombre, "tipo": TIPOS.get(qtipo, qtipo), "n_respuestas": an, "a": a}


def analizar_trama(trama: bytes) -> tuple | None:
    """Devuelve (ip_src, puerto_src, ip_dst, puerto_dst, carga_udp) si es IPv4/UDP con un extremo en 53."""
    off = 14
    etype = struct.unpack("!H", trama[12:14])[0]
    while etype in (0x8100, 0x88A8):
        etype = struct.unpack("!H", trama[off + 2:off + 4])[0]
        off += 4
    if etype != 0x0800 or len(trama) < off + 20:
        return None
    ihl = (trama[off] & 0x0F) * 4
    if trama[off + 9] != 17:
        return None
    src, dst = socket.inet_ntoa(trama[off + 12:off + 16]), socket.inet_ntoa(trama[off + 16:off + 20])
    u = off + ihl
    sp, dp, ln = struct.unpack("!HHH", trama[u:u + 6])
    if 53 not in (sp, dp):
        return None
    return src, sp, dst, dp, trama[u + 8:u + ln]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interfaz", required=True)
    ap.add_argument("--salida", required=True)
    ap.add_argument("--poblacion", required=True, help="IP separadas por comas")
    a = ap.parse_args()
    pobl = set(a.poblacion.split(","))
    sk = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sk.bind((a.interfaz, 0))
    sk.settimeout(1.0)
    cont = {"tramas_dns": 0, "registradas": 0, "errores_analisis": 0}
    vivo = [True]
    signal.signal(signal.SIGTERM, lambda *_: vivo.__setitem__(0, False))
    signal.signal(signal.SIGINT, lambda *_: vivo.__setitem__(0, False))
    with open(a.salida, "a", encoding="utf-8", buffering=1) as f:
        f.write(json.dumps({"evento": "arranque", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "interfaz": a.interfaz, "poblacion": sorted(pobl)}) + "\n")
        while vivo[0]:
            try:
                trama, info = sk.recvfrom(65535)
            except socket.timeout:
                continue
            r = analizar_trama(trama)
            if not r:
                continue
            src, sp, dst, dp, carga = r
            if src not in pobl and dst not in pobl:
                continue
            cont["tramas_dns"] += 1
            t = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")
            try:
                d = analizar_dns(carga)
            except Exception as e:  # noqa: BLE001 - se registra, no se oculta
                cont["errores_analisis"] += 1
                f.write(json.dumps({"utc": t, "error": str(e), "src": src, "dst": dst}) + "\n")
                continue
            cliente, pc = (src, sp) if src in pobl else (dst, dp)
            f.write(json.dumps({"utc": t, "sentido": "respuesta" if d["respuesta"] else "consulta",
                                "cliente": cliente, "puerto_cliente": pc, **d}, ensure_ascii=False) + "\n")
            cont["registradas"] += 1
        f.write(json.dumps({"evento": "fin", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), **cont}) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
