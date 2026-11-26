#!/usr/bin/env python3
"""Extracto publicable del tráfico EXPERIMENTAL de una ejecución (Bloque 1, revisión 4).

    python3 extracto_experimento.py pcap  ENTRADA[.pcap|.pcap.gz] SALIDA.pcap --poblacion IP,… --servidor IP,… \
        --clave FICHERO_PRIVADO [--informe x.json]
    python3 extracto_experimento.py eve   ENTRADA.json SALIDA.json --poblacion IP,… --servidor IP,…

Criterio (el mismo para el anillo de Sensor1, el extremo de srv-dmz y el PCAP de DC1): se conserva
una trama IPv4 si uno de sus extremos es de la población y el otro es de la población o un servidor
del experimento. Todo lo demás (gestión, equipos ajenos, ARP, STP/CDP, IPv6) se descarta y se cuenta
por motivo.

Lo que se conserva sin tocar, byte a byte: marca de tiempo (s + fracción, misma precisión), longitud
capturada y original, etiquetas 802.1Q/QinQ, cabeceras IP/TCP/UDP (TTL, IP ID, números de
secuencia, sumas de comprobación) y la carga (servidor sintético HTTP, TLS cifrado, DNS de la zona
del laboratorio).

Si SALIDA termina en .gz se escribe comprimida (gzip, mtime 0): el extracto del anillo conserva así
el nombre `live-*.pcap.gz` que registran el inventario y el manifiesto de la ejecución.

ÚNICA modificación del contenido: las MAC (Ethernet: destino y origen; Linux SLL/SLL2: la dirección de enlace) se
sustituyen por 02:xx:xx:xx:xx:xx = HMAC-SHA256(clave, MAC)[:5]. Así la seudonimización es
determinista y consistente entre ficheros y ejecuciones (la misma MAC da el mismo seudónimo en
Sensor1, srv-dmz y DC1) y no reversible sin la clave, que es privada y no se publica.

EVE: se conservan los eventos cuyo flujo cumple el mismo criterio de IP; se quita el campo `ether`
(MAC). No se modifica nada más.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import socket
import struct
import sys
from collections import Counter
from pathlib import Path


def abrir(ruta):
    return gzip.open(ruta, "rb") if str(ruta).endswith(".gz") else open(ruta, "rb")


def sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Seudonimo:
    def __init__(self, clave: bytes):
        self.clave, self.vistas = clave, set()

    def __call__(self, mac: bytes) -> bytes:
        if mac == b"\xff" * 6 or mac == b"\x00" * 6:
            return mac                               # difusión / vacía: no identifican a nadie
        self.vistas.add(mac)
        return b"\x02" + hmac.new(self.clave, mac, hashlib.sha256).digest()[:5]


def ip_ethernet(t: bytes):
    i, tipo = 12, struct.unpack("!H", t[12:14])[0]
    while tipo in (0x8100, 0x88A8):
        i += 4
        tipo = struct.unpack("!H", t[i:i + 2])[0]
    return i + 2 if tipo == 0x0800 else None


def filtrar_pcap(entrada, salida, poblacion, servidores, clave: bytes):
    pobl, serv = set(poblacion), set(servidores)
    permitido = pobl | serv
    seud = Seudonimo(clave)
    motivos, conservadas, leidas = Counter(), 0, 0
    # SALIDA .pcap.gz -> gzip, para conservar el nombre del fichero del anillo: el inventario y el
    # manifiesto de la ejecución lo nombran así, y cobertura/copias/extracción lo buscan por nombre.
    escribir = (lambda p: gzip.GzipFile(p, "wb", compresslevel=6, mtime=0)) if str(salida).endswith(".gz") else (lambda p: open(p, "wb"))
    with abrir(entrada) as f, escribir(salida) as o:
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
        enlace = struct.unpack(e + "I", glob[20:24])[0]
        if enlace not in (1, 113, 276):
            raise ValueError("enlace %d no soportado" % enlace)
        o.write(glob)
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
            if enlace == 1:
                ip = ip_ethernet(t) if len(t) >= 14 else None
            elif enlace == 113:
                ip = 16 if len(t) >= 16 and t[14:16] == b"\x08\x00" else None
            else:
                ip = 20 if len(t) >= 20 and t[0:2] == b"\x08\x00" else None
            if ip is None or len(t) < ip + 20:
                motivos["no_ipv4"] += 1
                continue
            src, dst = socket.inet_ntoa(t[ip + 12:ip + 16]), socket.inet_ntoa(t[ip + 16:ip + 20])
            if not ({src, dst} & pobl) or not ({src, dst} <= permitido):
                motivos["fuera_del_experimento"] += 1
                continue
            if enlace == 1:
                t = seud(t[0:6]) + seud(t[6:12]) + t[12:]
            elif enlace == 113:                       # SLL: dirección en [6:12] si su longitud es 6
                if struct.unpack("!H", t[4:6])[0] == 6:
                    t = t[:6] + seud(t[6:12]) + t[12:]
            else:                                     # SLL2: dirección en [12:18] si su longitud es 6
                if t[11] == 6:
                    t = t[:12] + seud(t[12:18]) + t[18:]
            o.write(cab + t)
            conservadas += 1
    return {"entrada": {"nombre": Path(entrada).name, "tramas": leidas},
            "salida": {"nombre": Path(salida).name, "sha256": sha256(salida), "tramas": conservadas},
            "enlace": enlace, "mac_seudonimizadas": len(seud.vistas),
            "descartadas_por_motivo": dict(motivos)}


def filtrar_eve(entrada, salida, poblacion, servidores):
    pobl, permitido = set(poblacion), set(poblacion) | set(servidores)
    n = guardados = 0
    with open(entrada, encoding="utf-8", errors="replace") as f, open(salida, "w", encoding="utf-8") as o:
        for linea in f:
            n += 1
            try:
                ev = json.loads(linea)
            except ValueError:
                continue
            par = {ev.get("src_ip"), ev.get("dest_ip")}
            if par & pobl and par <= permitido:
                ev.pop("ether", None)
                o.write(json.dumps(ev, ensure_ascii=False) + "\n")
                guardados += 1
    return {"entrada": {"nombre": Path(entrada).name, "eventos": n},
            "salida": {"nombre": Path(salida).name, "sha256": sha256(salida), "eventos": guardados}}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tipo", choices=("pcap", "eve"))
    ap.add_argument("entrada")
    ap.add_argument("salida")
    ap.add_argument("--poblacion", required=True)
    ap.add_argument("--servidor", required=True)
    ap.add_argument("--clave", help="fichero privado con la clave HMAC de las MAC (solo pcap)")
    ap.add_argument("--informe")
    a = ap.parse_args(argv)
    p, s = a.poblacion.split(","), a.servidor.split(",")
    try:
        if a.tipo == "pcap":
            if not a.clave:
                ap.error("--clave es obligatoria para pcap")
            r = filtrar_pcap(a.entrada, a.salida, p, s, Path(a.clave).read_bytes().strip())
        else:
            r = filtrar_eve(a.entrada, a.salida, p, s)
    except (OSError, ValueError, struct.error, EOFError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 3
    if a.informe:
        Path(a.informe).write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(r, ensure_ascii=False))
    return 3 if {"cabecera_truncada", "trama_truncada"} & set(r.get("descartadas_por_motivo", {})) else 0


if __name__ == "__main__":
    sys.exit(main())
