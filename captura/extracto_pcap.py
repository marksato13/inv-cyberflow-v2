#!/usr/bin/env python3
"""Extracto publicable de los PCAP de una ejecución.

    python3 extracto_pcap.py capturas/<ID>/pcap --salida extracto.pcap.gz \
        --completas 10.10.20.21,...,10.10.20.26 [--cabeceras 10.10.10.30,10.10.60.11] [--cabeceras-bytes 96]

- Tramas con un extremo en --completas (tráfico experimental: contenido sintético del generador y
  del servidor de laboratorio, DNS de la zona del laboratorio): se copian enteras.
- Tramas con un extremo en --cabeceras (gestión del laboratorio, p. ej. SSH bastión↔Sensor1, que
  hace falta para revisar B1): se copian recortadas a --cabeceras-bytes (Ethernet + VLAN + IP +
  TCP), conservando en la cabecera del registro la longitud original. La carga (cifrada) no se publica.
- Todo lo demás (tráfico de otros equipos y de otros proyectos, VLAN ajenas, control del switch) se
  descarta. Se cuentan las tramas descartadas por motivo.

Se conserva el instante y el orden; el resultado es un único PCAP (ns) comprimido. Los ficheros
dañados no se ocultan: el extracto sale incompleto y el resumen lo dice (código 3).
"""
from __future__ import annotations

import argparse
import collections
import gzip
import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from copias_espejo import EntradaError, NOMBRE, tramas  # noqa: E402


def ips(d: bytes):
    tipo, pos = struct.unpack_from("!H", d, 12)[0], 14
    while tipo in (0x8100, 0x88A8) and len(d) >= pos + 4:
        tipo = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    if tipo != 0x0800 or len(d) < pos + 20:
        return None
    return socket.inet_ntoa(d[pos + 12:pos + 16]), socket.inet_ntoa(d[pos + 16:pos + 20])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("carpeta", type=Path)
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--completas", required=True)
    ap.add_argument("--cabeceras", default="")
    ap.add_argument("--cabeceras-bytes", type=int, default=96)
    ap.add_argument("--desde", type=float)
    ap.add_argument("--hasta", type=float)
    a = ap.parse_args()
    comp = set(a.completas.split(","))
    cab = set(x for x in a.cabeceras.split(",") if x) - comp
    cuenta, problemas = collections.Counter(), []
    with gzip.open(a.salida, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, 1))
        for f in sorted(x for x in a.carpeta.iterdir() if NOMBRE.fullmatch(x.name)):
            try:
                for ts, orig, d in tramas(f):
                    if (a.desde and ts < a.desde) or (a.hasta and ts > a.hasta):
                        continue
                    par = ips(d)
                    if not par:
                        cuenta["descartada_no_ipv4"] += 1
                        continue
                    if comp & set(par):
                        dato, clase = d, "completa"
                    elif cab & set(par):
                        dato, clase = d[:a.cabeceras_bytes], "cabeceras"
                    else:
                        cuenta["descartada_fuera_de_poblacion"] += 1
                        continue
                    cuenta[clase] += 1
                    seg = int(ts)
                    ns = min(999999999, int(round((ts - seg) * 1e9)))
                    out.write(struct.pack("<IIII", seg, ns, len(dato), orig) + dato)
            except EntradaError as e:
                problemas.append({"fichero": f.name, "tipo": e.tipo, "detalle": str(e)})
    r = {"version": "1.0", "origen": str(a.carpeta), "salida": str(a.salida), "completas": sorted(comp),
         "cabeceras": sorted(cab), "cabeceras_bytes": a.cabeceras_bytes, "tramas": dict(cuenta),
         "problemas": problemas, "completo": not problemas}
    print(json.dumps(r, ensure_ascii=False))
    return 3 if problemas else 0


if __name__ == "__main__":
    raise SystemExit(main())
