#!/usr/bin/env python3
"""Contraste entre una captura en un extremo (srv-dmz) y lo recibido por Sensor1 a través del espejo.

    python3 comparar_extremo.py --extremo srv.pcap --sensor <dir_pcap> --servidor 10.10.30.10 --salida c.json

Para cada conexión TCP con el servidor (puertos 80/443) y cada sentido:
- cobertura de bytes de carga: unión de rangos de secuencia vistos en el extremo frente a los vistos
  en Sensor1 (todas las copias del espejo juntas). Los rangos que el extremo vio y Sensor1 no son
  bytes que circularon y no llegaron al sensor por ninguna copia;
- segmentos de control por sentido (SYN, SYN-ACK, FIN, RST) y ACK puros, en ambos lados.
Limitaciones (se informan en la salida):
- el extremo tiene TSO/GSO/GRO/LRO activos: sus «paquetes» pueden agrupar varios segmentos del
  cable; por eso se comparan RANGOS DE BYTES y segmentos de control, no números de paquetes de datos;
- los ACK puros entrantes pueden agruparse en el extremo (GRO); su recuento es orientativo;
- el extremo solo ve el tráfico del servidor: DNS (clientes ↔ DC1) no se contrasta aquí;
- un paquete que el propio extremo no capturó (descartes de su tcpdump) no se puede contrastar.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from copias_espejo import tramas  # noqa: E402

import socket
import struct


def tcp(d: bytes):
    if len(d) < 14:
        return None
    tipo, pos = struct.unpack_from("!H", d, 12)[0], 14
    while tipo in (0x8100, 0x88a8) and len(d) >= pos + 4:
        tipo = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    if tipo != 0x0800 or len(d) < pos + 20 or d[pos + 9] != 6:
        return None
    ihl = (d[pos] & 15) * 4
    largo = struct.unpack_from("!H", d, pos + 2)[0]
    o, de = socket.inet_ntoa(d[pos + 12:pos + 16]), socket.inet_ntoa(d[pos + 16:pos + 20])
    c = pos + ihl
    if len(d) < c + 20:
        return None
    po, pd, seq, ack = struct.unpack_from("!HHII", d, c)
    off = (d[c + 12] >> 4) * 4
    carga = max(0, largo - ihl - off)
    return o, po, de, pd, seq, d[c + 13], carga


def recoger(fuentes, servidor: str, puertos=(80, 443), desde=None, hasta=None):
    """{(cliente, puerto_cliente, puerto_srv): {sentido: {"rangos": [...], "ctl": Counter}}}"""
    con = collections.defaultdict(lambda: {s: {"rangos": [], "ctl": collections.Counter(), "seq0": None}
                                           for s in ("c2s", "s2c")})
    for ruta in fuentes:
        for ts, _, d in tramas(ruta):
            if (desde and ts < desde) or (hasta and ts > hasta):
                continue
            r = tcp(d)
            if not r:
                continue
            o, po, de, pd, seq, fl, carga = r
            if de == servidor and pd in puertos:
                k, s = (o, po, pd), "c2s"
            elif o == servidor and po in puertos:
                k, s = (de, pd, po), "s2c"
            else:
                continue
            x = con[k][s]
            if fl & 0x02:
                x["ctl"]["synack" if fl & 0x10 else "syn"] += 1
                x["seq0"] = seq if x["seq0"] is None else x["seq0"]
            if fl & 0x01:
                x["ctl"]["fin"] += 1
            if fl & 0x04:
                x["ctl"]["rst"] += 1
            if carga == 0 and fl == 0x10:
                x["ctl"]["ack_puro"] += 1
            if carga:
                x["rangos"].append((seq, carga))
    return con


def unir(rangos, base):
    iv = []
    for seq, n in rangos:
        a = (seq - base) % (1 << 32)
        if a >= 1 << 31:
            continue
        iv.append((a, a + n))
    iv.sort()
    out = []
    for a, b in iv:
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def restar(a, b):
    """Bytes de los intervalos a que no cubre b."""
    falta, j = [], 0
    for x, y in a:
        cur = x
        while j < len(b) and b[j][1] <= cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] < y:
            if b[k][0] > cur:
                falta.append([cur, b[k][0]])
            cur = max(cur, b[k][1])
            k += 1
        if cur < y:
            falta.append([cur, y])
    return falta


def comparar(ext, sen) -> dict:
    filas, tot = [], collections.Counter()
    for k, lados in ext.items():
        for s in ("c2s", "s2c"):
            e = lados[s]
            if not e["rangos"] and not e["ctl"]:
                continue
            so = sen.get(k, {}).get(s, {"rangos": [], "ctl": collections.Counter()})
            base = e["seq0"] if e["seq0"] is not None else (min(x[0] for x in e["rangos"]) if e["rangos"] else 0)
            if e["seq0"] is not None:
                base = (base + 1) % (1 << 32)
            re_, rs = unir(e["rangos"], base), unir(so["rangos"], base)
            falta = restar(re_, rs)
            bytes_ext = sum(b - a for a, b in re_)
            bytes_falta = sum(b - a for a, b in falta)
            ctl_falta = {c: e["ctl"][c] - so["ctl"].get(c, 0) for c in ("syn", "synack", "fin", "rst")
                         if e["ctl"][c] > so["ctl"].get(c, 0)}
            tot["sentidos"] += 1
            tot["bytes_extremo"] += bytes_ext
            tot["bytes_no_vistos_sensor"] += bytes_falta
            tot["sentidos_con_faltas"] += 1 if (bytes_falta or ctl_falta) else 0
            for c in ("syn", "synack", "fin", "rst", "ack_puro"):
                tot["extremo_" + c] += e["ctl"][c]
                tot["sensor_" + c] += so["ctl"].get(c, 0)
            if bytes_falta or ctl_falta:
                filas.append({"cliente": k[0], "puerto_cliente": k[1], "puerto_srv": k[2], "sentido": s,
                              "bytes_extremo": bytes_ext, "bytes_no_vistos_sensor": bytes_falta,
                              "rangos_no_vistos": falta[:20], "control_no_visto": ctl_falta})
    return {"conexiones": len(ext), "totales": dict(tot), "faltas": filas}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--extremo", type=Path, required=True)
    ap.add_argument("--sensor", type=Path, required=True)
    ap.add_argument("--servidor", default="10.10.30.10")
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--margen-s", type=float, default=1.0)
    a = ap.parse_args()
    ext = recoger([a.extremo], a.servidor)
    t = [ts for ts, _, _ in tramas(a.extremo)]
    desde, hasta = (min(t) - a.margen_s, max(t) + a.margen_s) if t else (None, None)
    fuentes = sorted(p for p in a.sensor.iterdir() if p.name.startswith("live-") and ".pcap" in p.name)
    sen = recoger(fuentes, a.servidor, desde=desde, hasta=hasta)
    r = comparar(ext, sen)
    r.update({"extremo": str(a.extremo), "sensor": str(a.sensor), "ventana": [desde, hasta],
              "limitaciones": ["TSO/GSO/GRO/LRO activos en el extremo: se comparan rangos de bytes y control",
                               "ACK puros entrantes del extremo pueden estar agrupados (GRO): orientativo",
                               "DNS no se contrasta (el extremo es el servidor web)",
                               "una conexión que empieza o acaba fuera de la captura del extremo queda parcial"]})
    a.salida.write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"conexiones": r["conexiones"], **r["totales"], "faltas": len(r["faltas"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
