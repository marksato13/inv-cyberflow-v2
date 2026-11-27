"""Deduplicación de las copias del espejo SPAN, V2 (Bloque 3, PENDIENTES 37).

Sustituye a ``extract_multilayer_v3.deduplicar_espejo`` (V1 @ d2c9772), que tenía dos defectos
medidos en el Bloque 1:

1. **Funde transmisiones distintas.** Su clave no lleva ``ack`` ni ``flags``, y cualquier trama con
   la misma clave a ≤ 5 ms y |ΔTTL| ≤ 1 se toma por copia. Un cliente que envía dos RST idénticos
   (ipid 0) en el mismo instante produce 4 tramas en el espejo, y V1 deja 1. En VD2–VD6 fundía 15–16
   transmisiones de unas 16 000 por ejecución.
2. **No empareja copias separadas más de 5 ms.** En E3, bajo ráfaga, dos copias llegaron a 5,1 ms.

Reglas V2, las mismas que verificó el comprobador ``captura/copias_espejo.py``:

- **Clave:** protocolo, IP y puertos, ``ipid``, longitud IP, ``seq``, **``ack``**, **``flags``**, y tipo
  e identificador ICMP.
- **Ventana:** 20 ms desde la primera trama del grupo.
- **Copia del espejo:** misma clave dentro de la ventana, con un TTL a ≤ 1 de todos los del grupo.
- **Unidifusión enrutada** (extremos en /24 distintos): dentro de un grupo no se repite el par (VLAN,
  TTL). El espejo enseña cada trama una vez por VLAN recorrida (con TTL−1 tras el enrutador), así que
  una segunda trama con la misma VLAN y el mismo TTL es otra transmisión idéntica.
- **Sin enrutar** (difusión, multidifusión, o extremos en el mismo /24): el espejo enseña dos copias
  idénticas, misma VLAN y TTL, una por troncal. Un grupo admite como mucho 2 tramas. Medido en VD4: unas
  40 000 copias así, dentro de 10.10.10.0/24 y 10.10.20.0/24, de las VLAN 70 y 95 y de pfsync en la 100.
  Límite: dos transmisiones idénticas sin enrutar que el espejo vea una sola vez cada una se funden, igual
  que en V1.
- **Se conserva la copia de mayor TTL** (la del emisor, la que mide ``ttl_mean_10s``); en empate, la
  primera en el orden de entrada. Es lo mismo que V1.

Interfaz idéntica a la de V1: ``deduplicar_espejo_v2(contextos) -> (paquetes conservados, n
quitados)``, con los paquetes en el orden estable por instante. Los contextos tienen que llevar
``tcp_ack``: los construye ``parse_con_contexto_v2``.

La partición ``clave_espejo`` de ``motor_incremental.Deduplicador`` (producto) es más gruesa que esta
clave (no lleva ``ack`` ni ``flags``), así que el deduplicador incremental del motor admite esta función
sin cambios. Lo comprueba ``tests/test_deduplicar_v2.py`` del producto. El motor la usa con
``--deduplicacion v2``; por omisión usa ``v1``, la del modelo en operación.

Este fichero tiene que ser idéntico en V2 (``extraccion/``) y en el producto (``scripts/features/``).
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

import extract_multilayer_v3 as v3

VERSION = 3
VENTANA_COPIA_S = 0.020
MAX_COPIAS_IDENTICAS = 2


@dataclass(frozen=True)
class FrameContextV2:
    """``FrameContext`` de V1 (paquete, VLAN, ipid) más el ``ack`` TCP, que V1 no lee."""
    packet: object
    vlan: int
    ip_id: int
    tcp_ack: int


def parse_con_contexto_v2(timestamp: float, frame: bytes) -> FrameContextV2 | None:
    ctx = v3.parse_con_contexto(timestamp, frame)
    if ctx is None:
        return None
    p, ack = ctx.packet, 0
    if p.protocol == 6 and not p.fragmented:
        pos, tipo = 14, struct.unpack("!H", frame[12:14])[0]
        while tipo in (0x8100, 0x88A8):
            tipo = struct.unpack("!H", frame[pos + 2:pos + 4])[0]
            pos += 4
        tcp = pos + (frame[pos] & 15) * 4
        if len(frame) >= tcp + 12:
            ack = struct.unpack("!I", frame[tcp + 8:tcp + 12])[0]
    return FrameContextV2(p, ctx.vlan, ctx.ip_id, ack)


def clave_v2(contexto) -> tuple:
    p = contexto.packet
    return (p.protocol, p.src_ip, p.dst_ip, p.src_port, p.dst_port, contexto.ip_id, p.ip_length,
            p.tcp_seq, contexto.tcp_ack, p.tcp_flags, p.icmp_type, p.icmp_id)


def es_difusion(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_multicast or ip == "255.255.255.255" or ip.endswith(".255")
    except ValueError:
        return False


def sin_enrutar(origen: str, destino: str) -> bool:
    """Difusión, multidifusión o los dos extremos en el mismo /24: el espejo ve copias idénticas."""
    return es_difusion(destino) or origen.rsplit(".", 1)[0] == destino.rsplit(".", 1)[0]


def deduplicar_espejo_v2(contextos: list, ventana_segundos: float = VENTANA_COPIA_S) -> tuple[list, int]:
    orden = sorted(range(len(contextos)), key=lambda i: contextos[i].packet.timestamp)
    abiertos: dict[tuple, list] = {}
    grupos = []
    for i in orden:
        c = contextos[i]
        p = c.packet
        k = clave_v2(c)
        lista = abiertos.setdefault(k, [])
        while lista and p.timestamp - lista[0]["t0"] > ventana_segundos:
            lista.pop(0)                         # ya no admite más copias
        identicas = sin_enrutar(p.src_ip, p.dst_ip)
        destino = None
        for g in lista:                          # el grupo abierto más antiguo que la admita
            if any(abs(p.ttl - t) > 1 for t in g["ttl"]):
                continue
            if (len(g["m"]) < MAX_COPIAS_IDENTICAS) if identicas else ((c.vlan, p.ttl) not in g["vt"]):
                destino = g
                break
        if destino is None:
            destino = {"t0": p.timestamp, "m": [], "vt": set(), "ttl": []}
            lista.append(destino)
            grupos.append(destino)
        destino["m"].append(i)
        destino["vt"].add((c.vlan, p.ttl))
        destino["ttl"].append(p.ttl)
    conservar = set()
    for g in grupos:
        # mayor TTL; en empate, el primero en el orden de entrada (g["m"] ya va en ese orden)
        conservar.add(max(g["m"], key=lambda i: (contextos[i].packet.ttl, -g["m"].index(i))))
    return [contextos[i].packet for i in orden if i in conservar], len(contextos) - len(conservar)
