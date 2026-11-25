"""Lectura estricta de PCAP clásico y tramas Ethernet IPv4/TCP."""

from __future__ import annotations

import gzip
import ipaddress
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path


class PcapDañado(ValueError):
    def __init__(self, ruta: Path, posicion: int, motivo: str):
        super().__init__(f"{ruta}:{posicion}: {motivo}")
        self.ruta = ruta
        self.posicion = posicion


@dataclass(frozen=True)
class Paquete:
    ts: float
    origen: str
    destino: str
    puerto_origen: int
    puerto_destino: int
    ipid: int
    longitud_ip: int
    seq: int
    ack: int
    flags: int
    carga: int
    vlan: int | None

    @property
    def identidad(self):
        return (self.origen, self.destino, self.puerto_origen,
                self.puerto_destino, self.ipid, self.longitud_ip,
                self.seq, self.ack, self.flags)


def tramas(ruta: Path):
    """Devuelve (instante, bytes, posición); rechaza archivos incompletos."""
    ruta = Path(ruta)
    posicion = 0
    try:
        with (gzip.open(ruta, "rb") if ruta.suffix == ".gz" else ruta.open("rb")) as f:
            cab = f.read(24)
            posicion = len(cab)
            if len(cab) != 24:
                raise PcapDañado(ruta, 0, "cabecera global truncada")
            magic = cab[:4]
            formatos = {b"\xd4\xc3\xb2\xa1": ("<", 1e6),
                        b"\xa1\xb2\xc3\xd4": (">", 1e6),
                        b"\x4d\x3c\xb2\xa1": ("<", 1e9),
                        b"\xa1\xb2\x3c\x4d": (">", 1e9)}
            if magic not in formatos:
                raise PcapDañado(ruta, 0, "magic PCAP inválido")
            endian, escala = formatos[magic]
            _, mayor, menor, _, _, snaplen, red = struct.unpack(endian + "IHHIIII", cab)
            if (mayor, menor) != (2, 4) or red != 1 or not 0 < snaplen <= 0x4000000:
                raise PcapDañado(ruta, 0, "cabecera PCAP inválida o enlace no Ethernet")
            while True:
                inicio = posicion
                rec = f.read(16)
                posicion += len(rec)
                if not rec:
                    break
                if len(rec) != 16:
                    raise PcapDañado(ruta, inicio, "cabecera de registro truncada")
                segundos, fraccion, incluido, original = struct.unpack(endian + "IIII", rec)
                if fraccion >= escala or incluido > snaplen or original < incluido:
                    raise PcapDañado(ruta, inicio, "registro PCAP inválido")
                datos = f.read(incluido)
                posicion += len(datos)
                if len(datos) != incluido:
                    raise PcapDañado(ruta, inicio, "registro final truncado")
                yield segundos + fraccion / escala, datos, inicio
    except (OSError, EOFError, zlib.error) as exc:
        raise PcapDañado(ruta, posicion, f"lectura o gzip roto: {exc}") from exc


def tcp(ts: float, datos: bytes) -> Paquete | None:
    if len(datos) < 14:
        return None
    tipo = struct.unpack_from("!H", datos, 12)[0]
    pos, vlan = 14, None
    for _ in range(2):
        if tipo not in (0x8100, 0x88a8):
            break
        if len(datos) < pos + 4:
            return None
        vlan = struct.unpack_from("!H", datos, pos)[0] & 0x0fff
        tipo = struct.unpack_from("!H", datos, pos + 2)[0]
        pos += 4
    if tipo != 0x0800 or len(datos) < pos + 20 or datos[pos] >> 4 != 4:
        return None
    ihl = (datos[pos] & 15) * 4
    largo = struct.unpack_from("!H", datos, pos + 2)[0]
    if ihl < 20 or largo < ihl + 20 or len(datos) < pos + largo or datos[pos + 9] != 6:
        return None
    if struct.unpack_from("!H", datos, pos + 6)[0] & 0x3fff:
        return None
    ipid = struct.unpack_from("!H", datos, pos + 4)[0]
    origen = str(ipaddress.IPv4Address(datos[pos + 12:pos + 16]))
    destino = str(ipaddress.IPv4Address(datos[pos + 16:pos + 20]))
    c = pos + ihl
    po, pd, seq, ack = struct.unpack_from("!HHII", datos, c)
    off = (datos[c + 12] >> 4) * 4
    if off < 20 or ihl + off > largo:
        return None
    return Paquete(ts, origen, destino, po, pd, ipid, largo, seq, ack,
                   datos[c + 13], largo - ihl - off, vlan)
