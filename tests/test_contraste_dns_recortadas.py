"""Tramas recortadas por el snaplen en contraste_dns.py (revisión del 26-nov).

El extracto publicado deja la gestión bastión↔Sensor1 en 96 B. Una trama recortada cuya
cabecera excluye DNS no es «ilegible»; una recortada que podría ser DNS, o una dañada sin
recorte declarado, sí lo es.
"""
import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "captura"))
import contraste_dns as c  # noqa: E402


def ipv4(proto, carga, src="10.10.10.30", dst="10.10.60.11"):
    return b"\0" * 12 + b"\x08\x00" + struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(carga), 1, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst)) + carga


def escribir(ruta, tramas):
    """tramas: (datos, longitud_original)."""
    with open(ruta, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, (datos, original) in enumerate(tramas):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(datos), original))
            f.write(datos)


@pytest.fixture(autouse=True)
def limpiar():
    c.ILEGIBLES.clear()
    c.RECORTADAS_NO_DNS[0] = 0
    yield
    c.ILEGIBLES.clear()
    c.RECORTADAS_NO_DNS[0] = 0


def test_tcp_recortado_no_es_ilegible(tmp_path):
    tcp = ipv4(6, struct.pack("!HH", 22, 50000) + b"\0" * 1400)
    escribir(tmp_path / "a.pcap", [(tcp[:96], len(tcp))])
    assert c.leer_pcap([tmp_path / "a.pcap"], {"10.10.20.21"}) == []
    assert c.ILEGIBLES == [] and c.RECORTADAS_NO_DNS[0] == 1


def test_udp_no_dns_recortado_no_es_ilegible(tmp_path):
    udp = ipv4(17, struct.pack("!HHHH", 5000, 6000, 1408, 0) + b"\0" * 1400)
    escribir(tmp_path / "a.pcap", [(udp[:96], len(udp))])
    c.leer_pcap([tmp_path / "a.pcap"], {"10.10.20.21"})
    assert c.ILEGIBLES == [] and c.RECORTADAS_NO_DNS[0] == 1


def test_udp_53_recortado_si_es_ilegible(tmp_path):
    udp = ipv4(17, struct.pack("!HHHH", 40000, 53, 1408, 0) + b"\0" * 1400,
               src="10.10.20.21", dst="10.10.10.20")
    escribir(tmp_path / "a.pcap", [(udp[:96], len(udp))])
    c.leer_pcap([tmp_path / "a.pcap"], {"10.10.20.21"})
    assert len(c.ILEGIBLES) == 1 and c.RECORTADAS_NO_DNS[0] == 0


def test_trama_danada_sin_recorte_declarado_sigue_ilegible(tmp_path):
    tcp = ipv4(6, struct.pack("!HH", 22, 50000) + b"\0" * 1400)
    escribir(tmp_path / "a.pcap", [(tcp[:96], 96)])      # original = incluido: no hubo snaplen
    c.leer_pcap([tmp_path / "a.pcap"], {"10.10.20.21"})
    assert len(c.ILEGIBLES) == 1 and c.RECORTADAS_NO_DNS[0] == 0
