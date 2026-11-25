"""Analizador del registrador DNS de DC1: consulta, respuesta A con compresión y NXDOMAIN."""
import socket
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "servidor"))
import registro_dns_v2 as r  # noqa: E402


def qname(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def mensaje(ident, flags, nombre, respuestas=()):
    m = struct.pack("!HHHHHH", ident, flags, 1, len(respuestas), 0, 0) + qname(nombre) + struct.pack("!HH", 1, 1)
    for ip in respuestas:
        m += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return m


def trama(src, sp, dst, dp, carga, vlan=None):
    udp = struct.pack("!HHHH", sp, dp, 8 + len(carga), 0) + carga
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    eth = b"\x00" * 12 + ((b"\x81\x00" + struct.pack("!H", vlan)) if vlan else b"") + b"\x08\x00"
    return eth + ip


class TestRegistroDNS(unittest.TestCase):
    def test_consulta_y_respuesta(self):
        q = r.analizar_dns(mensaje(0x1234, 0x0100, "portal.cf-v2.lab"))
        self.assertEqual((q["id"], q["respuesta"], q["nombre"], q["tipo"]), (0x1234, False, "portal.cf-v2.lab", "A"))
        a = r.analizar_dns(mensaje(0x1234, 0x8180, "portal.cf-v2.lab", ["10.10.30.10"]))
        self.assertEqual((a["respuesta"], a["rcode"], a["a"]), (True, "NOERROR", ["10.10.30.10"]))
        self.assertEqual(a["ttl"], [60])

    def test_pcap_nanosegundos(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "x.pcap")
            w = r.Pcap(ruta)
            w.escribir(1764000000.123456789, b"\x00" * 60)
            w.f.close()
            b = open(ruta, "rb").read()
            self.assertEqual(struct.unpack("<I", b[:4])[0], 0xA1B23C4D)
            seg, ns, n1, n2 = struct.unpack("<IIII", b[24:40])
            self.assertEqual((seg, n1, n2), (1764000000, 60, 60))
            self.assertAlmostEqual(ns, 123456789, delta=1000)

    def test_nxdomain(self):
        a = r.analizar_dns(mensaje(7, 0x8183, "noexiste.cf-v2.lab"))
        self.assertEqual((a["rcode"], a["n_respuestas"], a["a"]), ("NXDOMAIN", 0, []))

    def test_trama_con_y_sin_vlan(self):
        c = mensaje(9, 0x0100, "wiki.cf-v2.lab")
        for v in (None, 20):
            src, sp, dst, dp, carga = r.analizar_trama(trama("10.10.20.21", 40000, "10.10.10.20", 53, c, v))
            self.assertEqual((src, sp, dst, dp, carga), ("10.10.20.21", 40000, "10.10.10.20", 53, c))
        self.assertIsNone(r.analizar_trama(trama("10.10.20.21", 40000, "10.10.10.20", 80, c)))


if __name__ == "__main__":
    unittest.main()
