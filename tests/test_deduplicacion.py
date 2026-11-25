"""Conteos de deduplicación directa y mediante el cierre real del extractor."""
import socket
import struct
import unittest
from collections import Counter

from extraccion import extraer_v2 as ex


def contexto(ts, ipid=1, vlan=20, ttl=64, seq=1, destino="10.10.30.10", ack=0):
    eth = b"\xaa" * 6 + bytes([vlan]) * 6 + struct.pack("!HHH", 0x8100, vlan, 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, ipid, 0, ttl, 6, 0,
                     socket.inet_aton("10.10.20.21"), socket.inet_aton(destino))
    tcp = struct.pack("!HHIIBBHHH", 50000, 443, seq, ack, 0x50, 24, 4096, 0, 0)
    return ex.v3.parse_con_contexto(ts, eth + ip + tcp)


class DeduplicacionTest(unittest.TestCase):
    def comprobar(self, nombre, contextos, esperados, ttl=None, instante=None):
        self.assertTrue(all(x is not None for x in contextos), nombre)
        directos, quitados = ex.v3.deduplicar_espejo(contextos)
        cuentas = Counter()
        reales, pendientes = ex.finalizar_pendientes(contextos, 200, cuentas)
        self.assertEqual(pendientes, [], nombre)
        self.assertEqual((len(contextos), len(directos), quitados),
                         (len(contextos), esperados, len(contextos) - esperados), nombre)
        self.assertEqual((len(reales), cuentas["copias_espejo_quitadas"]),
                         (esperados, quitados), nombre)
        self.assertEqual(reales, directos, nombre)
        if ttl is not None:
            self.assertEqual(reales[0].ttl, ttl, nombre)
        if instante is not None:
            self.assertEqual(reales[0].timestamp, instante, nombre)

    def test_dos_copias_conserva_ttl_e_instante(self):
        originales = [contexto(100, vlan=20, ttl=64),
                      contexto(100.0002, vlan=30, ttl=63)]
        self.comprobar("dos copias", originales, 1, 64, 100)
        inversos = [contexto(101, vlan=30, ttl=63),
                    contexto(101.0002, vlan=20, ttl=64)]
        self.comprobar("mayor TTL posterior", inversos, 1, 64, 101.0002)
        self.assertIs(ex.v3.deduplicar_espejo(inversos)[0][0], inversos[1].packet)
        self.assertEqual(inversos[1].vlan, 20)

    def test_tres_ipid_distintos(self):
        self.comprobar("tres eventos", [contexto(100 + i * .001, ipid=i)
                                       for i in range(3)], 3)

    def test_retransmision_ipid_distinto(self):
        self.comprobar("retransmisión", [contexto(100, ipid=1, seq=10),
                                       contexto(100.001, ipid=2, seq=10)], 2)

    def test_mismo_evento_fuera_de_ventana(self):
        self.comprobar("repetición tardía", [contexto(100), contexto(100.006)], 2)

    def test_difusion_duplicada(self):
        self.comprobar("difusión", [contexto(100, vlan=20, destino="255.255.255.255"),
                                    contexto(100.0001, vlan=20, destino="255.255.255.255")],
                       1, 64, 100)

    def test_colision_de_clave_ack_distinto(self):
        # Documenta una limitación de V1: son dos paquetes distintos, pero se unen.
        self.comprobar("ACK distinto", [contexto(100, ack=1),
                                       contexto(100.001, ack=2)], 1)


if __name__ == "__main__":
    unittest.main()
