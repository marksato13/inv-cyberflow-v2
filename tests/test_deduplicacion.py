"""Conteos de deduplicación (deduplicar_v2) directa y mediante el cierre real del extractor."""
import socket
import struct
import unittest
from collections import Counter

from extraccion import extraer_v2 as ex

dv2 = ex.dv2


def trama(ts, ipid=1, vlan=20, ttl=64, seq=1, destino="10.10.30.10", ack=0, flags=24):
    eth = b"\xaa" * 6 + bytes([vlan]) * 6 + struct.pack("!HHH", 0x8100, vlan, 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, ipid, 0, ttl, 6, 0,
                     socket.inet_aton("10.10.20.21"), socket.inet_aton(destino))
    tcp = struct.pack("!HHIIBBHHH", 50000, 443, seq, ack, 0x50, flags, 4096, 0, 0)
    return ts, eth + ip + tcp


def contexto(*a, **k):
    return dv2.parse_con_contexto_v2(*trama(*a, **k))


class DeduplicacionTest(unittest.TestCase):
    def comprobar(self, nombre, contextos, esperados, ttl=None, instante=None):
        self.assertTrue(all(x is not None for x in contextos), nombre)
        directos, quitados = dv2.deduplicar_espejo_v2(contextos)
        cuentas = Counter()
        reales, pendientes = ex.finalizar_pendientes(contextos, 200, cuentas)
        self.assertEqual(pendientes, [], nombre)
        self.assertEqual((len(directos), quitados), (esperados, len(contextos) - esperados), nombre)
        self.assertEqual((len(reales), cuentas["copias_espejo_quitadas"]), (esperados, quitados), nombre)
        self.assertEqual(reales, directos, nombre)
        if ttl is not None:
            self.assertEqual(reales[0].ttl, ttl, nombre)
        if instante is not None:
            self.assertEqual(reales[0].timestamp, instante, nombre)
        return directos

    def test_lee_el_ack(self):
        self.assertEqual(contexto(100, ack=123456).tcp_ack, 123456)

    def test_dos_copias_conserva_ttl_e_instante(self):
        self.comprobar("dos copias", [contexto(100, vlan=20, ttl=64), contexto(100.0002, vlan=30, ttl=63)], 1, 64, 100)
        inversos = [contexto(101, vlan=30, ttl=63), contexto(101.0002, vlan=20, ttl=64)]
        directos = self.comprobar("mayor TTL posterior", inversos, 1, 64, 101.0002)
        self.assertIs(directos[0], inversos[1].packet)

    def test_tres_ipid_distintos(self):
        self.comprobar("tres eventos", [contexto(100 + i * .001, ipid=i) for i in range(3)], 3)

    def test_retransmision_ipid_distinto(self):
        self.comprobar("retransmisión", [contexto(100, ipid=1, seq=10), contexto(100.001, ipid=2, seq=10)], 2)

    def test_misma_vlan_y_ttl_es_otra_transmision(self):
        self.comprobar("repetición en la misma VLAN", [contexto(100), contexto(100.001)], 2)

    def test_dos_rst_identicos_dan_dos_transmisiones(self):
        # E3: el cliente envía dos RST idénticos (ipid 0) a la vez; el espejo enseña 4 tramas
        rst = dict(ipid=0, flags=0x14)
        c = [contexto(100, vlan=20, ttl=64, **rst), contexto(100.00001, vlan=20, ttl=64, **rst),
             contexto(100.0002, vlan=30, ttl=63, **rst), contexto(100.00021, vlan=30, ttl=63, **rst)]
        self.comprobar("RST idénticos", c, 2, 64)
        # V1 los fundía en uno (lo que corrige esta versión)
        v1 = [ex.v3.parse_con_contexto(*trama(100 + d, vlan=v, ttl=t, **rst))
              for d, v, t in ((0, 20, 64), (0.00001, 20, 64), (0.0002, 30, 63), (0.00021, 30, 63))]
        self.assertEqual(len(ex.v3.deduplicar_espejo(v1)[0]), 1)

    def test_copias_a_mas_de_5_ms_dentro_de_20_ms(self):
        self.comprobar("copia a 5,1 ms", [contexto(100, vlan=20, ttl=64), contexto(100.0051, vlan=30, ttl=63)], 1, 64)
        self.comprobar("copia a 19 ms", [contexto(100, vlan=20, ttl=64), contexto(100.019, vlan=30, ttl=63)], 1)

    def test_fuera_de_la_ventana_de_20_ms(self):
        self.comprobar("a 25 ms", [contexto(100, vlan=20, ttl=64), contexto(100.025, vlan=30, ttl=63)], 2)

    def test_ttl_a_mas_de_1_no_es_copia(self):
        self.comprobar("ΔTTL 2", [contexto(100, vlan=20, ttl=64), contexto(100.0002, vlan=30, ttl=62)], 2)

    def test_ack_o_flags_distintos_no_son_copia(self):
        self.comprobar("ACK distinto", [contexto(100, ack=1), contexto(100.001, vlan=30, ttl=63, ack=2)], 2)
        self.comprobar("flags distintos", [contexto(100, flags=0x10), contexto(100.001, vlan=30, ttl=63, flags=0x18)], 2)

    def test_difusion_dos_copias_identicas(self):
        b = dict(vlan=20, destino="255.255.255.255")
        self.comprobar("difusión", [contexto(100, **b), contexto(100.0001, **b)], 1, 64, 100)
        self.comprobar("difusión ×3", [contexto(100, **b), contexto(100.0001, **b), contexto(100.0002, **b)], 2)

    def test_cierre_con_espera_de_20_ms(self):
        # la copia a 15 ms del corte todavía no se cierra con el corte del extractor (ancla − 20 ms)
        c = [contexto(100, vlan=20, ttl=64), contexto(100.015, vlan=30, ttl=63)]
        cuentas = Counter()
        cerrados, pendientes = ex.finalizar_pendientes(c, 100.0 + 0.010, cuentas)
        self.assertEqual((len(cerrados), cuentas["copias_espejo_quitadas"]), (1, 1))
        self.assertEqual(pendientes, [])


if __name__ == "__main__":
    unittest.main()
