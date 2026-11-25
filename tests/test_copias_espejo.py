"""Casos de resultado conocido para la comprobación SPAN."""
import gzip
import json
import shutil
import socket
import struct
import unittest
import uuid
from pathlib import Path

from captura import copias_espejo as ce


CLIENTE = "10.10.20.21"
SERVIDOR = "10.10.30.10"


def trama(ts, origen=CLIENTE, destino=SERVIDOR, ipid=1, vlan=20, ttl=64,
          seq=1, flags=24, payload=b"abc"):
    iplen = 40 + len(payload)
    eth = b"\x00" * 6 + bytes([vlan]) * 6 + struct.pack("!HHH", 0x8100, vlan, 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, iplen, ipid, 0, ttl, 6, 0,
                     socket.inet_aton(origen), socket.inet_aton(destino))
    tcp = struct.pack("!HHIIBBHHH", 50000, 443, seq, 0, 0x50, flags, 4096, 0, 0)
    return ts, eth + ip + tcp + payload


def pcap(ruta, tramas):
    with ruta.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, dato in tramas:
            s = int(ts)
            f.write(struct.pack("<IIII", s, round((ts - s) * 1e6), len(dato), len(dato)))
            f.write(dato)


class CopiasEspejoTest(unittest.TestCase):
    def setUp(self):
        self.raiz = Path(__file__).resolve().parent / (".copias-" + uuid.uuid4().hex)
        self.pcap_dir = self.raiz / "captura" / "pcap"
        self.pcap_dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.raiz)
        self.fichero = self.pcap_dir / "live-20250101000000.pcap"

    def analizar(self, tramas, **opciones):
        pcap(self.fichero, tramas)
        return ce.analizar(self.pcap_dir, **opciones)

    def clases(self, resultado):
        return resultado["denominadores"]["eventos_por_clase"]

    def test_completa_y_orden_ttl(self):
        r = self.analizar([trama(100, vlan=20), trama(100.0002, vlan=30, ttl=63)])
        self.assertEqual(self.clases(r), {"completo": 1})
        self.assertEqual(r["denominadores"]["tramas_leidas"], 2)
        self.assertEqual(r["separaciones_copias_s"]["pares"], 1)
        self.assertAlmostEqual(r["separaciones_copias_s"]["max"], .0002, places=5)
        self.assertEqual(r["indicios"], {"ttl_incorrecto": 0, "orden_incorrecto": 0,
                                         "carga_distinta": 0, "mac_igual": 0})

    def test_falta_copia_y_sistematica(self):
        r = self.analizar([trama(100 + i, ipid=i) for i in range(3)])
        self.assertEqual(self.clases(r), {"falta_copia": 3})
        self.assertEqual(r["por_vlan_faltante"], {"30": 3})
        ruta = r["por_ruta"]["10.10.20.0/24>10.10.30.0/24"]
        self.assertEqual(ruta["clases"], {"falta_copia": 3})
        self.assertEqual(ruta["fraccion_falta_por_vlan"], {"30": 1.0})
        self.assertEqual(len(r["eventos_por_segundo"]), 3)
        self.assertEqual(r["anomalias_total"], 3)
        self.assertEqual(r["anomalias"][0]["vlans_faltan"], [30])

    def test_vlan_incorrecta_y_copias_de_mas(self):
        r = self.analizar([trama(100), trama(100.0001, vlan=20, ttl=63),
                          trama(101, ipid=2), trama(101.0001, ipid=2, vlan=30, ttl=63),
                          trama(101.0002, ipid=2, vlan=30, ttl=63)])
        # la tercera trama (VLAN 30, TTL 63) repite (VLAN, TTL): o es una copia de más o es otra
        # transmisión sin su copia de VLAN 20; no se puede distinguir → ambiguo, no se oculta
        self.assertEqual(self.clases(r), {"vlan_incorrecta": 1, "completo": 1, "ambiguo": 1})
        self.assertEqual(r["indicios"]["orden_incorrecto"], 1)

    def test_transmisiones_identicas_no_se_funden(self):
        # E3: el cliente envía dos RST idénticos (ipid 0) en el mismo instante; llegan 4 copias
        r = self.analizar([trama(100, ipid=0, flags=4, payload=b""), trama(100, ipid=0, flags=4, payload=b""),
                          trama(100.0001, ipid=0, vlan=30, ttl=63, flags=4, payload=b""),
                          trama(100.0001, ipid=0, vlan=30, ttl=63, flags=4, payload=b"")])
        self.assertEqual(self.clases(r), {"completo": 2})

    def test_copias_separadas_mas_de_5_ms(self):
        # E3: bajo ráfaga la segunda copia llegó 5,1 ms después de la primera
        r = self.analizar([trama(100), trama(100.0051, vlan=30, ttl=63)])
        self.assertEqual(self.clases(r), {"completo": 1})

    def test_indicios_no_cambian_clase(self):
        r = self.analizar([trama(100, vlan=20, ttl=64, payload=b"abc"),
                          trama(100.0001, vlan=30, ttl=64, payload=b"xyz")])
        self.assertEqual(self.clases(r), {"completo": 1})
        self.assertEqual(r["indicios"]["ttl_incorrecto"], 1)
        self.assertEqual(r["indicios"]["carga_distinta"], 1)

    def test_ambas_copias_perdidas_con_referencia(self):
        pcap(self.fichero, [])
        ref = self.raiz / "extremo.pcap"
        pcap(ref, [trama(100)])
        sin = ce.analizar(self.pcap_dir)
        con = ce.analizar(self.pcap_dir, referencia=ref)
        self.assertEqual(sin["denominadores"]["eventos"], 0)
        self.assertEqual(con["referencia"]["eventos_vistos"], 1)
        self.assertEqual(con["referencia"]["eventos_sin_copia_sensor"], 1)

    def test_repeticiones_y_ambiguedad(self):
        r = self.analizar([trama(100), trama(100.0001, vlan=30, ttl=63),
                          trama(100.02), trama(100.0201, vlan=30, ttl=63),
                          trama(101, ipid=2), trama(101.006, ipid=2)])
        self.assertEqual(self.clases(r), {"completo": 2, "ambiguo": 2})
        self.assertEqual(r["denominadores"]["eventos"], 4)

    def test_rutas_especiales(self):
        r = self.analizar([
            trama(100, destino="10.10.20.1"),
            trama(101, destino="10.10.20.22", ipid=2),
            trama(102, destino="255.255.255.255", ipid=3),
            trama(103, destino="8.8.8.8", ipid=4)])
        self.assertEqual(self.clases(r), {"completo": 1, "inesperado": 1,
                                          "no_determinable": 2})

    def test_inventario_ausente_y_salida_tres(self):
        pcap(self.fichero, [])
        inventario = self.raiz / "captura" / "inventario.jsonl"
        registros = [{"fichero": self.fichero.name, "primer_paquete_epoch": 100,
                      "ultimo_paquete_epoch": 104},
                     {"fichero": "live-20250101000005.pcap", "primer_paquete_epoch": 105,
                      "ultimo_paquete_epoch": 109}]
        inventario.write_text("".join(json.dumps(x) + "\n" for x in registros))
        r = ce.analizar(self.pcap_dir)
        self.assertFalse(r["entrada_completa"])
        self.assertEqual(r["resultado_global"], "incompleto")
        self.assertEqual(r["integridad_entrada"]["problemas"][0]["tipo"], "ausente")
        self.assertEqual(r["integridad_entrada"]["problemas"][0]["ultimo_paquete_epoch"], 109)
        salida = self.raiz / "resultado.json"
        self.assertEqual(ce.main([str(self.pcap_dir), "--salida", str(salida),
                                  "--detalle-umbral", "0"]), 3)

    def test_gzip_y_registro_truncados(self):
        pcap(self.fichero, [trama(100)])
        gz = self.pcap_dir / "live-20250101000005.pcap.gz"
        gz.write_bytes(gzip.compress(self.fichero.read_bytes())[:-5])
        corto = self.pcap_dir / "live-20250101000010.pcap"
        corto.write_bytes(self.fichero.read_bytes()[:-2])
        r = ce.analizar(self.pcap_dir)
        self.assertFalse(r["entrada_completa"])
        self.assertEqual({x["tipo"] for x in r["integridad_entrada"]["problemas"]},
                         {"ilegible", "truncado"})

    def test_cabecera_invalida_y_filtro_subred(self):
        r = self.analizar([trama(100, origen="10.10.20.22"),
                          trama(101, origen=CLIENTE, ipid=2)],
                         subredes=["10.10.20.0/24"], desde=100.5)
        self.assertEqual(r["denominadores"]["tramas_leidas"], 2)
        self.assertEqual(r["denominadores"]["tramas_en_poblacion"], 1)
        malo = self.pcap_dir / "live-20250101000015.pcap"
        malo.write_bytes(b"cabecera invalida")
        r = ce.analizar(self.pcap_dir)
        self.assertEqual(r["integridad_entrada"]["problemas"][0]["tipo"], "ilegible")


if __name__ == "__main__":
    unittest.main()
