"""Resultados conocidos del contraste extremo ↔ Sensor1."""
import gzip
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "captura"))
import comparar_extremo as cmp  # noqa: E402
from lector_pcap import PcapDañado, tcp, tramas  # noqa: E402

SERVIDOR = "10.10.30.10"
CLIENTE = "10.10.20.21"


def ip_bytes(ip):
    return bytes(map(int, ip.split(".")))


def trama(ts, origen=CLIENTE, destino=SERVIDOR, po=50000, pd=80,
          seq=100, ack=0, flags=0x10, carga=0, ipid=1, vlan=None):
    iplen = 40 + carga
    tcp = struct.pack("!HHIIHHHH", po, pd, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, iplen, ipid, 0, 64, 6, 0,
                     ip_bytes(origen), ip_bytes(destino))
    eth = b"\0" * 12
    if vlan is None:
        eth += b"\x08\x00"
    else:
        eth += struct.pack("!HHH", 0x8100, vlan, 0x0800)
    return ts, eth + ip + tcp + b"x" * carga


def pcap(filas, nano=False):
    cab = struct.pack("<IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4,
                      2, 4, 0, 0, 65535, 1)
    escala = 1_000_000_000 if nano else 1_000_000
    for ts, datos in filas:
        segundos = int(ts)
        frac = round((ts - segundos) * escala)
        cab += struct.pack("<IIII", segundos, frac, len(datos), len(datos)) + datos
    return cab


def base(isn=100, puerto=50000):
    return [trama(10.0, po=puerto, seq=isn, flags=2, ipid=1),
            trama(10.1, origen=SERVIDOR, destino=CLIENTE, po=80, pd=puerto,
                  seq=900, ack=isn + 1, flags=0x12, ipid=2),
            trama(10.2, po=puerto, seq=isn + 1, ack=901, flags=0x10, ipid=3),
            trama(10.3, po=puerto, seq=isn + 1, ack=901, carga=12, ipid=4),
            trama(10.4, origen=SERVIDOR, destino=CLIENTE, po=80, pd=puerto,
                  seq=901, ack=isn + 13, carga=7, ipid=5),
            trama(10.5, po=puerto, seq=isn + 13, ack=908, flags=0x11, ipid=6)]


def sensor_de(filas, desfase=0):
    resultado = []
    for ts, datos in filas:
        # Las dos copias tienen la misma cabecera IP/TCP; solo cambia la VLAN.
        for vlan, delta in ((20, 0), (30, .0002)):
            resultado.append((ts + desfase + delta,
                              datos[:12] + struct.pack("!HHH", 0x8100, vlan, 0x0800) + datos[14:]))
    return resultado


class CompararExtremo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def correr(self, extremo, sensor, margen=0, gz=False):
        e = self.dir / "extremo.pcap"
        s = self.dir / ("sensor.pcap.gz" if gz else "sensor.pcap")
        salida = self.dir / "salida.json"
        e.write_bytes(pcap(extremo))
        contenido = pcap(sensor, nano=True)
        s.write_bytes(gzip.compress(contenido) if gz else contenido)
        codigo = cmp.main(["--extremo", str(e), "--sensor", str(s),
                           "--salida", str(salida), "--margen-s", str(margen)])
        return codigo, json.loads(salida.read_text(encoding="utf-8"))

    def test_todo_coincide_por_paquete(self):
        filas = base()
        codigo, r = self.correr(filas, sensor_de(filas), gz=True)
        self.assertEqual(codigo, 0)
        self.assertEqual(r["modo"], "paquetes")
        self.assertEqual(r["sensor"]["eventos"], len(filas))
        self.assertEqual(r["sensor"]["copias"], 2 * len(filas))
        self.assertEqual(r["por_clase"]["datos"]["sin_sensor"]["total"], 0)

    def test_rst_identicos_y_copias_a_5_ms(self):
        # E3: dos RST idénticos (ipid 0) del cliente y copias separadas 5,1 ms bajo ráfaga
        filas = base()[:5] + [trama(10.5, seq=113, flags=0x04, ipid=0), trama(10.5, seq=113, flags=0x04, ipid=0)]
        sensor = sensor_de(filas)
        sensor = [(ts + (.0049 if i == 7 else 0), d) for i, (ts, d) in enumerate(sensor)]
        codigo, r = self.correr(filas, sensor)
        self.assertEqual(r["por_clase"]["rst"]["extremo"], 2)
        self.assertEqual(r["por_clase"]["rst"]["sensor"], 2)
        self.assertEqual(r["por_clase"]["datos"]["sin_extremo"]["total"], 0)
        self.assertEqual(codigo, 0, r["discrepancias"])

    def test_dato_sin_evento_sensor(self):
        filas = base()
        codigo, r = self.correr(filas, sensor_de([x for i, x in enumerate(filas) if i != 3]))
        self.assertEqual(codigo, 1)
        self.assertEqual(r["por_clase"]["datos"]["sin_sensor"]["total"], 1)

    def test_copias_no_compensan_syn_distinto(self):
        filas = base() + base(200, 50001)
        # Eliminar el SYN de la segunda conexión por su puerto.
        sensor = sensor_de([x for x in filas if not (x[0] == 10.0 and x[1][34:36] == struct.pack("!H", 50001))])
        codigo, r = self.correr(filas, sensor)
        self.assertEqual(codigo, 1)
        self.assertGreater(r["conexiones_solo_extremo"]["total"], 0)
        self.assertEqual(r["por_clase"]["syn"]["sin_sensor"]["total"], 1)

    def test_retransmision_ausente_en_modo_paquetes(self):
        filas = base() + [trama(10.45, seq=101, ack=901, carga=12, ipid=7)]
        sensor = sensor_de([x for x in filas if x[0] != 10.3])
        codigo, r = self.correr(filas, sensor)
        self.assertEqual(codigo, 1)
        self.assertEqual(r["por_clase"]["datos"]["sin_sensor"]["total"], 1)
        self.assertFalse(r["retransmisiones"]["coinciden"])

    def test_retransmision_no_comprobable_con_offload(self):
        filas = base() + [trama(10.45, seq=101, ack=901, carga=12, ipid=7),
                          trama(10.46, seq=1000, ack=901, carga=2960, ipid=8)]
        sensor = sensor_de([x for x in filas if x[0] not in (10.3, 10.46)])
        sensor += sensor_de([trama(10.46 + i * .001, seq=1000 + i * 1000,
                                   ack=901, carga=1000 if i < 2 else 960,
                                   ipid=8 + i) for i in range(3)])
        codigo, r = self.correr(filas, sensor)
        self.assertEqual(codigo, 0)
        self.assertEqual(r["modo"], "rangos")
        self.assertTrue(any("retransmitidas" in x["aspecto"] for x in r["no_comprobado"]))

    def test_reutilizacion_de_puerto(self):
        filas = base() + [(ts + 1, datos) for ts, datos in base(200)]
        codigo, r = self.correr(filas, sensor_de(filas))
        self.assertEqual(codigo, 0)
        self.assertEqual(r["denominadores"]["conexiones_extremo"], 2)

    def test_conexion_parcial(self):
        filas = [trama(10.2, seq=101, ack=901, carga=12, ipid=4),
                 trama(10.3, seq=113, ack=901, carga=5, ipid=5)]
        codigo, r = self.correr(filas, sensor_de(filas))
        self.assertEqual(codigo, 0)
        self.assertEqual(r["parciales_extremo"]["total"], 1)
        self.assertEqual(r["parciales_extremo"]["detalles"][0]["eventos"]["total"], 2)

    def test_desfase_constante(self):
        filas = base()
        # Tramas de guarda amplían el periodo común sin entrar en el contraste.
        guardas = [trama(9, pd=9999), trama(12, pd=9999)]
        codigo, r = self.correr(guardas + filas, sensor_de(guardas + filas, .003))
        self.assertEqual(codigo, 0)
        self.assertAlmostEqual(r["desfases"]["estimado_s"], .003, places=5)

    def test_offload_detectado(self):
        filas = base() + [trama(10.45, seq=1000, ack=901, carga=2960, ipid=8)]
        sensor = sensor_de(base() + [trama(10.45 + i * .001,
                                           seq=1000 + i * 1000, ack=901,
                                           carga=1000 if i < 2 else 960,
                                           ipid=8 + i) for i in range(3)])
        codigo, r = self.correr(filas, sensor)
        self.assertEqual(codigo, 0)
        self.assertTrue(r["captura_extremo"]["offload_detectado"])
        self.assertEqual(r["modo"], "rangos")
        self.assertGreater(r["transmisiones_verificadas_en_rangos"], 0)

    def test_entradas_truncadas_codigo_3(self):
        filas = base()
        e = self.dir / "extremo.pcap"
        s = self.dir / "sensor.pcap.gz"
        out = self.dir / "salida.json"
        e.write_bytes(pcap(filas))
        s.write_bytes(gzip.compress(pcap(sensor_de(filas)))[:-3])
        args = ["--extremo", str(e), "--sensor", str(s), "--salida", str(out)]
        self.assertEqual(cmp.main(args), 3)
        self.assertFalse(out.exists())
        s.write_bytes(gzip.compress(pcap(sensor_de(filas))))
        e.write_bytes(pcap(filas)[:-2])
        self.assertEqual(cmp.main(args), 3)
        self.assertFalse(out.exists())

    def test_cabecera_invalida_y_dos_vlan(self):
        ruta = self.dir / "malo.pcap"
        ruta.write_bytes(b"no es pcap" + b"\0" * 20)
        with self.assertRaises(PcapDañado) as exc:
            list(tramas(ruta))
        self.assertIn(str(ruta), str(exc.exception))
        ts, frame = trama(10, vlan=20)
        doble = frame[:12] + struct.pack("!HH", 0x88a8, 20) + frame[12:]
        p = tcp(ts, doble)
        self.assertEqual(p.vlan, 20)
        self.assertEqual(p.puerto_origen, 50000)


if __name__ == "__main__":
    unittest.main()
