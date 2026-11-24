"""PCAP libpcap sintéticos con etiquetas 802.1Q para la extracción V2."""
import csv
import ipaddress
import json
import socket
import struct
import shutil
import unittest
import uuid
from pathlib import Path

from extraccion import extraer_v2 as ex
from extraccion import verificar_v2 as ver


def trama(ts, src, dst, sport, dport, ipid, vlan=20, ttl=64, seq=1, flags=2, payload=b""):
    iplen = 20 + 20 + len(payload)
    eth = b"\x00" * 12 + struct.pack("!HHH", 0x8100, vlan, 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, iplen, ipid, 0, ttl, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 4096, 0, 0)
    return ts, eth + ip + tcp + payload


def pcap(path, frames):
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            out.write(struct.pack("<IIII", sec, round((ts - sec) * 1_000_000), len(frame), len(frame)))
            out.write(frame)


class ExtraccionTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent / (".extraccion-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.archivo = self.root / "ejecucion-1"
        (self.archivo / "pcap").mkdir(parents=True)
        (self.archivo / "eve").mkdir()
        self.pop = {"10.10.20.21"}

    def preparar(self, doble=False, gestion=False, frontera=False):
        c, s, b = "10.10.20.21", "10.10.30.10", "10.10.10.30"
        base = [trama(100.1, c, s, 50000, 443, 1),
                trama(100.2, s, c, 443, 50000, 2, vlan=30, flags=18),
                trama(115.1, c, s, 50000, 443, 3, seq=2, flags=24, payload=b"abc"),
                trama(170.1, c, s, 50000, 443, 4, seq=2, flags=24, payload=b"def")]
        if frontera:
            base.append(trama(155.1, c, s, 50001, 443, 6))
        if gestion:
            base.append(trama(105.1, b, s, 40000, 22, 9))
        base.sort(key=lambda x: x[0])
        if doble:
            copias = []
            for ts, frame in base:
                copias.append((ts, frame))
                # La copia de salida cambia sólo VLAN y TTL.
                otro = bytearray(frame)
                otro[14:16] = struct.pack("!H", 30)
                otro[26] -= 1
                copias.append((ts + 0.0001, bytes(otro)))
            base = copias
        pcap(self.archivo / "pcap" / "live-0001.pcap", [x for x in base if x[0] < 150])
        pcap(self.archivo / "pcap" / "live-0002.pcap", [x for x in base if x[0] >= 150])
        events = [{"timestamp": ex.utc(105.0), "event_type": "http", "src_ip": c,
                   "dest_ip": s, "http": {"status": 200, "http_method": "GET"}},
                  {"timestamp": ex.utc(165.0), "event_type": "tls", "src_ip": c,
                   "dest_ip": s, "flow_id": 1, "tls": {"version": "TLS 1.3"}}]
        if gestion:
            events.append({"timestamp": ex.utc(106.0), "event_type": "http", "src_ip": b,
                           "dest_ip": s, "http": {"status": 500}})
        (self.archivo / "eve" / "eve-1.json").write_text("".join(json.dumps(e) + "\n" for e in sorted(events, key=lambda e: e["timestamp"])))

    def extraer(self, nombre, fronteras=()):
        salida = self.root / nombre
        resumen = ex.procesar(self.archivo, salida, self.pop, list(fronteras))
        with (salida / "filas.csv").open(newline="", encoding="utf-8") as f:
            filas = list(csv.DictReader(f))
        return salida, resumen, filas

    def test_poblacion_descarta_gestion_antes_de_atribuir(self):
        self.preparar()
        _, _, base = self.extraer("base")
        self.preparar(gestion=True)
        salida, resumen, filas = self.extraer("gestion")
        self.assertEqual(base, filas)
        self.assertEqual(resumen["paquetes_descartados_poblacion"], 1)
        self.assertEqual({r["ip"] for r in filas}, self.pop)
        inv = json.loads((salida / "inventario_ips.json").read_text())
        self.assertEqual(next(i["regla"] for i in inv if i["ip"] == "10.10.10.30"), "gestion_excluida")

    def test_espejo_una_o_dos_copias(self):
        self.preparar()
        _, _, base = self.extraer("una")
        self.preparar(doble=True)
        _, resumen, doble = self.extraer("dos")
        self.assertEqual(base, doble)
        self.assertEqual(resumen["copias_espejo_quitadas"], 4)

    def test_frontera_no_mezcla_bloques_y_marca(self):
        self.preparar(frontera=True)
        _, _, filas = self.extraer("particion", (160.0,))
        f = next(r for r in filas if r["ventana_fin"] == ex.utc(170))
        self.assertEqual(f["bloque"], "1")
        self.assertIn("frontera", f["motivo_marca"])
        self.assertEqual(f["n_paquetes_ventana"], "0")
        self.assertEqual(float(f["flow_attempt_rate_10s"]), 0)

    def test_sin_futuro_y_paridad_motor(self):
        self.preparar()
        salida, _, filas = self.extraer("verificada")
        informe = ver.verificar(self.archivo, salida, self.pop, [], max_filas=None)
        self.assertTrue(informe["esquema_ok"])
        self.assertTrue(informe["sin_futuro_ok"])
        self.assertTrue(informe["paridad_motor_ok"])
        self.assertEqual(informe["filas_verificadas"], len(filas))
        # El último paquete del flujo sigue atribuido al iniciador y usa su inicio real.
        f = next(r for r in filas if r["ventana_fin"] == ex.utc(180))
        self.assertGreater(float(f["flow_duration_mean_30s"]), 60)
        self.assertEqual(float(f["tcp_retransmission_ratio_10s"]), 1.0)

    def test_tramos_igual_a_procesado_completo(self):
        self.preparar()
        _, _, filas = self.extraer("tramos")
        for row in filas:
            anchor = ex.v2.parse_eve_timestamp(row["ventana_fin"])
            completa = ver.referencia(self.archivo, row["ip"], anchor, self.pop, [])
            for name in ex.v2.FEATURE_NAMES:
                self.assertAlmostEqual(float(row[name]), completa[name], places=10,
                                       msg=f"{name} en {row['ventana_fin']}")

    def test_copia_posterior_al_cierre_no_modifica_fila_anterior(self):
        c, s = "10.10.20.21", "10.10.30.10"
        antes = trama(109.9999, c, s, 50000, 443, 12, ttl=63)
        despues = trama(110.0001, c, s, 50000, 443, 12, vlan=30, ttl=64)
        pcap(self.archivo / "pcap" / "live-0001.pcap", [antes, despues])
        (self.archivo / "eve" / "eve-1.json").write_text("")
        salida, resumen, filas = self.extraer("cierre")
        f110 = next(r for r in filas if r["ventana_fin"] == ex.utc(110))
        self.assertEqual(float(f110["packet_rate_10s"]), 0.1)
        self.assertEqual(float(f110["ttl_mean_10s"]), 63)
        self.assertEqual(resumen["copias_espejo_quitadas"], 1)
        self.assertTrue(ver.verificar(self.archivo, salida, self.pop, [])["sin_futuro_ok"])


if __name__ == "__main__":
    unittest.main()
