"""PCAP libpcap sintéticos con etiquetas 802.1Q para la extracción V2."""
import csv
import ipaddress
import json
import socket
import struct
import sys
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from extraccion import extraer_v2 as ex
from extraccion import verificar_v2 as ver
from extraccion import comparar_modos as comp


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

    def extraer(self, nombre, fronteras=(), estado="continuo"):
        salida = self.root / nombre
        resumen = ex.procesar(self.archivo, salida, self.pop, list(fronteras), estado_modo=estado)
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

    def test_frontera_etiqueta_y_marca(self):
        self.preparar(frontera=True)
        _, _, filas = self.extraer("particion", (160.0,))
        f = next(r for r in filas if r["ventana_fin"] == ex.utc(170))
        self.assertEqual(f["bloque"], "1")
        self.assertIn("frontera", f["motivo_marca"])
        self.assertEqual(f["n_paquetes_ventana"], "0")
        self.assertEqual(float(f["flow_attempt_rate_10s"]), 0)

    def preparar_flujo_cruzado(self):
        c, s = "10.10.20.21", "10.10.30.10"
        frames = [trama(100.1, c, s, 50000, 443, 1),
                  trama(280.1, c, s, 50000, 443, 2, seq=2, flags=24, payload=b"a"),
                  trama(305.1, c, s, 50000, 443, 3, seq=3, flags=24, payload=b"b"),
                  trama(399.1, c, s, 50000, 443, 4, seq=4, flags=24, payload=b"c"),
                  trama(529.1, c, s, 50001, 443, 5),
                  trama(550.1, c, s, 50001, 443, 6, seq=2, flags=24, payload=b"d")]
        pcap(self.archivo / "pcap" / "live-0001.pcap", frames)
        (self.archivo / "eve" / "eve-1.json").write_text("")

    def test_flujo_cruza_frontera_y_compara_modos(self):
        self.preparar_flujo_cruzado()
        continuo, resumen, filas = self.extraer("continuo", (300.0,))
        bloque, _, filas_bloque = self.extraer("por-bloque", (300.0,), "por-bloque")
        self.assertEqual(resumen["estado"], "continuo")
        self.assertEqual(resumen["guarda_estado_s"], 230)
        self.assertTrue(ver.verificar(self.archivo, continuo, self.pop, [300.0])["sin_futuro_ok"])
        self.assertTrue(ver.verificar(self.archivo, bloque, self.pop, [300.0], estado="por-bloque")["sin_futuro_ok"])
        por_ancla = {r["ventana_fin"]: r for r in filas}
        por_ancla_b = {r["ventana_fin"]: r for r in filas_bloque}
        self.assertNotEqual(float(por_ancla[ex.utc(310)]["flow_duration_mean_30s"]),
                            float(por_ancla_b[ex.utc(310)]["flow_duration_mean_30s"]))
        self.assertEqual(por_ancla[ex.utc(310)]["antecedentes_desde_utc"], ex.utc(100.1))
        for r in filas:
            anchor = ex.v2.parse_eve_timestamp(r["ventana_fin"])
            if anchor >= 300:
                esperado = ver.referencia(self.archivo, r["ip"], anchor, self.pop, [300.0])
                for name in ex.v2.FEATURE_NAMES:
                    self.assertAlmostEqual(float(r[name]), esperado[name], places=10,
                                           msg=f"{name} en {r['ventana_fin']}")
        resultado = comp.comparar(continuo / "filas.csv", bloque / "filas.csv", [300.0], self.root)
        self.assertGreater(resultado["filas_distintas"], 0)
        self.assertEqual(resultado["distintas_fuera_de_guarda"], 0)
        self.assertGreaterEqual(resultado["distancia_maxima_frontera_ancla_s"], 0)
        self.assertEqual(json.loads((self.root / "comparacion_modos.json").read_text()), resultado)
        # Los CSV precalculados pueden llegar en distinto orden.
        desordenado = self.root / "desordenado.csv"
        with desordenado.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=ex.FIELDS)
            writer.writeheader()
            writer.writerows(reversed(filas_bloque))
        self.assertEqual(comp.comparar(continuo / "filas.csv", desordenado, [300.0], self.root), resultado)

    def test_comparar_modos_cli(self):
        self.preparar_flujo_cruzado()
        fr = self.root / "fronteras.json"
        fr.write_text(json.dumps({"fronteras": [300.0]}))
        salida = self.root / "comparacion-cli"
        with patch.object(sys, "argv", ["comparar_modos.py", str(self.archivo),
                                        "--salida", str(salida), "--fronteras", str(fr)]):
            self.assertEqual(comp.main(), 0)
        informe = json.loads((salida / "comparacion_modos.json").read_text())
        self.assertGreater(informe["filas_distintas"], 0)
        self.assertEqual(informe["distintas_fuera_de_guarda"], 0)

    def test_guarda_cubre_horizonte_y_frontera(self):
        self.preparar_flujo_cruzado()
        with self.assertRaisesRegex(ValueError, "--guarda-s"):
            ex.procesar(self.archivo, self.root / "invalido", self.pop, [300.0], guarda_s=60)
        _, _, filas = self.extraer("guarda", (300.0,))
        por_ancla = {r["ventana_fin"]: r for r in filas}
        for anchor in (370, 520):
            self.assertIn("frontera", por_ancla[ex.utc(anchor)]["motivo_marca"])
        self.assertNotIn("frontera", por_ancla[ex.utc(530)]["motivo_marca"])
        self.assertIn("arranque", por_ancla[ex.utc(110)]["motivo_marca"])
        self.assertNotIn("arranque", por_ancla[ex.utc(340)]["motivo_marca"])

    def test_sin_futuro_y_paridad_motor(self):
        self.preparar()
        salida, _, filas = self.extraer("verificada")
        informe = ver.verificar(self.archivo, salida, self.pop, [], max_filas=None)
        self.assertTrue(informe["esquema_ok"])
        self.assertTrue(informe["sin_futuro_ok"])
        self.assertTrue(informe["paridad_motor_ok"])
        # Bloque 3: el motor de referencia (origen_v1) tiene la misma deduplicación, byte a byte
        d = informe["deduplicacion"]
        self.assertEqual((d["motor_referencia"], d["motor_misma_funcion"], d["motor_opcion"]),
                         ("deduplicar_v2.deduplicar_espejo_v2", True, "--deduplicacion v2"))
        self.assertEqual(d["sha256_motor"], d["sha256_extractor"])
        self.assertEqual(json.loads((salida / "resumen.json").read_text(encoding="utf-8"))["deduplicacion"]["sha256"],
                         d["sha256_extractor"])
        self.assertEqual(informe["filas_verificadas"], len(filas))
        # El último paquete del flujo sigue atribuido al iniciador y usa su inicio real.
        f = next(r for r in filas if r["ventana_fin"] == ex.utc(180))
        self.assertGreater(float(f["flow_duration_mean_30s"]), 60)
        self.assertEqual(float(f["tcp_retransmission_ratio_10s"]), 1.0)

    def test_flujo_largo_usa_el_horizonte_del_motor(self):
        """Piloto 24-nov: un flujo de aplicacion vivo >230 s daba flow_duration_mean_30s = 223 s
        en la extracción y 1,6 s en el motor, que solo conserva --history-seconds de paquetes."""
        c, s = "10.10.20.21", "10.10.30.10"
        frames = [trama(100.1, c, s, 50000, 443, 1),
                  trama(100.2, s, c, 443, 50000, 2, vlan=30, flags=18),
                  trama(300.1, c, s, 50000, 443, 3, seq=2, flags=24, payload=b"abc"),
                  trama(400.1, c, s, 50000, 443, 4, seq=3, flags=24, payload=b"def")]
        pcap(self.archivo / "pcap" / "live-0001.pcap", frames)
        (self.archivo / "eve" / "eve-1.json").write_text("")
        _, resumen, filas = self.extraer("largo")
        self.assertEqual(resumen["horizonte_estado_flujos_s"], ex.HORIZONTE_MOTOR_S)
        for row in filas:
            anchor = ex.v2.parse_eve_timestamp(row["ventana_fin"])
            motor = ver.referencia(self.archivo, row["ip"], anchor, self.pop, [], historia_s=ex.HORIZONTE_MOTOR_S)
            for name in ex.v2.FEATURE_NAMES:
                self.assertAlmostEqual(float(row[name]), motor[name], places=10,
                                       msg=f"{name} en {row['ventana_fin']}")
        f = next(r for r in filas if r["ventana_fin"] == ex.utc(410))
        # A los 410 s el motor ya no tiene el SYN de 100,1 s: el flujo empieza en 300,1 s.
        self.assertAlmostEqual(float(f["flow_duration_mean_30s"]), 100.0, places=3)

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
