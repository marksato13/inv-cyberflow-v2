"""PCAP sintéticos 802.1Q para la correlación V2; no usan red ni dependencias."""
from __future__ import annotations

import datetime as dt
import json
import random
import socket
import ssl
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "captura"))
import cobertura_v2 as cov  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generador"))
import transacciones as generador_tx  # noqa: E402


def utc(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def tx(ident, inicio=1000, origen="10.10.20.21", destino="10.10.30.10",
       po=40000, pd=80, proto="http", esperado=4):
    r = dict(transaccion_id=ident, ejecucion_id="E", perfil="navegacion", accion="web_pequena",
             inicio_utc=utc(inicio), fin_utc=utc(inicio + 1), origen_ip=origen,
             origen_puerto=po, destino_ip=destino, destino_puerto=pd, protocolo=proto)
    if esperado is not None:
        r["bytes_tcp_recibidos"] = esperado
    return r


def trama(proto, origen, destino, po=0, pd=0, seq=0, flags=0x18, carga=b"",
          vlan=20, ident=1, icmp_tipo=8):
    if proto == "tcp":
        transporte = struct.pack("!HHIIHHHH", po, pd, seq, 0, (5 << 12) | flags, 65535, 0, 0) + carga
        numero = 6
    elif proto == "udp":
        transporte = struct.pack("!HHHH", po, pd, 8 + len(carga), 0) + carga
        numero = 17
    else:
        transporte = struct.pack("!BBHHH", icmp_tipo, 0, 0, ident, 1) + carga
        numero = 1
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transporte), ident,
                     0, 64, numero, 0, socket.inet_aton(origen), socket.inet_aton(destino))
    eth = b"\0" * 12 + struct.pack("!HHH", 0x8100, vlan, 0x0800)
    return eth + ip + transporte


def tcp(t, sentido=0, seq=100, flags=0x18, carga=b"", vlan=20):
    o, d = t["origen_ip"], t["destino_ip"]
    po, pd = t["origen_puerto"], t["destino_puerto"]
    if sentido:
        o, d, po, pd = d, o, pd, po
    return trama("tcp", o, d, po, pd, seq, flags, carga, vlan)


def dns(t, ident, respuesta=False, rcode=0):
    cab = struct.pack("!HHHHHH", ident, (0x8180 if respuesta else 0x0100) | rcode, 1, 0, 0, 0)
    o, d = t["origen_ip"], t["destino_ip"]
    po, pd = t["origen_puerto"], t["destino_puerto"]
    if respuesta:
        o, d, po, pd = d, o, pd, po
    return trama("udp", o, d, po, pd, carga=cab)


class Caso(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "pcap").mkdir()
        (self.base / "eve").mkdir()

    def pcap(self, paquetes, truncar=b""):
        with (self.base / "pcap" / "live-19700101001640.pcap").open("wb") as f:
            f.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
            for ts, trama_ in paquetes:
                segundos = int(ts)
                micros = round((ts - segundos) * 1e6)
                f.write(struct.pack("<IIII", segundos, micros, len(trama_), len(trama_)))
                f.write(trama_)
            f.write(truncar)

    def medir(self, *txs):
        return cov.medir(self.base, list(txs))

    def test_cinco_tupla_clientes_y_destinos(self):
        a = tx("a")
        b = tx("b", origen="10.10.20.22", destino="10.10.10.20", pd=443)
        self.pcap([(1000.1, tcp(a, seq=100, flags=2)),
                   (1000.2, tcp(a, 1, seq=200, flags=0x12)),
                   (1000.3, tcp(a, carga=b"GET")),
                   (1000.4, tcp(a, 1, seq=201, carga=b"DATA")),
                   (1000.1, tcp(b, seq=500, flags=2)),
                   (1000.2, tcp(b, 1, seq=600, flags=0x12)),
                   (1000.3, tcp(b, carga=b"GET")),
                   (1000.4, tcp(b, 1, seq=601, carga=b"DATA"))])
        filas = self.medir(a, b)["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], [4, 4])
        self.assertTrue(all(r["transferencia"] == "completa" for r in filas))

    def test_reutilizacion_tupla_por_tiempo(self):
        a, b = tx("a"), tx("b", inicio=1010)
        self.pcap([(1000.2, tcp(a, 1, seq=200, flags=0x12)),
                   (1000.4, tcp(a, 1, seq=201, carga=b"DATA")),
                   (1010.2, tcp(b, 1, seq=900, flags=0x12)),
                   (1010.4, tcp(b, 1, seq=901, carga=b"OTRO"))])
        self.assertEqual([r["bytes_vistos"] for r in self.medir(a, b)["por_transaccion"]], [4, 4])

    def test_copias_dos_vlan_y_una_sola(self):
        t = tx("a")
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12, vlan=30)),
                   (1000.11, tcp(t, 1, seq=200, flags=0x12, vlan=20)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"DATA", vlan=30)),
                   (1000.21, tcp(t, 1, seq=201, carga=b"DATA", vlan=20))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertEqual((r["bytes_vistos"], r["copias_espejo"], r["retransmisiones"]), (4, 2, 0))
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12, vlan=30)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"DATA", vlan=30))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertEqual((r["bytes_vistos"], r["copias_espejo"]), (4, 0))

    def test_retransmision_y_solape_parcial(self):
        t = tx("a", esperado=6)
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"ABCD")),
                   (1000.3, tcp(t, 1, seq=201, carga=b"ABCD")),
                   (1000.4, tcp(t, 1, seq=203, carga=b"CDEF"))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertEqual((r["bytes_vistos"], r["retransmisiones"], r["huecos"]), (6, 2, 0))
        self.assertEqual(r["transferencia"], "completa")

    def test_hueco_hace_incompleta(self):
        t = tx("a", esperado=4)
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"AB")),
                   (1000.3, tcp(t, 1, seq=205, carga=b"CD"))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertEqual((r["bytes_vistos"], r["huecos"], r["transferencia"]), (4, 2, "incompleta"))

    def test_pcap_truncado_no_verificable(self):
        t = tx("a")
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12))], truncar=b"\x01\x02")
        informe = self.medir(t)
        self.assertIn("truncada", informe["errores"][0]["motivo"])
        self.assertEqual(informe["por_transaccion"][0]["estado"], "no verificable")
        self.assertEqual(informe["total"]["no_verificables"], 1)

    def test_dns_por_id(self):
        t = tx("dns", destino="10.10.10.20", pd=53, proto="dns", esperado=None)
        self.pcap([(1000.1, dns(t, 123)),
                   (1000.2, dns(t, 999, respuesta=True)),
                   (1000.3, dns(t, 123, respuesta=True))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertTrue(r["peticion"] and r["respuesta"])
        self.assertEqual(r["dns_rcode_pcap"], 0)
        self.assertEqual(r["transferencia"], "no comparable")

    def test_eve_flow_id_y_codigo(self):
        t = tx("a")
        t["http_codigo"] = 200
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"DATA"))])
        ev = [dict(timestamp=utc(1000.2), proto="TCP", src_ip=t["origen_ip"],
                   src_port=t["origen_puerto"], dest_ip=t["destino_ip"],
                   dest_port=t["destino_puerto"], flow_id=55, event_type="flow"),
              dict(timestamp=utc(1000.3), flow_id=55, event_type="http",
                   tx_id=7, http=dict(status=200)),
              dict(timestamp=utc(1000.4), flow_id=55, event_type="fileinfo")]
        (self.base / "eve" / "eve-E.json").write_text(
            "".join(json.dumps(x) + "\n" for x in ev), encoding="utf-8")
        r = self.medir(t)["por_transaccion"][0]
        self.assertEqual(r["eve_flow_id"], 55)
        self.assertEqual(r["eve_http_tx_id"], 7)
        self.assertTrue(r["eve_http_coincide"])
        self.assertEqual(set(r["eve_tipos"]), {"flow", "http", "fileinfo"})

    def test_eve_corrupto_no_verificable(self):
        t = tx("a")
        self.pcap([])
        (self.base / "eve" / "eve-E.json").write_text("{mal json\n", encoding="utf-8")
        informe = self.medir(t)
        self.assertEqual(informe["por_transaccion"][0]["estado"], "no verificable")
        self.assertIn("EVE", informe["errores"][0]["motivo"])

    def test_icmp_eco_y_respuesta_por_identificador(self):
        t = tx("ping", po=None, pd=None, proto="icmp", esperado=None)
        self.pcap([(1000.1, trama("icmp", t["origen_ip"], t["destino_ip"], ident=12)),
                   (1000.2, trama("icmp", t["destino_ip"], t["origen_ip"],
                                  ident=99, icmp_tipo=0)),
                   (1000.3, trama("icmp", t["destino_ip"], t["origen_ip"],
                                  ident=12, icmp_tipo=0))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertTrue(r["peticion"] and r["respuesta"])

    def test_registro_antiguo_no_comparable(self):
        t = tx("antigua", esperado=None)
        t["bytes_recibidos"] = 4
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"DATA"))])
        r = self.medir(t)["por_transaccion"][0]
        self.assertEqual(r["bytes_vistos"], 4)
        self.assertEqual(r["transferencia"], "no comparable")
        self.assertIsNone(r["fraccion"])

    def test_manifiesto_con_pcap_ausente(self):
        t = tx("a")
        self.pcap([])
        (self.base / "manifiesto.json").write_text('{"pcap_ficheros": 2}', encoding="utf-8")
        informe = self.medir(t)
        self.assertEqual(informe["por_transaccion"][0]["estado"], "no verificable")
        self.assertIn("PCAP archivados", informe["errores"][0]["motivo"])

    def test_medidor_http_plano_y_contadores_tcp(self):
        class SocketFalso:
            def __init__(self):
                self.recibido = False
                self.enviados = b""

            def sendall(self, datos):
                self.enviados += datos

            def recv(self, _n):
                if self.recibido:
                    return b""
                self.recibido = True
                return b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDATA"

            def close(self):
                pass

        socket_falso = SocketFalso()
        cliente = generador_tx.Cliente("10.10.20.21",
                                        {"servidor": "10.10.30.10", "puerto_http": 80,
                                         "puerto_https": 443}, {}, random.Random(1))
        cliente._conectar = lambda *_: socket_falso
        reg = {}
        cliente._http(reg, "/")
        self.assertEqual(reg["bytes_enviados"], reg["bytes_tcp_enviados"])
        self.assertEqual(reg["bytes_recibidos"], reg["bytes_tcp_recibidos"])
        self.assertEqual(reg["bytes_enviados"], len(socket_falso.enviados))

    def test_salida_json_y_csv(self):
        t = tx("a")
        self.pcap([(1000.1, tcp(t, 1, seq=200, flags=0x12)),
                   (1000.2, tcp(t, 1, seq=201, carga=b"DATA"))])
        registro = self.base / "transacciones.jsonl"
        registro.write_text(json.dumps(t) + "\n", encoding="utf-8")
        salida, csv_salida = self.base / "informe.json", self.base / "filas.csv"
        self.assertEqual(cov.main(["--capturas", str(self.base), "--transacciones",
                                   str(registro), "--salida", str(salida),
                                   "--csv", str(csv_salida)]), 0)
        self.assertEqual(json.loads(salida.read_text(encoding="utf-8"))["total"]["completas"], 1)
        self.assertIn("transaccion_id", csv_salida.read_text(encoding="utf-8"))

    def test_tls_medido_cuenta_socket_crudo(self):
        class SocketFalso:
            def __init__(self):
                self.enviados = b""

            def sendall(self, datos):
                self.enviados += datos

            def recv(self, _n):
                return b"SH"

            def close(self):
                pass

        class ContextoFalso:
            def wrap_bio(self, entrada, salida, **_):
                class TLSFalso:
                    def __init__(self):
                        self.primero = True

                    def do_handshake(self):
                        if self.primero:
                            self.primero = False
                            salida.write(b"CH")
                            raise ssl.SSLWantReadError()
                        self_respuesta = entrada.read()
                        if self_respuesta != b"SH":
                            raise AssertionError(self_respuesta)

                    def write(self, datos):
                        salida.write(b"EN" + datos)
                        return len(datos)

                return TLSFalso()

        socket_falso = SocketFalso()
        tls = generador_tx.TLSMedido(socket_falso, ContextoFalso(), "10.10.30.10")
        tls.handshake()
        tls.sendall(b"DATA")
        self.assertEqual((tls.tx, tls.rx), (8, 2))
        self.assertEqual(socket_falso.enviados, b"CHENDATA")


if __name__ == "__main__":
    unittest.main()
