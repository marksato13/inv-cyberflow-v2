"""El servidor V2 responde igual que V1 y registra cada petición (incluidos sorteos y cortes)."""
import http.client
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "servidor"))
import servidor_lab_v2 as s  # noqa: E402


class TestServidorV2(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.reg = Path(self.dir.name) / "srv.jsonl"
        cfg = {"semilla": 7, "registro": str(self.reg), "limite_bps": 0, "esquema": "http"}
        self.srv = s.Servidor(("127.0.0.1", 0), s.Manejador, cfg)
        self.puerto = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.srv.registro.f.close()
        self.dir.cleanup()

    def pedir(self, metodo, ruta, cuerpo=None):
        c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=10)
        c.request(metodo, ruta, body=cuerpo)
        r = c.getresponse()
        datos = r.read()
        c.close()
        return r.status, datos

    def lineas(self):
        time.sleep(0.2)
        return [json.loads(x) for x in self.reg.read_text(encoding="utf-8").splitlines()]

    def test_respuestas_como_v1_y_registro(self):
        self.assertEqual(self.pedir("GET", "/estatico/64k"), (200, (s.RELLENO * (65536 // len(s.RELLENO) + 1))[:65536]))
        self.assertEqual(self.pedir("GET", "/api/perdido")[0], 404)
        self.assertEqual(self.pedir("GET", "/api/fallo")[0], 500)
        self.assertEqual(self.pedir("GET", "/api/auth")[0], 401)
        st, _ = self.pedir("POST", "/api/datos", b"x" * 200)
        self.assertIn(st, (201, 500))
        L = [x for x in self.lineas() if "ruta" in x]
        self.assertEqual([x["codigo"] for x in L][:4], [200, 404, 500, 401])
        self.assertEqual(L[0]["bytes_cuerpo_enviados"], 65536)
        self.assertEqual(L[0]["resultado"], "completa")
        self.assertEqual(L[4]["bytes_cuerpo_recibidos"], 200)
        self.assertEqual(L[4]["aleatorio"]["codigo"], st)  # el sorteo registrado es el que se sirvió
        self.assertTrue(all(x["cliente"] == "127.0.0.1" and x["puerto_cliente"] > 0 for x in L))

    def test_corte_del_cliente_queda_incompleta(self):
        sk = socket.create_connection(("127.0.0.1", self.puerto))
        sk.sendall(b"GET /estatico/4096k HTTP/1.1\r\nHost: x\r\n\r\n")
        sk.recv(1000)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        sk.close()
        time.sleep(1.0)
        L = [x for x in self.lineas() if x.get("ruta") == "/estatico/4096k"]
        self.assertEqual(L[0]["resultado"], "incompleta")
        self.assertLess(L[0]["bytes_cuerpo_enviados"], 4096 * 1024)

    def test_limite_bps(self):
        self.srv.cfg["limite_bps"] = 1_000_000
        t0 = time.monotonic()
        st, d = self.pedir("GET", "/estatico/512k")
        dt = time.monotonic() - t0
        self.assertEqual((st, len(d)), (200, 524288))
        self.assertGreater(dt, 0.45)  # 524288 B a 1 MB/s ≈ 0,52 s
        self.assertEqual([x for x in self.lineas() if "ruta" in x][-1]["limite_bps"], 1_000_000)


if __name__ == "__main__":
    unittest.main()
