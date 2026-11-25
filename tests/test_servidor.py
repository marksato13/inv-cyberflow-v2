"""El servidor V3 conserva V1 y registra peticiones, cortes y tamaños exactos."""
import hashlib
import http.client
import json
import random
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


class TestServidorV3(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile(dir=RAIZ / "tests", suffix=".jsonl", delete=False) as f:
            self.reg = Path(f.name)
        cfg = {"semilla": 7, "registro": str(self.reg), "limite_bps": 0, "esquema": "http"}
        self.srv = s.Servidor(("127.0.0.1", 0), s.Manejador, cfg)
        self.puerto = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.srv.registro.f.close()
        self.reg.unlink()

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
        st, _ = self.pedir("POST", "/api/enviar", b"x" * 200)
        self.assertEqual(st, 201)
        L = [x for x in self.lineas() if "ruta" in x]
        self.assertEqual([x["codigo"] for x in L][:4], [200, 404, 500, 401])
        self.assertEqual(L[0]["bytes_cuerpo_enviados"], 65536)
        self.assertEqual(L[0]["resultado"], "completa")
        self.assertEqual(L[4]["bytes_cuerpo_recibidos"], 200)
        self.assertIsNone(L[4]["aleatorio"])
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

    def test_contenido_tamanos_exactos_y_deterministas(self):
        for n in (1, 100, 1_999_999, 5_000_000):
            with self.subTest(n=n):
                datos = []
                for tipo in ("archivo", "principal"):
                    c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=10)
                    c.request("GET", f"/contenido/{n}?tipo={tipo}")
                    r = c.getresponse()
                    self.assertEqual((r.status, r.getheader("Content-Length"), r.getheader("Content-Type")),
                                     (200, str(n), "application/octet-stream"))
                    datos.append(r.read())
                    c.close()
                bloque = random.Random("cyberflow-v2-contenido").randbytes(1 << 20)
                esperado = (bloque * (n // len(bloque) + 1))[:n]
                self.assertEqual(len(datos[0]), n)
                self.assertEqual(hashlib.sha256(datos[0]).digest(), hashlib.sha256(esperado).digest())
                self.assertEqual(hashlib.sha256(datos[0]).digest(), hashlib.sha256(datos[1]).digest())
        L = [x for x in self.lineas() if x.get("ruta", "").startswith("/contenido/")]
        self.assertEqual([x["bytes_cuerpo_esperados"] for x in L],
                         [n for n in (1, 100, 1_999_999, 5_000_000) for _ in range(2)])
        self.assertEqual([x["tipo"] for x in L], [tipo for _ in range(4) for tipo in ("archivo", "principal")])
        self.assertTrue(all(x["resultado"] == "completa" for x in L))

    def test_contenido_invalido(self):
        for valor in ("0", "5000001", "abc", "-1"):
            with self.subTest(valor=valor):
                codigo, cuerpo = self.pedir("GET", "/contenido/" + valor)
                self.assertEqual(codigo, 400)
                self.assertIn("error", json.loads(cuerpo))

    def test_contenido_conexion_persistente(self):
        c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=10)
        try:
            for n in (1, 100, 200):
                c.request("GET", f"/contenido/{n}")
                r = c.getresponse()
                self.assertEqual((r.status, len(r.read())), (200, n))
        finally:
            c.close()
        L = [x for x in self.lineas() if x.get("ruta", "").startswith("/contenido/")]
        self.assertEqual([x["peticion_en_conexion"] for x in L], [1, 2, 3])
        self.assertEqual(len({x["conexion"] for x in L}), 1)

    def test_consulta_512_bytes(self):
        c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=10)
        c.request("GET", "/app/consulta?ref=" + "a" * 80)
        r = c.getresponse()
        cuerpo = r.read()
        c.close()
        self.assertEqual((r.status, r.getheader("Content-Length"), len(cuerpo)), (200, "512", 512))
        self.assertEqual(json.loads(cuerpo)["ref"], "a" * 64)
        L = [x for x in self.lineas() if x.get("ruta") == "/app/consulta"]
        self.assertEqual((L[0]["ref"], L[0]["bytes_cuerpo_esperados"]), ("a" * 64, 512))

    def test_envio_siempre_201_y_sha256(self):
        for n in range(50):
            cuerpo = bytes(range(n))
            codigo, datos = self.pedir("POST", "/app/envio", cuerpo)
            self.assertEqual(codigo, 201)
            self.assertEqual(json.loads(datos), {"recibido": n, "sha256": hashlib.sha256(cuerpo).hexdigest()})
        L = [x for x in self.lineas() if x.get("ruta") == "/app/envio"]
        self.assertEqual(len(L), 50)
        self.assertTrue(all(x["codigo"] == 201 and x["aleatorio"] is None for x in L))

    def test_envio_sin_longitud_e_incompleto(self):
        sk = socket.create_connection(("127.0.0.1", self.puerto))
        sk.sendall(b"POST /app/envio HTTP/1.1\r\nHost: x\r\n\r\n")
        respuesta = sk.recv(1000)
        sk.close()
        self.assertIn(b" 411 ", respuesta)
        sk = socket.create_connection(("127.0.0.1", self.puerto))
        sk.sendall(b"POST /app/envio HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        sk.shutdown(socket.SHUT_WR)
        self.assertEqual(sk.recv(1000), b"")
        sk.close()
        L = [x for x in self.lineas() if x.get("ruta") == "/app/envio"]
        self.assertEqual((L[-1]["resultado"], L[-1]["bytes_cuerpo_recibidos"], L[-1]["codigo"]),
                         ("incompleta", 3, None))

    def test_limite_bps_contenido(self):
        self.srv.cfg["limite_bps"] = 2_000_000
        t0 = time.monotonic()
        codigo, cuerpo = self.pedir("GET", "/contenido/1000000")
        duracion = time.monotonic() - t0
        self.assertEqual((codigo, len(cuerpo)), (200, 1_000_000))
        self.assertGreaterEqual(duracion, 0.45)
        L = [x for x in self.lineas() if x.get("ruta") == "/contenido/1000000"]
        self.assertEqual(L[0]["limite_bps"], 2_000_000)


if __name__ == "__main__":
    unittest.main()
