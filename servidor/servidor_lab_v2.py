#!/usr/bin/env python3
"""Servidor web del laboratorio para CyberFlow V2: HTTP y HTTPS con registro.

Derivado de origen_v1/scripts/laboratorio/servidor_lab.py @ d2c97728916c2484f770a7a16a984c4c6bd42175
(sha256 9e91d8b8…). Cambios respecto a V1, todos sin alterar las respuestas:

1. Registro JSONL independiente (``--registro``), una línea por petición: conexión, cliente y puerto,
   instantes UTC de inicio y fin, duración monotónica, método, ruta, código, bytes de cuerpo y de
   cabeceras enviados, resultado del sorteo aleatorio (pausa de /api/lento, 201/500 del POST) y
   cualquier excepción (cliente que corta = ``incompleta``). No registra cuerpos ni cabeceras de
   petición (sin contenido sensible ni credenciales).
2. Aleatoriedad del servidor con generador propio (``--semilla``; por omisión, del sistema) y su
   valor registrado al arrancar. Con hilos concurrentes el ORDEN de los sorteos depende de la
   llegada de las peticiones, así que la semilla no hace reproducible la secuencia: lo que vale es
   el resultado registrado por petición. La semilla del cliente no controla nada de esto.
3. ``--limite-bps`` opcional para cuerpos de /estatico (ritmo de envío por conexión, envío en trozos
   de 16 KiB). 0 = sin límite, comportamiento V1. Si se usa, se registra en cada petición.
4. ``--version`` para que el arranque deje constancia.

Solo biblioteca estándar.

Cambios de v3 respecto a v2:

1. /contenido/<n> sirve bytes deterministas en trozos de 64 KiB y respeta --limite-bps.
2. /app/consulta devuelve un JSON de 512 bytes; /app/envio confirma longitud y SHA-256.
3. Los POST dejan de sortear errores 500. --semilla solo afecta a /api/lento.
4. El registro incluye tipo, ref y el límite de velocidad de /contenido.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import itertools
import json
import os
import random
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "v3.0.1"
RELLENO = (b"CyberFlow laboratorio. Cuerpo de relleno para dar tamano a la "
           b"respuesta sin depender de ficheros en disco. ")
TROZO = 16384
TROZO_CONTENIDO = 65536
BLOQUE_CONTENIDO = random.Random("cyberflow-v2-contenido").randbytes(1 << 20)


def ahora_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class Registro:
    def __init__(self, ruta: str | None):
        self.f = open(ruta, "a", encoding="utf-8", buffering=1) if ruta else None
        self.lock = threading.Lock()

    def escribir(self, d: dict) -> None:
        if not self.f:
            return
        linea = json.dumps(d, ensure_ascii=False, separators=(",", ":"))
        with self.lock:
            self.f.write(linea + "\n")


class Servidor(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, direccion, manejador, cfg):
        super().__init__(direccion, manejador)
        self.cfg = cfg
        self.rng = random.Random(cfg["semilla"])
        self.rng_lock = threading.Lock()
        self.conexiones = itertools.count(1)
        self.registro = Registro(cfg["registro"])

    def sorteo(self, fn):
        with self.rng_lock:
            return fn(self.rng)


class Manejador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cyberflow-lab"

    def setup(self) -> None:
        super().setup()
        self.conexion = next(self.server.conexiones)
        self.n_peticion = 0

    # --- envío con contabilidad -------------------------------------------------
    def _cabeceras(self, codigo: int, cabeceras: list[tuple[str, str]]) -> None:
        self.send_response(codigo)
        for k, v in cabeceras:
            self.send_header(k, v)
        self._bytes_cab = sum(len(x) for x in self._headers_buffer) + 2  # + CRLF final
        self.end_headers()

    def _limite(self) -> int:
        return self.server.cfg["limite_bps"] if self._ruta.startswith(("/estatico/", "/contenido/")) else 0

    def _escribir_trozos(self, trozos) -> int:
        limite = self._limite()
        enviados = 0
        t0 = time.monotonic()
        for trozo in trozos:
            self.wfile.write(trozo)
            enviados += len(trozo)
            if limite:
                espera = enviados / limite - (time.monotonic() - t0)
                if espera > 0:
                    time.sleep(espera)
        return enviados

    def _escribir(self, cuerpo: bytes) -> int:
        paso = TROZO if self._limite() else max(len(cuerpo), 1)
        return self._escribir_trozos(cuerpo[i:i + paso] for i in range(0, len(cuerpo), paso))

    def _responder(self, codigo: int, cuerpo: bytes, tipo: str = "text/plain") -> None:
        self._codigo = codigo
        try:
            self._cabeceras(codigo, [("Content-Type", tipo + "; charset=utf-8"), ("Content-Length", str(len(cuerpo)))])
            self._enviados = self._escribir(cuerpo)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as e:
            self._excepcion = type(e).__name__  # el cliente cortó: normal en los abandonos

    # --- ciclo de cada petición -------------------------------------------------
    def _inicio(self) -> None:
        self.n_peticion += 1
        self._t0 = time.monotonic()
        self._ini = ahora_utc()
        self._ruta = self.path.split("?")[0]
        self._codigo = None
        self._enviados = 0
        self._bytes_cab = 0
        self._excepcion = None
        self._aleatorio = None
        self._recibidos_cuerpo = 0
        self._esperado = None
        self._entrada_incompleta = False
        self._tipo = None
        self._ref = None

    def _fin(self) -> None:
        esperado = getattr(self, "_esperado", None)
        self.server.registro.escribir({
            "servidor": VERSION, "esquema": self.server.cfg["esquema"], "puerto": self.server.server_address[1],
            "conexion": self.conexion, "peticion_en_conexion": self.n_peticion,
            "cliente": self.client_address[0], "puerto_cliente": self.client_address[1],
            "inicio_utc": self._ini, "fin_utc": ahora_utc(),
            "duracion_s": round(time.monotonic() - self._t0, 6),
            "metodo": self.command, "ruta": self._ruta, "codigo": self._codigo,
            "bytes_cuerpo_recibidos": self._recibidos_cuerpo,
            "bytes_cabeceras_enviadas": self._bytes_cab, "bytes_cuerpo_enviados": self._enviados,
            "bytes_cuerpo_esperados": esperado,
            "resultado": "incompleta" if (self._entrada_incompleta or self._excepcion or
                                       (esperado is not None and self._enviados < esperado)) else "completa",
            "aleatorio": self._aleatorio, "excepcion": self._excepcion,
            "limite_bps": self._limite(), "tipo": self._tipo, "ref": self._ref,
        })

    def do_GET(self) -> None:  # noqa: N802
        self._inicio()
        try:
            self._get()
        finally:
            self._fin()

    def _get(self) -> None:
        ruta = self._ruta
        if ruta == "/":
            cuerpo = b"<html><body><h1>Laboratorio CyberFlow</h1></body></html>"
            self._esperado = len(cuerpo)
            self._responder(200, cuerpo, "text/html")
        elif ruta.startswith("/estatico/"):
            try:
                kb = int(ruta.rsplit("/", 1)[1].rstrip("kK"))
            except ValueError:
                kb = 8
            kb = max(1, min(kb, 4096))
            self._esperado = kb * 1024
            self._responder(200, (RELLENO * ((kb * 1024) // len(RELLENO) + 1))[:kb * 1024])
        elif ruta.startswith("/contenido/"):
            self._tipo = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("tipo", [None])[0]
            valor = ruta[len("/contenido/"):]
            cifras = valor.lstrip("0")
            if (not valor.isascii() or not valor.isdecimal() or not cifras or
                    len(cifras) > 7 or int(cifras) > 5_000_000):
                self._responder(400, b'{"error":"tamano invalido"}', "application/json")
                return
            n = int(cifras)
            self._esperado = n
            self._codigo = 200
            try:
                self._cabeceras(200, [("Content-Type", "application/octet-stream"), ("Content-Length", str(n))])
                # Con límite, trozos de 16 KiB como /estatico: los de 64 KiB salen a ritmo de línea
                # y, duplicados por el SPAN, desbordaban Gi2/0/19 (output drops en T1, 25-nov).
                paso = TROZO if self._limite() else TROZO_CONTENIDO
                self._enviados = self._escribir_trozos(
                    BLOQUE_CONTENIDO[i % len(BLOQUE_CONTENIDO):
                                     i % len(BLOQUE_CONTENIDO) + min(paso, n - i)]
                    for i in range(0, n, paso))
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as e:
                self._excepcion = type(e).__name__
        elif ruta == "/app/consulta":
            self._ref = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("ref", [""])[0][:64]
            cuerpo = json.dumps({"ref": self._ref, "estado": "ok"}, ensure_ascii=True,
                                separators=(",", ":")).encode("ascii").ljust(512, b" ")
            self._esperado = 512
            self._responder(200, cuerpo, "application/json")
        elif ruta == "/api/ok":
            self._esperado = None
            self._responder(200, b'{"estado":"ok"}', "application/json")
        elif ruta == "/api/auth":
            self._codigo = 401
            self._esperado = 0
            self._cabeceras(401, [("WWW-Authenticate", 'Basic realm="laboratorio"'), ("Content-Length", "0")])
        elif ruta == "/api/perdido":
            self._esperado = None
            self._responder(404, b'{"error":"no existe"}', "application/json")
        elif ruta == "/api/fallo":
            self._esperado = None
            self._responder(500, b'{"error":"fallo interno simulado"}', "application/json")
        elif ruta == "/api/lento":
            pausa = self.server.sorteo(lambda r: r.uniform(1.5, 4.0))
            self._aleatorio = {"tipo": "pausa_s", "valor": round(pausa, 6)}
            time.sleep(pausa)
            self._esperado = None
            self._responder(200, b'{"estado":"tarde pero llego"}', "application/json")
        else:
            self._esperado = None
            self._responder(404, b'{"error":"ruta desconocida"}', "application/json")

    def do_POST(self) -> None:  # noqa: N802
        self._inicio()
        try:
            cabecera = self.headers.get("Content-Length")
            if cabecera is None:
                if self._ruta == "/app/envio":
                    self.close_connection = True
                    self._responder(411, b'{"error":"falta Content-Length"}', "application/json")
                    return
                cabecera = "0"
            try:
                longitud = int(cabecera)
                if longitud < 0:
                    raise ValueError
            except ValueError:
                self.close_connection = True
                self._responder(400, b'{"error":"Content-Length invalido"}', "application/json")
                return
            resumen = hashlib.sha256()
            restante = longitud
            while restante:
                try:
                    trozo = self.rfile.read(min(restante, TROZO_CONTENIDO))
                except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
                    self._excepcion = type(e).__name__
                    self._entrada_incompleta = True
                    self.close_connection = True
                    return
                if not trozo:
                    self._entrada_incompleta = True
                    self.close_connection = True
                    return
                self._recibidos_cuerpo += len(trozo)
                resumen.update(trozo)
                restante -= len(trozo)
            if self._ruta == "/app/envio":
                cuerpo = json.dumps({"recibido": longitud, "sha256": resumen.hexdigest()},
                                    separators=(",", ":")).encode("ascii")
            else:
                cuerpo = b'{"recibido":true}'
            self._responder(201, cuerpo, "application/json")
        finally:
            self._fin()

    def do_HEAD(self) -> None:  # noqa: N802
        self._inicio()
        try:
            self._codigo = 200
            self._esperado = 0
            self._cabeceras(200, [("Content-Length", "0")])
        finally:
            self._fin()

    def log_message(self, *args: object) -> None:
        pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--direccion", default="0.0.0.0")
    p.add_argument("--puerto", type=int, default=8080)
    p.add_argument("--cert")
    p.add_argument("--clave")
    p.add_argument("--registro", help="fichero JSONL de peticiones (se abre en modo añadir)")
    p.add_argument("--semilla", type=int, default=None, help="semilla del generador del servidor (se registra)")
    p.add_argument("--limite-bps", type=int, default=0, help="ritmo máximo de /estatico y /contenido por conexión, bytes/s (0 = sin límite)")
    p.add_argument("--version", action="version", version=VERSION)
    a = p.parse_args()
    semilla = a.semilla if a.semilla is not None else int.from_bytes(os.urandom(6), "big")
    cfg = {"semilla": semilla, "registro": a.registro, "limite_bps": a.limite_bps,
           "esquema": "https" if a.cert and a.clave else "http"}
    srv = Servidor((a.direccion, a.puerto), Manejador, cfg)
    if a.cert and a.clave:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.clave)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.registro.escribir({"evento": "arranque", "servidor": VERSION, "utc": ahora_utc(), "pid": os.getpid(),
                           "esquema": cfg["esquema"], "puerto": a.puerto, "semilla": semilla,
                           "limite_bps": a.limite_bps})
    print("laboratorio %s: %s://%s:%d/ semilla=%d limite_bps=%d" % (VERSION, cfg["esquema"], a.direccion, a.puerto,
                                                                     semilla, a.limite_bps), flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
