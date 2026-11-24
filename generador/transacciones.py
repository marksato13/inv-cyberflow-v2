"""Acciones de tráfico legítimo de CyberFlow V2, cada una medida como una transacción.

Origen: ``scripts/laboratorio/clientes_lab.py`` de inv-cyberflow-sistema
(commit d2c97728916c2484f770a7a16a984c4c6bd42175, sha256 ae5134a7…). Se conservan las
mismas acciones, rutas, tamaños, puertos y tiempos de espera de red. Cambios (ver
docs/PROCEDENCIA.md):

* Cada acción devuelve un registro con el resultado observado en vez de lanzar o callar.
* HTTP se habla a mano sobre el socket para contar bytes de aplicación y leer el código.
* DNS decodifica la respuesta (rcode y registros A) en lugar de descartarla.
* Los nombres DNS salen del programa (zona controlada) y no del dominio de otro proyecto.
* La aleatoriedad (rutas, tamaños, nombres, cuerpos) usa el generador con semilla.
"""
from __future__ import annotations

import random
import socket
import ssl
import struct
import subprocess

ESPERA_TCP_S = 5.0      # V1: _socket(espera=5.0)
ESPERA_HTTP_S = 10.0    # V1: _socket(..., espera=10.0) y HTTPConnection(timeout=10)
ESPERA_DNS_S = 3.0      # V1: s.settimeout(3.0)
ESPERA_CERRADO_S = 2.0  # V1: puerto_cerrado espera=2.0

# Resultado esperado de cada acción. "intencional" marca los errores buscados a propósito.
ESPERADO = {
    "web_pequena": ("http", {200}, False),
    "web_media": ("http", {200}, False),
    "web_grande": ("http", {200}, False),
    "https": ("http", {200}, False),
    "api_ok": ("http", {200}, False),
    "api_lento": ("http", {200}, False),
    # El servidor V1 responde 500 al 10 % de los POST (aleatoriedad documentada).
    "api_post": ("http", {201, 500}, False),
    "api_auth": ("http", {401}, True),
    "api_404": ("http", {404}, True),
    "api_500": ("http", {500}, True),
    "abandono": ("abandono", None, True),
    "puerto_cerrado": ("cerrado", None, True),
    "dns": ("dns", 0, False),
    "dns_inexistente": ("dns", 3, True),
    "ping": ("icmp", 0, False),
}


class Medidor:
    """Cuenta bytes de aplicación; en HTTPS son texto plano, no registros TLS."""

    def __init__(self, s):
        self.s = s
        self.tx = 0
        self.rx = 0

    def enviar(self, datos: bytes) -> None:
        self.s.sendall(datos)
        self.tx += len(datos)

    def recibir(self, n: int = 65536) -> bytes:
        d = self.s.recv(n)
        self.rx += len(d)
        return d


class TLSMedido:
    """TLS con BIO: cuenta en el socket los registros cifrados, incluido el handshake."""

    def __init__(self, s: socket.socket, ctx: ssl.SSLContext, servidor: str):
        self.s = s
        self.entrada = ssl.MemoryBIO()
        self.salida = ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self.entrada, self.salida, server_side=False,
                                server_hostname=servidor)
        self.tx = self.rx = 0

    def handshake(self):
        self._hacer(self.tls.do_handshake)

    def _vaciar(self):
        while True:
            datos = self.salida.read()
            if not datos:
                break
            self.s.sendall(datos)
            self.tx += len(datos)

    def _hacer(self, operacion):
        while True:
            try:
                resultado = operacion()
                self._vaciar()
                return resultado
            except ssl.SSLWantWriteError:
                self._vaciar()
            except ssl.SSLWantReadError:
                self._vaciar()
                datos = self.s.recv(65536)
                self.rx += len(datos)
                if datos:
                    self.entrada.write(datos)
                else:
                    self.entrada.write_eof()

    def sendall(self, datos: bytes):
        pos = 0
        while pos < len(datos):
            pos += self._hacer(lambda: self.tls.write(datos[pos:]))

    def recv(self, n: int):
        return self._hacer(lambda: self.tls.read(n))

    def version(self):
        return self.tls.version()

    def close(self):
        self.s.close()


class Cliente:
    def __init__(self, origen: str, destinos: dict, tamanos: dict, rng: random.Random):
        self.origen = origen
        self.d = destinos
        self.t = tamanos
        self.rng = rng

    # -- utilidades -------------------------------------------------------
    def _conectar(self, destino: str, puerto: int, espera: float, reg: dict) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(espera)
            if self.origen:
                s.bind((self.origen, 0))
            reg["origen_puerto"] = s.getsockname()[1]
            s.connect((destino, puerto))
        except BaseException:
            s.close()
            raise
        return s

    def _http(self, reg: dict, ruta: str, metodo: str = "GET", cuerpo: bytes | None = None,
              https: bool = False, leer: bool = True) -> None:
        servidor = self.d["servidor"]
        puerto = self.d["puerto_https"] if https else self.d["puerto_http"]
        reg.update(destino_ip=servidor, destino_puerto=puerto,
                   protocolo="https" if https else "http", ruta=ruta, metodo=metodo)
        reg.setdefault("bytes_tcp_enviados", 0)
        reg.setdefault("bytes_tcp_recibidos", 0)
        s = self._conectar(servidor, puerto, ESPERA_HTTP_S, reg)
        m = None
        tls = None
        try:
            if https:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # certificado propio del laboratorio (igual que V1)
                tls = TLSMedido(s, ctx, servidor)
                s = tls
                tls.handshake()
                reg["tls_version"] = tls.version()
            m = Medidor(s)
            cab = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (metodo, ruta, servidor)
            if cuerpo is not None:
                cab += "Content-Length: %d\r\nContent-Type: application/octet-stream\r\n" % len(cuerpo)
            m.enviar(cab.encode() + b"\r\n" + (cuerpo or b""))
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = m.recibir()
                if not d:
                    break
                buf += d
            linea = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            partes = linea.split()
            if len(partes) >= 2 and partes[1].isdigit():
                reg["http_codigo"] = int(partes[1])
            cabeceras = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").lower()
            largo = None
            for c in cabeceras.split("\r\n")[1:]:
                if c.startswith("content-length:"):
                    try:
                        largo = int(c.split(":", 1)[1])
                    except ValueError:
                        pass
            reg["http_content_length"] = largo
            if not leer:
                reg["cortada_por_cliente"] = True
                return
            while True:
                d = m.recibir()
                if not d:
                    break
            cuerpo_rx = m.rx - (len(buf.split(b"\r\n\r\n", 1)[0]) + 4)
            reg["http_cuerpo_bytes"] = cuerpo_rx
            if largo is not None and cuerpo_rx < largo:
                reg["incompleta"] = True
        finally:
            if tls is not None:
                reg["bytes_tcp_enviados"] = tls.tx
                reg["bytes_tcp_recibidos"] = tls.rx
            elif m is not None:
                reg["bytes_tcp_enviados"] = m.tx
                reg["bytes_tcp_recibidos"] = m.rx
            if m is not None:
                reg["bytes_enviados"] = m.tx
                reg["bytes_recibidos"] = m.rx
            try:
                s.close()
            except OSError:
                pass

    def _dns(self, reg: dict, nombre: str) -> None:
        tid = self.rng.randint(0, 65535)
        reg["dns_id"] = tid
        cabecera = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        pregunta = b"".join(bytes([len(p)]) + p.encode() for p in nombre.split(".")) + b"\x00"
        paquete = cabecera + pregunta + struct.pack("!HH", 1, 1)
        servidor = self.d["dns_servidor"]
        reg.update(destino_ip=servidor, destino_puerto=53, protocolo="dns", dns_nombre=nombre)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(ESPERA_DNS_S)
        try:
            if self.origen:
                s.bind((self.origen, 0))
            reg["origen_puerto"] = s.getsockname()[1]
            s.sendto(paquete, (servidor, 53))
            reg["bytes_enviados"] = len(paquete)
            resp, _ = s.recvfrom(4096)
            reg["bytes_recibidos"] = len(resp)
        finally:
            s.close()
        rtid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:12])
        reg["dns_id_coincide"] = rtid == tid
        reg["dns_rcode"] = flags & 0x000F
        reg["dns_respuestas"] = _registros_a(resp, qd, an)

    # -- acciones (mismas rutas y tamaños que V1, tomados del programa) ---
    def web_pequena(self, reg):
        self._http(reg, self.rng.choice(self.t["web_pequena"]))

    def web_media(self, reg):
        self._http(reg, self.rng.choice(self.t["web_media"]))

    def web_grande(self, reg):
        self._http(reg, self.rng.choice(self.t["web_grande"]))

    def https(self, reg):
        self._http(reg, self.rng.choice(self.t["https"]), https=True)

    def dns(self, reg):
        nombre = "%s.%s" % (self.rng.choice(self.d["dns_nombres"]), self.d["dns_zona"])
        self._dns(reg, nombre)

    def dns_inexistente(self, reg):
        nombre = "%s.%s" % (self.rng.randbytes(6).hex(), self.d["dns_zona"])
        self._dns(reg, nombre)

    def api_ok(self, reg):
        self._http(reg, "/api/ok")

    def api_post(self, reg):
        lo, hi = self.t["api_post_bytes"]
        self._http(reg, "/api/enviar", metodo="POST", cuerpo=self.rng.randbytes(self.rng.randint(lo, hi)))

    def api_auth(self, reg):
        self._http(reg, "/api/auth")

    def api_404(self, reg):
        self._http(reg, "/api/perdido")

    def api_500(self, reg):
        self._http(reg, "/api/fallo")

    def api_lento(self, reg):
        self._http(reg, "/api/lento")

    def abandono(self, reg):
        self._http(reg, self.t["abandono"], leer=False)

    def puerto_cerrado(self, reg):
        servidor = self.d["servidor"]
        puerto = self.rng.choice(self.d["puertos_cerrados"])
        reg.update(destino_ip=servidor, destino_puerto=puerto, protocolo="tcp",
                   bytes_tcp_enviados=0, bytes_tcp_recibidos=0)
        try:
            self._conectar(servidor, puerto, ESPERA_CERRADO_S, reg).close()
        except ConnectionRefusedError:
            reg["cerrado_como"] = "rst"
            return
        except (socket.timeout, TimeoutError):
            reg["cerrado_como"] = "sin_respuesta"
            reg["timeout"] = True
            return
        reg["cerrado_como"] = "abierto"

    def ping(self, reg):
        destino = self.d["ping"]
        reg.update(destino_ip=destino, protocolo="icmp")
        orden = ["ping", "-n", "-c", "1", "-W", "2"]
        if self.origen:
            orden += ["-I", self.origen]
        r = subprocess.run(orden + [destino], capture_output=True, timeout=8, text=True)
        reg["icmp_rc"] = r.returncode


def _saltar_nombre(m: bytes, i: int) -> int:
    while True:
        n = m[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def _registros_a(m: bytes, qd: int, an: int) -> list[str]:
    i = 12
    for _ in range(qd):
        i = _saltar_nombre(m, i) + 4
    ips = []
    for _ in range(an):
        i = _saltar_nombre(m, i)
        tipo, _clase, _ttl, largo = struct.unpack("!HHIH", m[i:i + 10])
        i += 10
        if tipo == 1 and largo == 4:
            ips.append(socket.inet_ntoa(m[i:i + 4]))
        i += largo
    return ips


def clasificar(accion: str, reg: dict, destinos: dict) -> None:
    """Rellena resultado_esperado/observado, coincide y clase.

    clase: ``ok`` (lo esperado y no es un error), ``error_intencional`` (lo esperado y es un
    error buscado a propósito), ``variacion_servidor`` (resultado admitido por la aleatoriedad
    documentada del servidor), ``incompleta_no_verificable`` (la acción no salió como se esperaba
    pero llegó una parada mientras corría: no se puede atribuir al sistema) o ``fallo_inesperado``
    (cualquier otra cosa). El cruce con la captura y el registro del servidor (cobertura_v2) puede
    rebajar después una transacción a no verificable; nunca la sube a correcta.
    """
    tipo, esperado, intencional = ESPERADO[accion]
    exc = reg.get("excepcion")
    if tipo == "http":
        reg["resultado_esperado"] = "http " + "|".join(str(c) for c in sorted(esperado))
        obs = reg.get("http_codigo")
        reg["resultado_observado"] = ("http %s" % obs) if obs is not None else ("excepcion " + str(exc))
        ok = obs in esperado and not reg.get("incompleta") and not exc
    elif tipo == "abandono":
        reg["resultado_esperado"] = "cabeceras recibidas y corte del cliente"
        reg["resultado_observado"] = ("http %s cortada" % reg.get("http_codigo")) if reg.get("cortada_por_cliente") else ("excepcion " + str(exc))
        ok = bool(reg.get("cortada_por_cliente")) and not exc
        reg["incompleta"] = True
    elif tipo == "cerrado":
        reg["resultado_esperado"] = "rst o sin_respuesta"
        reg["resultado_observado"] = reg.get("cerrado_como") or ("excepcion " + str(exc))
        ok = reg.get("cerrado_como") in ("rst", "sin_respuesta") and not exc
    elif tipo == "dns":
        rc = reg.get("dns_rcode")
        if esperado == 0:
            ip = destinos["dns_ip_esperada"]
            reg["resultado_esperado"] = "rcode 0 con A %s" % ip
            ok = rc == 0 and ip in (reg.get("dns_respuestas") or []) and reg.get("dns_id_coincide", False)
        else:
            reg["resultado_esperado"] = "rcode 3 (NXDOMAIN)"
            ok = rc == 3 and reg.get("dns_id_coincide", False)
        reg["resultado_observado"] = ("rcode %s A=%s" % (rc, ",".join(reg.get("dns_respuestas") or [])) if rc is not None else "excepcion " + str(exc))
    else:  # icmp
        reg["resultado_esperado"] = "eco respondido"
        reg["resultado_observado"] = ("rc %s" % reg.get("icmp_rc")) if "icmp_rc" in reg else ("excepcion " + str(exc))
        ok = reg.get("icmp_rc") == 0 and not exc
    reg["coincide"] = bool(ok)
    if not ok and reg.get("parada_durante_accion"):
        reg["clase"] = "incompleta_no_verificable"
    elif not ok:
        reg["clase"] = "fallo_inesperado"
    elif accion == "api_post" and reg.get("http_codigo") == 500:
        reg["clase"] = "variacion_servidor"
    else:
        reg["clase"] = "error_intencional" if intencional else "ok"
