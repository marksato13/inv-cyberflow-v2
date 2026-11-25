"""Transacciones DNS y HTTP medidas por intercambio."""
from __future__ import annotations
import socket
import ssl
import struct

ESPERA_TCP_S = 5.0
ESPERA_HTTP_S = 10.0
ESPERA_DNS_S = 3.0

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
        self.cierre = None

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
        # Paridad con V1 (ssl.wrap_socket con suppress_ragged_eofs=True): un cierre TCP sin
        # close_notify es fin de datos, no error. La integridad la sigue juzgando Content-Length.
        try:
            return self._hacer(lambda: self.tls.read(n))
        except ssl.SSLZeroReturnError:
            self.cierre = "close_notify"
            return b""
        except ssl.SSLEOFError:
            self.cierre = "sin_close_notify"
            return b""

    def version(self):
        return self.tls.version()

    def close(self):
        self.s.close()


class Cliente:
    """Cliente DNS y HTTP/1.1 con una conexión reutilizable por página P2."""

    def __init__(self, origen: str, destinos: dict, contenido=None, red=None):
        self.origen = origen
        self.d = destinos
        self.contenido = contenido
        self.red = red or contenido
        self.pagina = None

    def _conectar(self, ip, puerto, reg):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(ESPERA_TCP_S)
            if self.origen:
                s.bind((self.origen, 0))
            s.connect((ip, puerto))
            s.settimeout(ESPERA_HTTP_S)
            reg["origen_puerto"] = s.getsockname()[1]
            return s
        except BaseException:
            s.close()
            raise

    def _abrir(self, ip, https, reg):
        puerto = self.d["puerto_https"] if https else self.d["puerto_http"]
        s = self._conectar(ip, puerto, reg)
        tls = None
        if https:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls = TLSMedido(s, ctx, self.d["servidor"])
                tls.handshake()
                reg["tls_version"] = tls.version()
                s = tls
            except BaseException:
                s.close()
                raise
        return {"socket": s, "tls": tls, "medidor": Medidor(s),
                "puerto": reg.get("origen_puerto"), "buffer": b""}

    def cerrar_pagina(self):
        if self.pagina:
            self.pagina["socket"].close()
            self.pagina = None

    def _http(self, reg, ruta, metodo="GET", cuerpo=None, https=False, ip=None,
              persistente=False):
        ip = ip or self.d["servidor"]
        puerto = self.d["puerto_https"] if https else self.d["puerto_http"]
        reg.update(destino_ip=ip, destino_puerto=puerto, ruta=ruta, metodo=metodo,
                   protocolo="https" if https else "http",
                   visibilidad_l7="cifrada" if https else "visible")
        nueva = not (persistente and self.pagina)
        if not nueva:
            conexion = self.pagina
            reg["origen_puerto"] = conexion["puerto"]
        else:
            conexion = self._abrir(ip, https, reg)
            if persistente:
                self.pagina = conexion
        m = conexion["medidor"]
        tls = conexion["tls"]
        tx0 = 0 if nueva else (tls.tx if tls else m.tx)
        rx0 = 0 if nueva else (tls.rx if tls else m.rx)
        plano_tx0, plano_rx0 = m.tx, m.rx
        try:
            cab = ("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: %s\r\n" %
                   (metodo, ruta, self.d["servidor"],
                    "keep-alive" if persistente else "close"))
            if cuerpo is not None:
                cab += "Content-Length: %d\r\nContent-Type: application/octet-stream\r\n" % len(cuerpo)
            m.enviar(cab.encode("ascii") + b"\r\n" + (cuerpo or b""))
            buf = conexion["buffer"]
            while b"\r\n\r\n" not in buf:
                dato = m.recibir()
                if not dato:
                    raise ConnectionError("respuesta HTTP sin cabeceras completas")
                buf += dato
            cabeceras, buf = buf.split(b"\r\n\r\n", 1)
            linea = cabeceras.split(b"\r\n", 1)[0].split()
            if len(linea) < 2 or not linea[1].isdigit():
                raise ValueError("línea de estado HTTP inválida")
            reg["http_codigo"] = int(linea[1])
            largo = None
            for linea in cabeceras.split(b"\r\n")[1:]:
                if linea.lower().startswith(b"content-length:"):
                    largo = int(linea.split(b":", 1)[1].strip())
            reg["http_content_length"] = largo
            if largo is None:
                raise ValueError("falta Content-Length")
            cuerpo_rx = min(len(buf), largo)
            buf = buf[cuerpo_rx:]
            while cuerpo_rx < largo:
                dato = m.recibir(min(65536, largo - cuerpo_rx))
                if not dato:
                    reg["incompleta"] = True
                    break
                cuerpo_rx += len(dato)
            reg["bytes_cuerpo_recibidos"] = cuerpo_rx
            reg["http_cuerpo_bytes"] = cuerpo_rx
            conexion["buffer"] = buf
        finally:
            reg["bytes_tcp_enviados"] = (tls.tx if tls else m.tx) - tx0
            reg["bytes_tcp_recibidos"] = (tls.rx if tls else m.rx) - rx0
            reg["bytes_enviados"] = m.tx - plano_tx0
            reg["bytes_recibidos"] = m.rx - plano_rx0
            if tls:
                reg["tls_cierre"] = tls.cierre
            if not persistente:
                conexion["socket"].close()

    def dns(self, reg, nombre):
        tid = self.red.randint(0, 65535)
        cabecera = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        pregunta = b"".join(bytes([len(x)]) + x.encode("ascii") for x in nombre.split(".")) + b"\x00"
        paquete = cabecera + pregunta + struct.pack("!HH", 1, 1)
        servidor = self.d["dns_servidor"]
        reg.update(destino_ip=servidor, destino_puerto=53, protocolo="dns",
                   dns_nombre=nombre, dns_id=tid, bytes_enviados=len(paquete))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(ESPERA_DNS_S)
        try:
            if self.origen:
                s.bind((self.origen, 0))
            reg["origen_puerto"] = s.getsockname()[1]
            s.sendto(paquete, (servidor, 53))
            respuesta, _ = s.recvfrom(4096)
            reg["bytes_recibidos"] = len(respuesta)
        finally:
            s.close()
        rtid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", respuesta[:12])
        ips, ttl = _registros_a(respuesta, qd, an)
        reg.update(dns_id_coincide=rtid == tid, dns_rcode=flags & 15,
                   dns_respuestas=ips, dns_ttl=ttl)
        return ips[0] if ips else None

    def obtener(self, reg, ip, tamano, tipo_objeto="objeto", https=False, persistente=False):
        reg.update(bytes_solicitados=tamano, tipo_objeto=tipo_objeto)
        self._http(reg, "/contenido/%d?tipo=%s" % (tamano, tipo_objeto),
                   https=https, ip=ip, persistente=persistente)

    def consulta(self, reg, ip, ref):
        reg.update(bytes_solicitados=512, tipo_objeto="consulta")
        self._http(reg, "/app/consulta?ref=%s" % ref, ip=ip)

    def envio(self, reg, ip, cuerpo):
        reg.update(bytes_solicitados=len(cuerpo), tipo_objeto="envio")
        self._http(reg, "/app/envio", metodo="POST", cuerpo=cuerpo, ip=ip)


def _saltar_nombre(m: bytes, i: int) -> int:
    while True:
        n = m[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def _registros_a(m: bytes, qd: int, an: int) -> tuple[list[str], int | None]:
    i = 12
    for _ in range(qd):
        i = _saltar_nombre(m, i) + 4
    ips = []
    ttl_primero = None
    for _ in range(an):
        i = _saltar_nombre(m, i)
        tipo, clase, ttl, largo = struct.unpack("!HHIH", m[i:i + 10])
        i += 10
        if tipo == 1 and clase == 1 and largo == 4:
            ips.append(socket.inet_ntoa(m[i:i + 4]))
            if ttl_primero is None:
                ttl_primero = ttl
        i += largo
    return ips, ttl_primero


def clasificar(accion: str, reg: dict, destinos: dict) -> None:
    exc = reg.get("excepcion")
    if accion == "dns":
        esperado = destinos["dns_ip_esperada"]
        reg["resultado_esperado"] = "rcode 0 con A %s e id coincidente" % esperado
        reg["resultado_observado"] = "rcode %s A=%s" % (
            reg.get("dns_rcode"), ",".join(reg.get("dns_respuestas") or []))
        ok = (reg.get("dns_rcode") == 0 and
              esperado in (reg.get("dns_respuestas") or []) and
              reg.get("dns_id_coincide") is True)
    else:
        codigo = 201 if accion == "envio" else 200
        largo = reg.get("bytes_cuerpo_recibidos", reg.get("http_cuerpo_bytes"))
        reg["resultado_esperado"] = "http %d" % codigo
        reg["resultado_observado"] = "http %s cuerpo %s" % (reg.get("http_codigo"), largo)
        ok = reg.get("http_codigo") == codigo
        if accion == "obtener":
            ok = ok and largo == reg.get("bytes_solicitados") == reg.get("http_content_length")
        elif accion == "consulta":
            ok = ok and largo == reg.get("http_content_length") == 512
    ok = bool(ok and not exc and not reg.get("incompleta"))
    reg["coincide"] = ok
    reg["clase"] = ("ok" if ok else "incompleta_no_verificable"
                    if reg.get("parada_durante_accion") else "fallo_inesperado")
