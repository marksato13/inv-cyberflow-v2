#!/usr/bin/env python3
"""Generador v3: una secuencia de tráfico legítimo por perfil."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import random
import signal
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import distribuciones as dist
import programa as prg
import transacciones as tx

VERSION = "3.0.0"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


class Registro:
    def __init__(self, ruta):
        self.f = open(ruta, "a", encoding="utf-8")

    def escribir(self, obj):
        self.f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        self.f.flush()

    def cerrar(self):
        os.fsync(self.f.fileno())
        self.f.close()


class Generador:
    """Reloj, dormir y ejecutar son inyectables para pruebas sin red."""

    def __init__(self, prog, prog_sha, perfil, origen, ejecucion, salida,
                 reloj=time.monotonic, dormir=None, ejecutar=None):
        prg.validar(prog)
        self.prog, self.prog_sha, self.perfil = prog, prog_sha, perfil
        self.origen, self.ejecucion = origen, ejecucion
        self.p = prog["perfiles"][perfil]
        self.reloj = reloj
        self.dormir = dormir or self._dormir_interrumpible
        self.ejecutar = ejecutar or self._ejecutar_real
        self.parar = False
        self.motivo_parada = None
        self.inyectado = ejecutar is not None
        self.rng_espera = random.Random()
        self.rng_contenido = random.Random()
        self.rng_red = random.Random()
        self.bloque = None
        self.jornada = None
        self.nivel = None
        self.en_on = None
        self.cliente = None
        self.cliente_pagina = None
        self.t0 = None
        self.n = 0
        self.secuencia = 0
        self.conexion_n = 0
        self.paginas_bloque = 0
        self.p4_paso = 0
        self.p4_ip = None
        self.p4_ref = None
        self.dns_id_actual = None
        salida.mkdir(parents=True, exist_ok=True)
        self.tx_log = Registro(salida / ("transacciones-%s.jsonl" % perfil))
        self.ev_log = Registro(salida / ("eventos-%s.jsonl" % perfil))

    def _t(self):
        return self.reloj() - self.t0

    def _dormir_interrumpible(self, segundos):
        fin = self.reloj() + segundos
        while not self.parar:
            queda = fin - self.reloj()
            if queda <= 0:
                return
            time.sleep(min(queda, 0.5))

    def evento(self, tipo, t, **extra):
        self.ev_log.escribir(dict(extra, tipo=tipo, utc=utc(),
                                  t_s=round(t, 6), ejecucion_id=self.ejecucion,
                                  perfil=self.perfil, pid=os.getpid()))

    def senal(self, signum, _frame):
        self.parar = True
        self.motivo_parada = signal.Signals(signum).name

    def _actualizar(self, t):
        b = prg.tramo_en(self.prog["bloques"], t)
        if self.bloque is None or b["id"] != self.bloque["id"]:
            self.bloque = b
            semillas = b["semillas"][self.perfil]
            for flujo in prg.FLUJOS:
                getattr(self, "rng_" + flujo).seed(semillas[flujo])
            self.cliente = tx.Cliente(self.origen, self.prog["destinos"],
                                      self.rng_contenido, self.rng_red)
            self.paginas_bloque = 0
            self.evento("bloque", t, bloque_id=b["id"], particion=b["particion"],
                        semillas=semillas)
        j = prg.tramo_en(self.prog["jornadas"], t)
        if j["id"] != self.jornada:
            self.jornada = j["id"]
            self.evento("jornada", t, jornada_id=self.jornada, patron=j["patron"])
        nivel = prg.nivel_en(self.prog, self.perfil, t)
        if nivel != self.nivel:
            self.nivel = nivel
            self.evento("nivel", t, nivel=nivel,
                        factor=self.prog["factores"][nivel])
        if self.perfil == "P6":
            en_on = prg.on_p6(self.prog, t)
            if en_on != self.en_on:
                self.en_on = en_on
                self.evento("on" if en_on else "off", t)

    def _habilitado(self, t):
        if t >= self.prog["duracion_s"] or self.parar:
            return False
        self._actualizar(t)
        return (self.prog["factores"][self.nivel] > 0 and
                (self.perfil != "P6" or self.en_on))

    def _esperar(self):
        """Espera sorteada y resorteada tras cualquier borde; devuelve tiempo real."""
        acumulada = 0.0
        dur = self.prog["duracion_s"]
        while not self.parar and self._t() < dur:
            t = self._t()
            self._actualizar(t)
            borde = min(prg.proximo_borde(self.prog, self.perfil, t), dur)
            factor = self.prog["factores"][self.nivel]
            if factor == 0 or (self.perfil == "P6" and not self.en_on):
                paso = borde - t
                self.dormir(paso)
                acumulada += paso
                continue
            espera = dist.pausa(self.rng_espera, self.p["media_espera_s"], factor)
            if t + espera >= borde:
                paso = borde - t
                self.dormir(paso)
                acumulada += paso
                self.evento("pausa_cortada", borde, desde_s=t,
                            espera_s=espera, borde_s=borde)
                continue
            self.dormir(espera)
            acumulada += espera
            if self._habilitado(self._t()):
                return acumulada
        return None

    def _ejecutar_real(self, accion, reg):
        if accion == "dns":
            self.cliente.dns(reg, reg["dns_nombre"])
        elif accion == "obtener":
            (self.cliente_pagina or self.cliente).obtener(reg, reg["ip_resuelta"], reg["bytes_solicitados"],
                                 reg["tipo_objeto"], reg["protocolo"] == "https",
                                 reg.get("persistente", False))
        elif accion == "consulta":
            self.cliente.consulta(reg, reg["ip_resuelta"], reg["ref"])
        elif accion == "envio":
            self.cliente.envio(reg, reg["ip_resuelta"], reg["cuerpo_post"])

    def _accion(self, accion, paso, secuencia_id, espera_previa_s=0.0, **extra):
        t = self._t()
        if not self._habilitado(t):
            return None
        self.n += 1
        if accion != "dns" and extra.get("conexion_n") is None:
            self.conexion_n += 1
            extra["conexion_n"] = self.conexion_n
        reg = {"ejecucion_id": self.ejecucion,
               "transaccion_id": "%s-%s-%09d" % (self.ejecucion, self.perfil, self.n),
               "programa_sha256": self.prog_sha, "perfil": self.perfil,
               "secuencia_id": secuencia_id, "paso": paso, "accion": accion,
               "tipo_objeto": "objeto" if accion == "dns" else extra.get("tipo_objeto"),
               "inicio_utc": utc(), "inicio_t_s": round(t, 6),
               "origen_ip": self.origen, "jornada_id": self.jornada,
               "bloque_id": self.bloque["id"], "particion": self.bloque["particion"],
               "nivel": self.nivel, "factor": self.prog["factores"][self.nivel],
               "en_on": self.en_on if self.perfil == "P6" else None,
               "espera_previa_s": round(espera_previa_s, 6),
               "bytes_solicitados": None, "bytes_cuerpo_recibidos": None,
               "dns_ttl": None, "dns_id": self.dns_id_actual if accion != "dns" else None,
               "conexion_n": None, "peticion_en_conexion": None,
               "visibilidad_l7": ("cifrada" if extra.get("protocolo") == "https" else
                                  "visible" if accion != "dns" else None),
               "origen_puerto": None,
               "bytes_tcp_enviados": 0, "bytes_tcp_recibidos": 0,
               "http_codigo": None, "timeout": False, "incompleta": False,
               "excepcion": None}
        reg.update(extra)
        try:
            self.ejecutar(accion, reg)
        except (socket.timeout, TimeoutError) as exc:
            reg["timeout"] = True
            reg["excepcion"] = "%s: %s" % (type(exc).__name__, str(exc)[:120])
        except Exception as exc:
            reg["excepcion"] = "%s: %s" % (type(exc).__name__, str(exc)[:120])
        fin = self._t()
        reg["fin_utc"] = utc()
        reg["duracion_s"] = round(fin - t, 6)
        reg["tras_fin_programa"] = fin > self.prog["duracion_s"]
        reg["parada_durante_accion"] = self.parar
        reg["cruza_borde_on"] = (self.perfil == "P6" and
                                t % 180 < 60 and
                                fin > 180 * int(t // 180) + 60)
        reg.pop("cuerpo_post", None)
        tx.clasificar(accion, reg, self.prog["destinos"])
        self.tx_log.escribir(reg)
        return reg

    def _dns(self, secuencia, espera):
        nombre = "%s.%s" % (self.rng_contenido.choice(self.prog["destinos"]["dns_nombres"]),
                             self.prog["destinos"]["dns_zona"])
        reg = self._accion("dns", "dns", secuencia, espera, dns_nombre=nombre,
                           protocolo="dns", destino_ip=self.prog["destinos"]["dns_servidor"],
                           destino_puerto=53, dns_id=self.rng_red.randint(0, 65535)
                           if self.inyectado else None)
        if reg and reg["clase"] == "ok":
            self.dns_id_actual = reg.get("dns_id")
            ips = reg.get("dns_respuestas") or []
            return ips[0] if ips else None
        return None

    def _web(self, espera):
        self.secuencia += 1
        sid = self.secuencia
        ip = self._dns(sid, espera)
        if not ip or self.parar:
            return
        self._actualizar(self._t())
        tamano = dist.f1(self.rng_contenido) if self.perfil == "P3" else dist.h1(self.rng_contenido)
        tipo = "archivo" if self.perfil == "P3" else "objeto"
        self._accion("obtener", "obtener", sid, tipo_objeto=tipo,
                     bytes_solicitados=tamano, ip_resuelta=ip, protocolo="http",
                     peticion_en_conexion=1)

    def _navegacion(self, espera):
        self.secuencia += 1
        sid = self.secuencia
        ip = self._dns(sid, espera)
        if not ip or self.parar:
            return
        self._actualizar(self._t())
        https = self.paginas_bloque % 2 == 1
        self.paginas_bloque += 1
        protocolo = "https" if https else "http"
        self.conexion_n += 1
        conexion = self.conexion_n
        self.cliente_pagina = self.cliente
        try:
            principal = self._accion("obtener", "principal", sid,
                                    tipo_objeto="principal", bytes_solicitados=dist.h1(self.rng_contenido),
                                    ip_resuelta=ip, protocolo=protocolo, persistente=True,
                                    conexion_n=conexion, peticion_en_conexion=1)
            if not principal or principal["clase"] != "ok" or self.parar:
                return
            self.dormir(dist.parsing(self.rng_espera))
            self._actualizar(self._t())
            n = dist.h3(self.rng_contenido)
            for i in range(n):
                if self.parar or self._t() >= self.prog["duracion_s"]:
                    break
                if not self._habilitado(self._t()):
                    while not self._habilitado(self._t()) and self._t() < self.prog["duracion_s"] and not self.parar:
                        t = self._t()
                        self.dormir(prg.proximo_borde(self.prog, self.perfil, t) - t)
                if self.parar or self._t() >= self.prog["duracion_s"]:
                    break
                secundario = self._accion("obtener", "secundario_%d" % (i + 1), sid,
                                         tipo_objeto="secundario",
                                         bytes_solicitados=dist.h2(self.rng_contenido),
                                         ip_resuelta=ip, protocolo=protocolo,
                                         persistente=True, conexion_n=conexion,
                                         peticion_en_conexion=i + 2)
                if not secundario or secundario["clase"] != "ok":
                    break
        finally:
            if self.cliente_pagina:
                self.cliente_pagina.cerrar_pagina()
                self.cliente_pagina = None

    def _transaccional(self, espera):
        if self.p4_paso == 0:
            self.secuencia += 1
            self.p4_ip = self._dns(self.secuencia, espera)
            if not self.p4_ip or self.parar:
                self.p4_paso = 0
                return
            self._actualizar(self._t())
            self.p4_ref = self.rng_contenido.randint(0, 999999)
        paso = self.p4_paso
        accion = "envio" if paso == 1 else "consulta"
        extra = {"ip_resuelta": self.p4_ip, "protocolo": "http",
                 "peticion_en_conexion": 1}
        if accion == "envio":
            extra["cuerpo_post"] = self.rng_contenido.randbytes(
                self.rng_contenido.randint(200, 8000))
            extra["bytes_solicitados"] = len(extra["cuerpo_post"])
        else:
            extra["ref"] = self.p4_ref
            extra["bytes_solicitados"] = 512
        reg = self._accion(accion, ("consulta", "envio", "consulta_final")[paso],
                           self.secuencia, 0 if paso == 0 else espera, **extra)
        self.p4_paso = paso + 1 if reg and reg["clase"] == "ok" and paso < 2 else 0

    def correr(self):
        self.t0 = self.reloj()
        dur = self.prog["duracion_s"]
        self.evento("inicio", 0, version=VERSION, python=platform.python_version(),
                    programa_id=self.prog["programa_id"], programa_sha256=self.prog_sha,
                    origen_ip=self.origen, duracion_s=dur, host=socket.gethostname())
        estado = "completa"
        try:
            while not self.parar and self._t() < dur:
                espera = self._esperar()
                if espera is None:
                    break
                if self.perfil == "P2":
                    self._navegacion(espera)
                elif self.perfil == "P4":
                    self._transaccional(espera)
                else:
                    self._web(espera)
            if self.parar:
                estado = "interrumpida"
        finally:
            if self.cliente:
                self.cliente.cerrar_pagina()
            self.evento("fin", self._t(), estado=estado, motivo=self.motivo_parada,
                        transacciones=self.n)
            self.tx_log.cerrar()
            self.ev_log.cerrar()
        return estado


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--programa", required=True)
    ap.add_argument("--validar", action="store_true")
    ap.add_argument("--perfil", choices=prg.PERFILES)
    ap.add_argument("--origen", default="")
    ap.add_argument("--ejecucion")
    ap.add_argument("--salida")
    a = ap.parse_args()
    prog = prg.cargar(a.programa)
    if a.validar:
        print("programa válido: %s (%s s)" % (prog["programa_id"], prog["duracion_s"]))
        return 0
    if not a.perfil or not a.ejecucion or not a.salida:
        ap.error("hacen falta --perfil, --ejecucion y --salida")
    origen = a.origen or prog["perfiles"][a.perfil]["origen"]
    gen = Generador(prog, prg.huella(a.programa), a.perfil, origen,
                    a.ejecucion, Path(a.salida))
    signal.signal(signal.SIGTERM, gen.senal)
    signal.signal(signal.SIGINT, gen.senal)
    return 0 if gen.correr() == "completa" else 3


if __name__ == "__main__":
    raise SystemExit(main())
