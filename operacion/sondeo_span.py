#!/usr/bin/env python3
"""Sondeo de solo lectura del destino SPAN mediante una sesión interactiva.

Cada muestra abarca ambos comandos: envio es anterior al primero y recepcion
corresponde al prompt del segundo. intervalo_desde_anterior_s mide envio a envio
entre muestras válidas, incluido el tiempo de respuesta y cualquier reconexión.
"""

import argparse
import json
import os
import queue
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback

VERSION = "1.1"
INTERFAZ = "show interfaces GigabitEthernet2/0/19 | include output drops|packets output"
COLA = "show platform hardware fed switch 2 qos queue stats interface GigabitEthernet2/0/19 | include ^ 1 "
PROMPT = re.compile(r"(?:^|\n)[^\r\n]*#\s*$")
DROPS = re.compile(r"Total output drops:\s*(\d+)")
PAQUETES = re.compile(r"(\d+)\s+packets output,\s*(\d+)\s+bytes")
FILA = re.compile(r"^\s*1\s+\d+(?:\s+\d+)+\s*$")


class SesionPerdida(Exception):
    pass


class RespuestaAgotada(Exception):
    pass


class Detenido(Exception):
    pass


class Sesion:
    def __init__(self, comando):
        self.proceso = subprocess.Popen(
            shlex.split(comando), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0,
        )
        self.cola = queue.Queue()
        self.hilo = threading.Thread(target=self._leer, daemon=True)
        self.hilo.start()

    def _leer(self):
        try:
            while True:
                bloque = os.read(self.proceso.stdout.fileno(), 4096)
                if not bloque:
                    break
                self.cola.put(bloque)
        finally:
            self.cola.put(None)

    def respuesta(self, limite, mantener_vivo):
        partes = []
        while True:
            mantener_vivo()
            restante = limite - time.monotonic()
            if restante <= 0:
                raise RespuestaAgotada("sin prompt dentro del plazo")
            try:
                bloque = self.cola.get(timeout=min(restante, 0.2))
            except queue.Empty:
                continue
            if bloque is None:
                raise SesionPerdida("la sesión terminó antes del prompt")
            partes.append(bloque.decode("utf-8", errors="replace").replace("\r", ""))
            texto = "".join(partes)
            if PROMPT.search(texto):
                return texto, time.time()

    def comando(self, orden, segundos, mantener_vivo):
        mantener_vivo()
        envio = time.time()
        try:
            self.proceso.stdin.write((orden + "\n").encode("utf-8"))
            self.proceso.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise SesionPerdida(str(exc)) from exc
        texto, recepcion = self.respuesta(time.monotonic() + segundos, mantener_vivo)
        return envio, recepcion, texto

    def cerrar(self):
        if self.proceso.poll() is None:
            self.proceso.kill()
        try:
            self.proceso.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        self.proceso.stdout.close()
        self.proceso.stdin.close()


def extraer(interfaz, cola):
    drops = DROPS.search(interfaz)
    paquetes = PAQUETES.search(interfaz)
    filas = [linea for linea in cola.splitlines() if FILA.fullmatch(linea)]
    if not (drops and paquetes and filas):
        raise ValueError("faltan contadores o filas numéricas de la cola 1")
    return int(drops.group(1)), int(paquetes.group(1)), int(paquetes.group(2)), "\n".join(filas)


def recortar(texto, limite=2000):
    return texto[-limite:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--salida", required=True)
    parser.add_argument("--hasta-epoch", required=True, type=float)
    parser.add_argument("--cada-s", type=float, default=2)
    parser.add_argument("--comando-ssh", default="ssh -tt -o BatchMode=yes sw-core-stack")
    parser.add_argument("--pid")
    parser.add_argument("--tiempo-max-respuesta-s", type=float, default=20)
    # Plazo para el prompt inicial y «terminal length 0» de una sesión NUEVA. Por omisión, el mismo
    # que el de respuesta (comportamiento anterior). Separado porque abrir la sesión (ssh, o el
    # switch falso de las pruebas) puede tardar más que responder a un comando.
    parser.add_argument("--tiempo-max-conexion-s", type=float, default=None)
    args = parser.parse_args(argv)
    if args.tiempo_max_conexion_s is None:
        args.tiempo_max_conexion_s = args.tiempo_max_respuesta_s
    if args.cada_s <= 0 or args.tiempo_max_respuesta_s <= 0 or args.tiempo_max_conexion_s <= 0:
        parser.error("los tiempos deben ser positivos")

    detenido = [False]
    def senal(_signum, _frame):
        detenido[0] = True
    signal.signal(signal.SIGTERM, senal)
    signal.signal(signal.SIGINT, senal)

    salida = None
    sesion = None
    ultimo = None
    causa_hueco = None
    inicio = time.time()
    ultimo_latido = inicio
    siguiente = inicio
    intento = 0
    espera_reconexion = 2
    estado = "hasta_epoch"
    codigo = 0
    try:
        salida = open(args.salida, "a", encoding="utf-8", newline="\n")
        def registrar(tipo, **datos):
            json.dump({"t": time.time(), "tipo": tipo, **datos}, salida, ensure_ascii=False)
            salida.write("\n")
            salida.flush()
            os.fsync(salida.fileno())

        def mantener_vivo():
            nonlocal ultimo_latido
            ahora = time.time()
            if ahora - ultimo_latido >= 60:
                registrar("latido")
                ultimo_latido = ahora
            if detenido[0]:
                raise Detenido
            if ahora >= args.hasta_epoch:
                raise TimeoutError("hasta_epoch")

        def dormir(segundos):
            limite = time.monotonic() + segundos
            while time.monotonic() < limite:
                mantener_vivo()
                time.sleep(min(0.2, limite - time.monotonic()))

        if args.pid:
            with open(args.pid, "w", encoding="ascii") as archivo_pid:
                archivo_pid.write(str(os.getpid()) + "\n")
                archivo_pid.flush()
                os.fsync(archivo_pid.fileno())
        registrar("arranque", version=VERSION, parametros={
            "salida": args.salida, "hasta_epoch": args.hasta_epoch,
            "cada_s": args.cada_s, "comando_ssh": args.comando_ssh,
            "pid": args.pid, "tiempo_max_respuesta_s": args.tiempo_max_respuesta_s,
            "tiempo_max_conexion_s": args.tiempo_max_conexion_s,
        }, pid=os.getpid(), host=socket.gethostname())

        while True:
            mantener_vivo()
            if sesion is None:
                intento += 1
                try:
                    sesion = Sesion(args.comando_ssh)
                    sesion.respuesta(time.monotonic() + args.tiempo_max_conexion_s, mantener_vivo)
                    sesion.comando("terminal length 0", args.tiempo_max_conexion_s, mantener_vivo)
                    registrar("conexion", intento=intento, ok=True, error=None)
                    espera_reconexion = 2
                    siguiente = time.monotonic()
                except (SesionPerdida, RespuestaAgotada, OSError) as exc:
                    registrar("conexion", intento=intento, ok=False, error=str(exc))
                    causa_hueco = causa_hueco or ("timeout" if isinstance(exc, RespuestaAgotada) else "desconexion")
                    if sesion is not None:
                        sesion.cerrar()
                        sesion = None
                    dormir(espera_reconexion)
                    espera_reconexion = min(30, espera_reconexion * 2)
                    continue
            dormir(max(0, siguiente - time.monotonic()))
            try:
                envio, _, interfaz = sesion.comando(INTERFAZ, args.tiempo_max_respuesta_s, mantener_vivo)
                _, recepcion, cola = sesion.comando(COLA, args.tiempo_max_respuesta_s, mantener_vivo)
                try:
                    drops, paquetes, bytes_salida, filas = extraer(interfaz, cola)
                except ValueError as exc:
                    registrar("respuesta_invalida", error=str(exc), texto=recortar(interfaz + "\n" + cola))
                    causa_hueco = causa_hueco or "respuesta_invalida"
                    siguiente = time.monotonic() + args.cada_s
                    continue
                if ultimo is None and envio - inicio > args.cada_s:
                    registrar("hueco", desde=inicio, hasta=envio, causa="arranque_retrasado")
                if ultimo is not None and causa_hueco:
                    registrar("hueco", desde=ultimo["recepcion"], hasta=envio, causa=causa_hueco)
                if ultimo is not None and drops < ultimo["drops"]:
                    registrar("contador_disminuye", antes=ultimo["drops"], despues=drops,
                              desde=ultimo["envio"], hasta=recepcion)
                muestra = {
                    "envio": envio, "recepcion": recepcion, "drops": drops,
                    "paquetes_salida": paquetes, "bytes_salida": bytes_salida,
                    "cola1_filas": filas, "latencia_s": recepcion - envio,
                    "intervalo_desde_anterior_s": envio - ultimo["envio"] if ultimo else None,
                }
                registrar("muestra", **muestra)
                ultimo = muestra
                causa_hueco = None
                siguiente = time.monotonic() + args.cada_s
            except (SesionPerdida, RespuestaAgotada) as exc:
                causa_hueco = causa_hueco or ("timeout" if isinstance(exc, RespuestaAgotada) else "desconexion")
                sesion.cerrar()
                sesion = None
                dormir(espera_reconexion)
                espera_reconexion = min(30, espera_reconexion * 2)
    except Detenido:
        estado = "señal"
    except TimeoutError as exc:
        if str(exc) != "hasta_epoch":
            raise
    except Exception:
        estado = "error"
        codigo = 1
        if salida is not None:
            try:
                registrar("error_supervisor", traza=recortar(traceback.format_exc(), 4000))
            except Exception:
                traceback.print_exc(file=sys.stderr)
        else:
            traceback.print_exc(file=sys.stderr)
    finally:
        if sesion is not None:
            sesion.cerrar()
        if salida is not None:
            try:
                registrar("fin", motivo=estado)
            except Exception:
                codigo = 1
                traceback.print_exc(file=sys.stderr)
            salida.close()
        if args.pid:
            try:
                with open(args.pid, encoding="ascii") as archivo_pid:
                    propio = archivo_pid.read().strip() == str(os.getpid())
                if propio:
                    os.unlink(args.pid)
            except FileNotFoundError:
                pass
    return codigo


if __name__ == "__main__":
    sys.exit(main())
