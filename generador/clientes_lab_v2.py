#!/usr/bin/env python3
"""Generador de tráfico legítimo de CyberFlow V2: un perfil, una ejecución finita.

Deriva de ``scripts/laboratorio/clientes_lab.py`` de inv-cyberflow-sistema
(commit d2c97728916c2484f770a7a16a984c4c6bd42175). Diferencias con V1 (detalle en
docs/PROCEDENCIA.md):

1. Duración finita: el programa fija ``duracion_s``; al cumplirse no empieza más acciones,
   termina la que esté en curso, la registra y sale con código 0.
2. Identificadores: cada registro lleva ejecución, jornada, perfil, bloque, fase y un
   identificador de transacción único (``<ejecucion>-<perfil>-<n>``).
3. Semillas: una por perfil y bloque, fijadas en el programa y registradas. Al entrar en
   un bloque el generador se vuelve a sembrar con la semilla de ese bloque.
4. Programa por tiempo transcurrido (reloj monotónico) en vez de ``factor_horario(now())``
   y del factor de fin de semana. Las esperas siguen siendo exponenciales con la misma
   fórmula de V1, ``expovariate(1 / max(ritmo / factor, 0.05))``: el piso de 0,05 s se aplica
   a la MEDIA de la exponencial, no a cada espera, así que puede haber esperas < 0,05 s.
   Si una espera cruza un cambio de fase o pulso, se corta en el borde y se vuelve a
   sortear con el factor nuevo (proceso de Poisson por tramos; V1 dormía la espera entera).
5. Registro por transacción (JSONL, una línea por acción, escrita y vaciada al momento) y
   registro de eventos (inicio, cambios de fase, ráfagas, señales, fin).
6. Parada controlada con SIGTERM/SIGINT: termina la acción en curso, registra y sale.
   Sin reinicio automático: un reinicio es una ejecución nueva y queda registrado.

Uso:
    python3 clientes_lab_v2.py --programa J1.json --perfil ofimatica --origen 10.10.20.21 \\
        --ejecucion V2-J1-20261201T130000Z --salida /ruta/ejecucion
    python3 clientes_lab_v2.py --programa J1.json --validar
"""
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
import programa as prg  # noqa: E402
import transacciones as tx  # noqa: E402

VERSION = "2.0.0"


def utc(ts: float | None = None) -> str:
    t = datetime.datetime.fromtimestamp(time.time() if ts is None else ts, datetime.timezone.utc)
    return t.isoformat(timespec="microseconds").replace("+00:00", "Z")


class Registro:
    """Escritor JSONL que vacía cada línea y hace fsync cada ``cada`` líneas."""

    def __init__(self, ruta: Path, cada: int = 20):
        self.f = open(ruta, "a", encoding="utf-8")
        self.n = 0
        self.cada = cada

    def escribir(self, obj: dict) -> None:
        self.f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        self.f.flush()
        self.n += 1
        if self.n % self.cada == 0:
            os.fsync(self.f.fileno())

    def cerrar(self) -> None:
        self.f.flush()
        os.fsync(self.f.fileno())
        self.f.close()


class Generador:
    """Bucle de un perfil. Reloj, espera y ejecución de acciones son inyectables (pruebas)."""

    def __init__(self, prog: dict, prog_sha: str, perfil: str, origen: str, ejecucion: str,
                 salida: Path, reloj=time.monotonic, dormir=None, ejecutar=None):
        self.prog, self.prog_sha, self.perfil = prog, prog_sha, perfil
        self.origen, self.ejecucion = origen, ejecucion
        self.jornada = prog.get("jornada_id", prog["programa_id"])
        self.p = prog["perfiles"][perfil]
        self.acciones = sorted(self.p["acciones"])
        self.pesos = [self.p["acciones"][a] for a in self.acciones]
        self.raf = prog.get("rafagas", {}).get(perfil)
        self.reloj = reloj
        self.parar = False
        self.motivo_parada = None
        self.dormir = dormir or self._dormir_interrumpible
        self.ejecutar = ejecutar or self._ejecutar_real
        salida.mkdir(parents=True, exist_ok=True)
        self.tx_log = Registro(salida / ("transacciones-%s.jsonl" % perfil))
        self.ev_log = Registro(salida / ("eventos-%s.jsonl" % perfil), cada=1)
        self.rng = random.Random()
        self.bloque = None
        self.cliente = None

    # -- infraestructura --------------------------------------------------
    def _dormir_interrumpible(self, segundos: float) -> None:
        fin = self.reloj() + segundos
        while not self.parar:
            r = fin - self.reloj()
            if r <= 0:
                return
            time.sleep(min(r, 0.5))

    def evento(self, tipo: str, t: float, **extra) -> None:
        self.ev_log.escribir(dict(extra, tipo=tipo, utc=utc(), t_s=round(t, 6), ejecucion_id=self.ejecucion,
                                  jornada_id=self.jornada, perfil=self.perfil, pid=os.getpid()))

    def senal(self, signum, _frame) -> None:
        self.parar = True
        self.motivo_parada = signal.Signals(signum).name

    def _entrar_bloque(self, t: float) -> None:
        b = prg.tramo_en(self.prog["bloques"], t)
        if self.bloque is None or b["id"] != self.bloque["id"]:
            self.bloque = b
            semilla = b["semillas"][self.perfil]
            self.rng.seed(semilla)
            self.cliente = tx.Cliente(self.origen, self.prog["destinos"], self.prog["tamanos"], self.rng)
            self.evento("bloque", t, bloque_id=b["id"], semilla=semilla, particion=b.get("particion"))

    def _ejecutar_real(self, accion: str, reg: dict) -> None:
        getattr(self.cliente, accion)(reg)

    # -- bucle -------------------------------------------------------------
    def correr(self) -> str:
        dur = self.prog["duracion_s"]
        t0 = self.reloj()
        self.evento("inicio", 0.0, version=VERSION, programa_id=self.prog["programa_id"],
                    programa_sha256=self.prog_sha, origen_ip=self.origen, duracion_s=dur,
                    host=socket.gethostname(), python=platform.python_version(),
                    ritmo_s=self.p["ritmo_s"], acciones=self.p["acciones"])
        n = 0
        fase_id = None
        en_rafaga, fin_rafaga, rafaga_id = False, 0.0, None
        espera_previa = 0.0
        estado = "completa"
        while True:
            t = self.reloj() - t0
            if self.parar:
                estado = "interrumpida"
                break
            if t >= dur:
                break
            self._entrar_bloque(t)
            f, fase, pulsos = prg.factor(self.prog, self.perfil, t)
            if fase["id"] != fase_id:
                fase_id = fase["id"]
                self.evento("fase", t, fase_id=fase_id, factor_programado=f, pulsos=pulsos)
            if f <= 0:
                # Pausa programada: no hay acciones hasta el próximo cambio.
                hasta = min(prg.proximo_cambio(self.prog, t), dur)
                self.evento("pausa", t, hasta_s=hasta)
                self.dormir(max(hasta - t, 0.0))
                espera_previa = 0.0
                continue
            if self.raf:
                if en_rafaga and t > fin_rafaga:
                    en_rafaga = False
                    self.evento("rafaga_fin", t, rafaga_id=rafaga_id)
                elif not en_rafaga and self.rng.random() < self.raf["probabilidad_por_iteracion"]:
                    en_rafaga = True
                    lo, hi = self.raf["duracion_s"]
                    fin_rafaga = t + self.rng.uniform(lo, hi)
                    rafaga_id = "R%05d" % n
                    self.evento("rafaga_inicio", t, rafaga_id=rafaga_id, hasta_s=round(fin_rafaga, 3))
                if en_rafaga:
                    f *= self.raf["factor"]
            accion = self.rng.choices(self.acciones, weights=self.pesos)[0]
            n += 1
            reg = {"ejecucion_id": self.ejecucion, "jornada_id": self.jornada,
                   "programa_sha256": self.prog_sha, "perfil": self.perfil,
                   "transaccion_id": "%s-%s-%07d" % (self.ejecucion, self.perfil, n),
                   "n": n, "accion": accion, "origen_ip": self.origen,
                   "bloque_id": self.bloque["id"], "particion": self.bloque.get("particion"),
                   "fase_id": fase_id, "pulsos": pulsos, "en_rafaga": en_rafaga,
                   "factor": round(f, 6), "espera_previa_s": round(espera_previa, 6),
                   "timeout": False, "incompleta": False, "excepcion": None}
            reg["inicio_utc"] = utc()
            m0 = self.reloj()
            reg["inicio_t_s"] = round(m0 - t0, 6)
            try:
                self.ejecutar(accion, reg)
            except (socket.timeout, TimeoutError) as e:
                reg["timeout"] = True
                reg["excepcion"] = "%s: %s" % (type(e).__name__, str(e)[:120])
            except Exception as e:  # noqa: BLE001  (se registra, no se oculta)
                reg["excepcion"] = "%s: %s" % (type(e).__name__, str(e)[:120])
            m1 = self.reloj()
            reg["fin_utc"] = utc()
            reg["duracion_s"] = round(m1 - m0, 6)
            reg["tras_fin_programa"] = (m1 - t0) > dur
            reg["parada_durante_accion"] = self.parar
            tx.clasificar(accion, reg, self.prog["destinos"])
            self.tx_log.escribir(reg)
            # Espera de V1 con el factor vigente; se corta en el próximo cambio de programa.
            t = self.reloj() - t0
            media = max(self.p["ritmo_s"] / f, 0.05)
            espera = self.rng.expovariate(1.0 / media)
            borde = min(prg.proximo_cambio(self.prog, t), dur)
            if en_rafaga:
                borde = min(borde, fin_rafaga)
            if t + espera > borde:
                espera = max(borde - t, 0.0)
            espera_previa = espera
            self.dormir(espera)
        t = self.reloj() - t0
        self.evento("fin", t, estado=estado, motivo=self.motivo_parada, transacciones=n)
        self.tx_log.cerrar()
        self.ev_log.cerrar()
        return estado


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--programa", required=True)
    p.add_argument("--validar", action="store_true", help="valida el programa y sale")
    p.add_argument("--perfil", choices=prg.PERFILES_V1)
    p.add_argument("--origen", default="", help="IP de origen: es la identidad de la entidad")
    p.add_argument("--ejecucion", help="identificador único de la ejecución")
    p.add_argument("--salida", help="directorio de la ejecución")
    a = p.parse_args()
    prog = prg.cargar(a.programa)
    sha = prg.huella(a.programa)
    if a.validar:
        print("programa valido: %s (%s s, %d fases, %d bloques) sha256 %s"
              % (prog["programa_id"], prog["duracion_s"], len(prog["fases"]), len(prog["bloques"]), sha))
        return 0
    if not (a.perfil and a.ejecucion and a.salida):
        p.error("hacen falta --perfil, --ejecucion y --salida")
    if a.perfil not in prog["perfiles"]:
        p.error("el perfil %s no está activo en este programa" % a.perfil)
    g = Generador(prog, sha, a.perfil, a.origen, a.ejecucion, Path(a.salida))
    signal.signal(signal.SIGTERM, g.senal)
    signal.signal(signal.SIGINT, g.senal)
    estado = g.correr()
    return 0 if estado == "completa" else 3


if __name__ == "__main__":
    raise SystemExit(main())
