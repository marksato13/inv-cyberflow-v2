#!/usr/bin/env python3
"""Vigía del bastión: renueva permiso mientras la captura esté sana."""
from __future__ import annotations

import argparse
import datetime
import json
import shlex
import subprocess
import time
from pathlib import Path


def ejecutar(orden: list[str]) -> str:
    if orden and orden[0] == "ssh":  # nunca pedir contraseña ni quedarse colgado
        orden = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"] + orden[1:]
    r = subprocess.run(orden, capture_output=True, text=True, timeout=20)
    if r.returncode:
        raise RuntimeError("%s: %s" % (r.returncode, r.stderr.strip()))
    return r.stdout


class Vigia:
    def __init__(self, a, ejecutor=ejecutar, reloj=time.time, dormir=time.sleep):
        self.a, self.ejecutor, self.reloj, self.dormir = a, ejecutor, reloj, dormir
        self.fallos = 0
        self.detenido = False

    def registrar(self, tipo: str, **datos) -> None:
        reg = dict(datos, tipo=tipo, utc=datetime.datetime.fromtimestamp(self.reloj(), datetime.timezone.utc).isoformat())
        with open(self.a.registro, "a", encoding="utf-8") as f:
            f.write(json.dumps(reg, sort_keys=True) + "\n")

    def parar(self, motivo: str) -> None:
        self.detenido = True
        orden = ["ssh", "clientes", "python3 %s parar --ejecucion %s --motivo %s" %
                 (shlex.quote(self.a.v2ctl_remoto), shlex.quote(self.a.ejecucion), shlex.quote(motivo))]
        try:
            self.ejecutor(orden)
            self.registrar("parada", motivo=motivo)
        except Exception as e:
            self.registrar("parada_fallida", motivo=motivo, error=str(e))

    def paso(self) -> bool:
        if self.detenido:
            return False
        try:
            raw = self.ejecutor(["ssh", "sensor1", "cat %s" % shlex.quote(self.a.estado_remoto)])
            estado = json.loads(raw)
            self.fallos = 0
        except Exception as e:
            self.fallos += 1
            self.registrar("lectura_fallida", consecutivas=self.fallos, error=str(e))
            if self.fallos >= self.a.max_fallos:
                self.parar("estado_inaccesible")
                return False
            return True
        if estado.get("estado") == "terminado":
            # Fin normal del archivador (tras HASTA + margen). No se para nada: si el generador
            # siguiera vivo, el hombre muerto del supervisor lo detiene y marca la ejecución incompleta.
            self.registrar("archivador_terminado")
            return False
        if estado.get("estado") != "ok":
            self.parar("archivador_%s_%s" % (estado.get("estado", "desconocido"), estado.get("motivo", "")))
            return False
        try:
            latido = datetime.datetime.fromisoformat(estado["utc"].replace("Z", "+00:00")).timestamp()
        except (KeyError, ValueError) as e:
            self.parar("latido_invalido")
            return False
        if self.reloj() - latido > self.a.latido_max_s:
            self.parar("latido_viejo")
            return False
        try:
            self.ejecutor(["ssh", "clientes", "touch %s" % shlex.quote(self.a.permiso_remoto)])
            self.registrar("permiso_renovado", libre_gb=estado.get("libre_gb"))
        except Exception as e:
            self.registrar("permiso_fallido", error=str(e))
            self.parar("permiso_inaccesible")
            return False
        return True

    def correr(self) -> int:
        while self.paso():
            self.dormir(self.a.cada)
        return 1 if self.detenido else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ejecucion", required=True)
    p.add_argument("--estado-remoto", help="ruta absoluta de estado.json en Sensor1")
    p.add_argument("--permiso-remoto", help="ruta absoluta del permiso en Clientes")
    p.add_argument("--v2ctl-remoto", default="/home/m4rk/cyberflow-v2/operacion/v2ctl.py")
    p.add_argument("--registro", default="vigia.jsonl")
    p.add_argument("--cada", type=float, default=10.0)
    p.add_argument("--latido-max-s", type=float, default=60.0)
    p.add_argument("--max-fallos", type=int, default=3)
    a = p.parse_args()
    a.estado_remoto = a.estado_remoto or "/home/m4rk/cyberflow-v2/capturas/%s/estado.json" % a.ejecucion
    a.permiso_remoto = a.permiso_remoto or "/home/m4rk/cyberflow-v2/ejecuciones/%s/PERMISO_CAPTURA" % a.ejecucion
    return Vigia(a).correr()


if __name__ == "__main__":
    raise SystemExit(main())
