#!/usr/bin/env python3
"""Vigía del bastión: permiso, fin dinámico y supervisión."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import time
from pathlib import Path

CONDICIONES = {
    "PARADA": ("archivador_no_ok", "latido_viejo", "estado_inaccesible", "enlace_invalido", "espacio"),
    "INVALIDACION": {"output_drops": "perdida_antes_sensor",
                     "kernel_drops": "perdida_en_sensor", "hueco_eve": "perdida_en_sensor",
                     "hueco_pcap": "perdida_en_sensor", "desfase_reloj": "desfase_reloj"},
}


def ejecutar(orden: list[str]) -> str:
    if orden and orden[0] == "ssh":
        orden = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"] + orden[1:]
    r = subprocess.run(orden, capture_output=True, text=True, timeout=20)
    if r.returncode:
        raise RuntimeError("%s: %s" % (r.returncode, r.stderr.strip()))
    return r.stdout


def epoch(utc: str) -> float:
    return dt.datetime.fromisoformat(utc.replace("Z", "+00:00")).timestamp()


def ultimo_kernel_drops(raw: str) -> int | None:
    for linea in reversed(raw.splitlines()):
        try:
            reg = json.loads(linea)
            if reg.get("event_type") == "stats":
                return int(reg["stats"]["capture"]["kernel_drops"])
        except (ValueError, KeyError, TypeError):
            pass
    return None


def enlace(raw: str) -> tuple[bool | None, int | None]:
    # Un destino de SPAN se ve como «is up, line protocol is down (monitoring)»: es el estado
    # normal. Inválido = interfaz caída o protocolo caído sin «(monitoring)», o no 1000 Full.
    interfaz = re.search(r"^\S+ is (up|down|administratively down)", raw, re.I | re.M)
    protocolo = re.search(r"line protocol is (up|down)( \(monitoring\))?", raw, re.I)
    velocidad = re.search(r"Full-duplex,\s*1000Mb/s", raw, re.I)
    drops = re.search(r"output drops:\s*(\d+)|(\d+)\s+output drops", raw, re.I)
    if not (interfaz and protocolo):
        valido = None
    else:
        proto_ok = protocolo.group(1).lower() == "up" or bool(protocolo.group(2))
        valido = interfaz.group(1).lower() == "up" and proto_ok and bool(velocidad)
    return valido, int(drops.group(1) or drops.group(2)) if drops else None


class Vigia:
    def __init__(self, a, ejecutor=ejecutar, reloj=time.time, dormir=time.sleep):
        self.a, self.ejecutor, self.reloj, self.dormir = a, ejecutor, reloj, dormir
        self.fallos = 0
        self.detenido = False
        self.hasta_escrito = False
        self.proxima_supervision = 0
        self.previos = {}
        self.ultimo_control = None

    def registrar_archivo(self, nombre: str, **datos) -> None:
        datos["utc"] = dt.datetime.fromtimestamp(self.reloj(), dt.timezone.utc).isoformat()
        with open(Path(self.a.registro).with_name(nombre), "a", encoding="utf-8") as f:
            f.write(json.dumps(datos, sort_keys=True) + "\n")

    def registrar(self, tipo: str, **datos) -> None:
        self.registrar_archivo(Path(self.a.registro).name, tipo=tipo, **datos)

    def parar(self, motivo: str) -> None:
        self.detenido = True
        orden = ["ssh", "clientes", "python3 %s parar --ejecucion %s --motivo %s" %
                 (shlex.quote(self.a.v2ctl_remoto), shlex.quote(self.a.ejecucion), shlex.quote(motivo))]
        try:
            self.ejecutor(orden)
            self.registrar("parada", motivo=motivo)
        except Exception as e:
            self.registrar("parada_fallida", motivo=motivo, error=str(e))

    def consultar_fin(self) -> None:
        if self.hasta_escrito:
            return
        try:
            raw = self.ejecutor(["ssh", "clientes", "python3 %s estado --ejecucion %s --json" %
                                 (shlex.quote(self.a.v2ctl_remoto), shlex.quote(self.a.ejecucion))])
            estado = json.loads(raw)
            if not estado.get("terminado"):
                return
            fin = epoch(estado["fin_utc"])
            hasta = fin + getattr(self.a, "margen_fin_s", 120)
            remoto = shlex.quote(getattr(self.a, "hasta_remoto",
                str(Path(self.a.estado_remoto).with_name("HASTA_EPOCH"))))
            orden = "printf '%%s\\n' %s > %s.tmp && mv %s.tmp %s" % (
                shlex.quote(str(hasta)), remoto, remoto, remoto)
            self.ejecutor(["ssh", "sensor1", orden])
            self.registrar("fin_generador_real", fin_epoch=fin, estado=estado.get("estado"))
            self.registrar("hasta_escrito", hasta_epoch=hasta)
            self.hasta_escrito = True
        except Exception as e:
            self.registrar("fin_pendiente", error=str(e))

    def invalidar(self, condicion: str, desde: float, hasta: float, **datos) -> None:
        self.registrar_archivo("invalidaciones.jsonl", condicion=condicion,
            categoria=CONDICIONES["INVALIDACION"][condicion], desde_epoch=desde,
            hasta_epoch=hasta, **datos)

    def supervision(self, estado: dict) -> bool:
        ahora = self.reloj()
        if ahora < self.proxima_supervision:
            return True
        self.proxima_supervision = ahora + getattr(self.a, "supervision_cada_s", 300)
        desde = self.ultimo_control if self.ultimo_control is not None else ahora
        self.ultimo_control = ahora
        reg = {"desde_epoch": desde, "hasta_epoch": ahora}
        try:
            reg["enlace_valido"], reg["output_drops"] = enlace(
                self.ejecutor(["ssh", "sw-core-stack", "show interfaces GigabitEthernet2/0/19"]))
        except Exception as e:
            reg["enlace_error"] = str(e)
        try:
            reg["kernel_drops"] = ultimo_kernel_drops(self.ejecutor(
                ["ssh", "sensor1", "tail -n 2000 /var/log/suricata/v2/eve.json"]))
        except Exception as e:
            reg["eve_error"] = str(e)
        reg["libre_gb"] = estado.get("libre_gb")
        for host in ("sensor1", "clientes"):
            try:
                antes = self.reloj()
                remoto = float(self.ejecutor(["ssh", host, "date +%s.%N"]).strip())
                despues = self.reloj()
                reg["desfase_" + host + "_s"] = remoto - (antes + despues) / 2
            except Exception as e:
                reg["reloj_" + host + "_error"] = str(e)
        reg["eve_huecos"] = estado.get("eve_huecos")
        reg["pcap_huecos"] = estado.get("pcap_huecos")
        self.registrar_archivo("supervision.jsonl", **reg)
        for campo, condicion in (("output_drops", "output_drops"), ("kernel_drops", "kernel_drops"),
                                 ("eve_huecos", "hueco_eve"), ("pcap_huecos", "hueco_pcap")):
            valor, anterior = reg.get(campo), self.previos.get(campo)
            if anterior is None and campo in ("eve_huecos", "pcap_huecos"):
                anterior = 0
            if valor is not None and anterior is not None and valor > anterior:
                self.invalidar(condicion, desde, ahora, anterior=anterior, nuevo=valor)
            if valor is not None:
                self.previos[campo] = valor
        for host in ("sensor1", "clientes"):
            desfase = reg.get("desfase_" + host + "_s")
            if desfase is not None and abs(desfase) > 1:
                self.invalidar("desfase_reloj", desde, ahora, host=host, desfase_s=desfase)
        if reg.get("enlace_valido") is False:
            self.parar("enlace_invalido")
            return False
        if reg["libre_gb"] is not None and reg["libre_gb"] < getattr(self.a, "libre_minimo_gb", 4):
            self.parar("espacio")
            return False
        return True

    def paso(self) -> bool:
        if self.detenido:
            return False
        try:
            estado = json.loads(self.ejecutor(
                ["ssh", "sensor1", "cat %s" % shlex.quote(self.a.estado_remoto)]))
            self.fallos = 0
        except Exception as e:
            self.fallos += 1
            self.registrar("lectura_fallida", consecutivas=self.fallos, error=str(e))
            if self.fallos >= self.a.max_fallos:
                self.parar("estado_inaccesible")
                return False
            return True
        self.consultar_fin()
        if estado.get("estado") == "terminado":
            self.registrar("archivador_terminado")
            return False
        if estado.get("estado") != "ok":
            self.parar("archivador_%s_%s" % (estado.get("estado", "desconocido"), estado.get("motivo", "")))
            return False
        try:
            latido = epoch(estado["utc"])
        except (KeyError, ValueError):
            self.parar("latido_invalido")
            return False
        if self.reloj() - latido > self.a.latido_max_s:
            self.parar("latido_viejo")
            return False
        if not self.supervision(estado):
            return False
        if not self.hasta_escrito:
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
    p.add_argument("--estado-remoto")
    p.add_argument("--hasta-remoto")
    p.add_argument("--permiso-remoto")
    p.add_argument("--v2ctl-remoto", default="/home/adminclientes/cyberflow-v2/codigo/operacion/v2ctl.py")
    p.add_argument("--registro", default="vigia.jsonl")
    p.add_argument("--cada", type=float, default=10.0)
    p.add_argument("--latido-max-s", type=float, default=60.0)
    p.add_argument("--max-fallos", type=int, default=3)
    p.add_argument("--margen-fin-s", type=float, default=120.0)
    p.add_argument("--supervision-cada-s", type=float, default=300.0)
    p.add_argument("--libre-minimo-gb", type=float, default=4.0)
    a = p.parse_args()
    a.estado_remoto = a.estado_remoto or "/home/m4rk/cyberflow-v2/capturas/%s/estado.json" % a.ejecucion
    a.hasta_remoto = a.hasta_remoto or str(Path(a.estado_remoto).with_name("HASTA_EPOCH"))
    a.permiso_remoto = a.permiso_remoto or "/home/adminclientes/cyberflow-v2/ejecuciones/%s/PERMISO_CAPTURA" % a.ejecucion
    return Vigia(a).correr()


if __name__ == "__main__":
    raise SystemExit(main())
