#!/usr/bin/env python3
"""Vigila las referencias independientes (BASTIÓN) durante la captura y analiza su registro.

    python3 vigilar_referencias.py vigilar --ejecucion ID --salida E/referencias.jsonl --pid E/referencias.pid \
        --generador-desde INI --generador-hasta FIN_GEN --hasta-epoch TOPE
    python3 vigilar_referencias.py analizar E/referencias.jsonl [--parada-cierre-epoch T] > calidad-referencias.json

Cada `cada_s` lee, en srv-dmz, si sigue vivo el tcpdump de la ejecución, el tamaño de su PCAP y el
espacio libre; y en DC1, si la unidad del registro DNS está activa, el tamaño de su JSONL y PCAP y
el espacio libre de /var/log.

Incidentes (se registran en el acto; `analizar` los convierte en evidencia INCOMPLETA, nunca en
«sin pérdida»):
- `proceso_caido`: el proceso de la referencia ha muerto antes de que el cierre lo pare;
- `sin_progreso`: durante la generación el fichero deja de crecer más de `sin_progreso_s`;
- `espacio_bajo`: queda menos de `minimo_gb`. Parada coordinada: se para la captura de la
  referencia con SIGINT (el PCAP queda legible y con sus estadísticas) antes de llenar el disco,
  y se marca la referencia como incompleta desde ese instante;
- `sin_supervision`: no se pudo leer un equipo durante más de `sin_lectura_s`.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

EXT = "/home/adminsrvdmz/cyberflow-v2/extremo"
DC1 = "dcadmin@10.10.10.20"


def ejecutar(host, orden, timeout=25):
    r = subprocess.run(["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, orden],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout


def leer_srvdmz(ident, ejecutor=ejecutar):
    rc, s = ejecutor("srvdmz", "pgrep -f '[t]cpdump .* -w %s/%s.pcap' >/dev/null && echo vivo || echo muerto; "
                     "stat -c %%s %s/%s.pcap 2>/dev/null || echo -1; df -B1 --output=avail %s | tail -1"
                     % (EXT, ident, EXT, ident, EXT))
    if rc != 0:
        return None
    lineas = s.split()
    return dict(proceso=lineas[0] == "vivo", bytes=[int(lineas[1])], libre_b=int(lineas[2]))


def leer_dc1(ident, ejecutor=ejecutar):
    u = "cf-v2-dns-" + ident.lower()
    base = "/var/log/cyberflow-v2/dns-" + ident
    rc, s = ejecutor(DC1, "systemctl is-active %s || true; sudo -n stat -c %%s %s.jsonl 2>/dev/null || echo -1; "
                     "sudo -n stat -c %%s %s.pcap 2>/dev/null || echo -1; df -B1 --output=avail /var/log | tail -1"
                     % (u, base, base))
    if rc != 0:
        return None
    lineas = s.split()
    return dict(proceso=lineas[0] == "active", bytes=[int(lineas[1]), int(lineas[2])], libre_b=int(lineas[3]))


def parar_srvdmz(ident, ejecutor=ejecutar):
    return ejecutor("srvdmz", "sudo -n pkill -INT -f '[t]cpdump .* -w %s/%s.pcap'" % (EXT, ident))[0]


def parar_dc1(ident, ejecutor=ejecutar):
    return ejecutor(DC1, "sudo -n systemctl stop cf-v2-dns-%s" % ident.lower())[0]


class Vigilante:
    def __init__(self, a, ejecutor=ejecutar, reloj=time.time, dormir=time.sleep):
        self.a, self.ejecutor, self.reloj, self.dormir = a, ejecutor, reloj, dormir
        self.parar_pedido = False
        self.ultimo = {}          # equipo -> (instante, bytes) del último crecimiento
        self.ultima_lectura = {}
        self.parados = set()      # referencias paradas por el vigilante (espacio)
        self.avisado = set()

    def escribir(self, **d):
        d.setdefault("utc_epoch", self.reloj())
        with open(self.a.salida, "a", encoding="utf-8") as f:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    def incidente(self, equipo, tipo, **d):
        clave = (equipo, tipo)
        if clave in self.avisado:
            return
        self.avisado.add(clave)
        self.escribir(tipo="incidente", equipo=equipo, incidente=tipo, **d)

    def paso(self):
        t = self.reloj()
        en_generacion = self.a.generador_desde <= t <= self.a.generador_hasta
        lectores = {"srvdmz": (leer_srvdmz, parar_srvdmz, self.a.minimo_gb_srvdmz),
                    "dc1": (leer_dc1, parar_dc1, self.a.minimo_gb_dc1)}
        for equipo, (leer, parar, minimo) in lectores.items():
            try:
                m = leer(self.a.ejecucion, self.ejecutor)
            except (subprocess.TimeoutExpired, OSError, ValueError, IndexError) as exc:
                m = None
                self.escribir(tipo="error_lectura", equipo=equipo, error=str(exc)[:200])
            if m is None:
                desde = self.ultima_lectura.get(equipo, self.a.inicio)
                if t - desde > self.a.sin_lectura_s:
                    self.incidente(equipo, "sin_supervision", sin_lectura_desde_epoch=desde)
                continue
            self.ultima_lectura[equipo] = t
            self.escribir(tipo="muestra", equipo=equipo, en_generacion=en_generacion, **m)
            if equipo in self.parados:
                continue
            if not m["proceso"]:
                self.incidente(equipo, "proceso_caido")
            if m["libre_b"] < minimo * 1e9:
                rc = parar(self.a.ejecucion, self.ejecutor)
                self.parados.add(equipo)
                self.incidente(equipo, "espacio_bajo", libre_b=m["libre_b"], minimo_gb=minimo,
                               accion="captura de la referencia parada (SIGINT)", rc_parada=rc)
                continue
            tam = sum(x for x in m["bytes"] if x > 0)
            previo = self.ultimo.get(equipo)
            if previo is None or tam > previo[1]:
                self.ultimo[equipo] = (t, tam)
            # VD4: el reloj se cuenta desde el inicio de la generación como pronto. Antes (sondas,
            # margen previo) no hay tráfico hacia las referencias y su quietud no es un incidente.
            elif en_generacion and t - max(previo[0], self.a.generador_desde) > self.a.sin_progreso_s:
                self.incidente(equipo, "sin_progreso", bytes=tam, sin_crecer_desde_epoch=previo[0])

    def correr(self):
        Path(self.a.pid).write_text(str(os.getpid()))
        self.escribir(tipo="inicio", ejecucion=self.a.ejecucion, cada_s=self.a.cada_s,
                      generador_desde=self.a.generador_desde, generador_hasta=self.a.generador_hasta,
                      minimo_gb_srvdmz=self.a.minimo_gb_srvdmz, minimo_gb_dc1=self.a.minimo_gb_dc1,
                      sin_progreso_s=self.a.sin_progreso_s, sin_lectura_s=self.a.sin_lectura_s)
        while not self.parar_pedido and self.reloj() < self.a.hasta_epoch:
            self.paso()
            for _ in range(max(1, int(self.a.cada_s))):      # en pasos de 1 s: SIGTERM corta pronto
                if self.parar_pedido:
                    break
                self.dormir(1)
        self.escribir(tipo="fin", motivo="parado_por_cierre" if self.parar_pedido else "tope")


def progreso_desde_muestras(ini, muestras):
    """Recalcula `sin_progreso` con las muestras registradas y la regla corregida (reloj desde el
    inicio de la generación). Para reanalizar registros escritos con la regla anterior."""
    salida, ultimo = [], {}
    for x in muestras:
        eq, t = x["equipo"], x["utc_epoch"]
        tam = sum(b for b in x["bytes"] if b > 0)
        previo = ultimo.get(eq)
        if previo is None or tam > previo[1]:
            ultimo[eq] = (t, tam)
        elif (x.get("en_generacion") and t - max(previo[0], ini["generador_desde"]) > ini["sin_progreso_s"]
              and not any(i["equipo"] == eq for i in salida)):
            salida.append({"tipo": "incidente", "equipo": eq, "incidente": "sin_progreso", "bytes": tam,
                           "sin_crecer_desde_epoch": previo[0], "utc_epoch": t, "recalculado": True})
    return salida


def analizar(lineas, parada_cierre=None, recalcular_progreso=False):
    """completo | incompleta (con incidentes) | sin_datos. Sin registro NUNCA es completo."""
    if not lineas:
        return {"version": 1, "estado": "sin_datos", "motivo": "sin registro de vigilancia"}
    ini = next((x for x in lineas if x.get("tipo") == "inicio"), None)
    fin = next((x for x in lineas if x.get("tipo") == "fin"), None)
    muestras = [x for x in lineas if x.get("tipo") == "muestra"]
    inc = [x for x in lineas if x.get("tipo") == "incidente"]
    registrados = None
    if recalcular_progreso and ini is not None:
        registrados = [x for x in inc if x.get("incidente") == "sin_progreso"]
        inc = [x for x in inc if x.get("incidente") != "sin_progreso"] + progreso_desde_muestras(ini, muestras)
    por_equipo = {}
    for eq in ("srvdmz", "dc1"):
        m = [x for x in muestras if x["equipo"] == eq]
        gen = [x for x in m if x.get("en_generacion")]
        por_equipo[eq] = dict(muestras=len(m), en_generacion=len(gen),
                              libre_min_gb=round(min(x["libre_b"] for x in m) / 1e9, 3) if m else None,
                              bytes_fin=sum(b for b in m[-1]["bytes"] if b > 0) if m else None,
                              proceso_vivo_en_todas=all(x["proceso"] for x in m) if m else None)
    motivos = ["%s:%s" % (x["equipo"], x["incidente"]) for x in inc]
    if ini is None:
        motivos.append("sin_inicio")
    if fin is None:
        motivos.append("sin_fin")
    for eq, d in por_equipo.items():
        if not d["en_generacion"]:
            motivos.append("%s:sin_muestras_en_generacion" % eq)
    r = {"version": 1, "estado": "completo" if not motivos else "incompleta", "motivos": motivos,
         "por_equipo": por_equipo, "incidentes": inc}
    if registrados is not None:
        r["recalculado_progreso"] = {"regla": "reloj de sin_progreso desde max(último crecimiento, inicio de la generación)",
                                     "incidentes_registrados_sustituidos": registrados}
    return {**r,
            "fin": fin.get("motivo") if fin else None, "parada_cierre_epoch": parada_cierre}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    v = sub.add_parser("vigilar")
    v.add_argument("--ejecucion", required=True)
    v.add_argument("--salida", required=True)
    v.add_argument("--pid", required=True)
    v.add_argument("--generador-desde", type=float, required=True)
    v.add_argument("--generador-hasta", type=float, required=True)
    v.add_argument("--hasta-epoch", type=float, required=True)
    v.add_argument("--cada-s", type=float, default=20)
    v.add_argument("--minimo-gb-srvdmz", type=float, default=1.0)
    v.add_argument("--minimo-gb-dc1", type=float, default=1.0)
    v.add_argument("--sin-progreso-s", type=float, default=180)
    v.add_argument("--sin-lectura-s", type=float, default=90)
    z = sub.add_parser("analizar")
    z.add_argument("registro")
    z.add_argument("--parada-cierre-epoch", type=float)
    z.add_argument("--recalcular-progreso", action="store_true",
                   help="reanálisis: recalcula sin_progreso con las muestras y la regla corregida")
    a = ap.parse_args(argv)
    if a.orden == "vigilar":
        a.inicio = time.time()
        vig = Vigilante(a)
        signal.signal(signal.SIGTERM, lambda *_: setattr(vig, "parar_pedido", True))
        vig.correr()
        return 0
    p = Path(a.registro)
    lineas = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []
    r = analizar(lineas, a.parada_cierre_epoch, a.recalcular_progreso)
    print(json.dumps(r, indent=1, ensure_ascii=False))
    return 0 if r["estado"] == "completo" else 1


if __name__ == "__main__":
    raise SystemExit(main())
