#!/usr/bin/env python3
"""Archiva PCAP y EVE completos de una ejecución V2 fuera del anillo de CyberFlow V1.

Contexto comprobado en Sensor1 (24-nov-2026):
* ``ppi-motor-capture`` (tcpdump -G 5) escribe ``/var/lib/ppi-motor-capture/live-%Y%m%d%H%M%S.pcap``.
* ``cyberflow-limpieza.timer`` (cada 5 min) borra los ``live-*.pcap`` con ``-mmin +15``:
  ese es el proceso que borra el anillo. Este archivador copia cada fichero cerrado mucho
  antes (cada ``--cada`` segundos) y no toca el anillo ni sus servicios.
* Suricata escribe un único ``/var/log/suricata/eve.json`` que logrotate rota a diario
  (00:00 UTC) o al pasar 500 MB, con ``copytruncate``. El archivador sigue el fichero por
  desplazamiento y registra cada truncado como evento (posible pérdida entre copia y truncado).

No necesita privilegios: m4rk pertenece al grupo del directorio del anillo y eve.json es
legible. Escribe en ``<raiz>/<ejecucion>/`` (fuera de ``artifacts/linea-base``).

Salidas: ``pcap/`` (copias byte a byte), ``eve/eve-<ejecucion>.json``, ``inventario.jsonl``
(un registro por fichero con sha256), ``eventos.jsonl`` (inicio, huecos, truncados, fin),
``contadores-{inicio,fin}.json`` y ``manifiesto.json`` al terminar.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

ANILLO = Path("/var/lib/ppi-motor-capture")
EVE = Path("/var/log/suricata/eve.json")
STATS = Path("/var/log/suricata/stats.log")
PATRON = re.compile(r"^live-(\d{14})\.pcap$")
ROTACION_S = 5


def ahora_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(ruta: Path) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def nombre_a_epoch(nombre: str) -> float | None:
    m = PATRON.match(nombre)
    if not m:
        return None
    return datetime.datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc).timestamp()


def sh(orden: str) -> str:
    try:
        return subprocess.run(orden, shell=True, capture_output=True, text=True, timeout=20).stdout
    except Exception as e:  # noqa: BLE001
        return "ERROR %s" % e


def contadores(interfaz: str) -> dict:
    """Contadores de pérdidas y reloj que no necesitan privilegios."""
    c = {"utc": ahora_utc(), "monotonic": time.monotonic()}
    base = Path("/sys/class/net/%s/statistics" % interfaz)
    for k in ("rx_packets", "rx_bytes", "rx_dropped", "rx_missed_errors", "rx_errors"):
        try:
            c["nic_" + k] = int((base / k).read_text())
        except OSError:
            c["nic_" + k] = None
    try:
        c["softnet_dropped_total"] = sum(int(l.split()[1], 16) for l in open("/proc/net/softnet_stat"))
    except OSError:
        c["softnet_dropped_total"] = None
    c["tcpdump_ultima_estadistica"] = sh("journalctl -u ppi-motor-capture -n 40 --no-pager -o short-iso-precise "
                                         "| grep 'packets captured' | tail -1").strip()
    st = sh("tail -c 200000 %s | grep -E 'capture.kernel_(packets|drops)|^Date' | tail -3" % STATS).strip()
    c["suricata_stats"] = st
    c["timesync"] = sh("timedatectl timesync-status 2>&1 | grep -E 'Server|Offset|Delay|Jitter'").strip()
    c["ntp_sincronizado"] = sh("timedatectl show -p NTPSynchronized --value").strip()
    du = shutil.disk_usage("/")
    c["disco_libre_bytes"] = du.free
    return c


class Archivador:
    def __init__(self, a):
        self.a = a
        self.dir = Path(a.raiz) / a.ejecucion
        if self.dir.exists() and any(self.dir.iterdir()):
            raise SystemExit("ya existe %s: una ejecución no se reutiliza" % self.dir)
        (self.dir / "pcap").mkdir(parents=True, exist_ok=True)
        (self.dir / "eve").mkdir(exist_ok=True)
        self.inv = open(self.dir / "inventario.jsonl", "a", encoding="utf-8")
        self.ev = open(self.dir / "eventos.jsonl", "a", encoding="utf-8")
        self.eve_out = open(self.dir / "eve" / ("eve-%s.json" % a.ejecucion), "ab")
        self.copiados: set[str] = set()
        self.ultimo_epoch: float | None = None
        self.parar = False
        self.bytes_pcap = 0
        self.eve_off = 0
        self.eve_ino = None
        self.eve_bytes = 0

    def evento(self, tipo: str, **k) -> None:
        self.ev.write(json.dumps(dict(k, tipo=tipo, utc=ahora_utc()), sort_keys=True) + "\n")
        self.ev.flush()

    def senal(self, signum, _f) -> None:
        self.parar = True
        self.evento("senal", nombre=signal.Signals(signum).name)

    # -- PCAP ---------------------------------------------------------------
    def pasada_pcap(self, final: bool = False) -> None:
        nombres = sorted(n for n in os.listdir(ANILLO) if PATRON.match(n))
        if not final:
            nombres = nombres[:-1]  # el más nuevo lo está escribiendo tcpdump
        for n in nombres:
            if n in self.copiados:
                continue
            ep = nombre_a_epoch(n)
            if ep is None or ep < self.desde - ROTACION_S:
                continue
            src = ANILLO / n
            dst = self.dir / "pcap" / n
            try:
                shutil.copy2(src, dst)
            except FileNotFoundError:
                self.evento("pcap_perdido_antes_de_copiar", fichero=n)
                continue
            st_src = src.stat() if src.exists() else None
            reg = {"fichero": n, "inicio_nombre_epoch": ep, "bytes": dst.stat().st_size,
                   "sha256": sha256(dst), "copiado_utc": ahora_utc(), "final": final,
                   "origen_cambio_tras_copiar": bool(st_src and st_src.st_size != dst.stat().st_size)}
            self.inv.write(json.dumps(reg, sort_keys=True) + "\n")
            self.inv.flush()
            self.copiados.add(n)
            self.bytes_pcap += reg["bytes"]
            if self.ultimo_epoch is not None and ep - self.ultimo_epoch > ROTACION_S + 1:
                self.evento("hueco_rotacion", anterior_epoch=self.ultimo_epoch, siguiente=n,
                            segundos=ep - self.ultimo_epoch)
            self.ultimo_epoch = ep

    # -- EVE ----------------------------------------------------------------
    def pasada_eve(self) -> None:
        try:
            st = EVE.stat()
        except FileNotFoundError:
            self.evento("eve_ausente")
            return
        if self.eve_ino is not None and st.st_ino != self.eve_ino:
            self.evento("eve_inodo_cambiado", antes=self.eve_ino, ahora=st.st_ino)
            self.eve_off = 0
        if st.st_size < self.eve_off:
            self.evento("eve_truncado", desplazamiento_previo=self.eve_off, tamano_actual=st.st_size,
                        nota="copytruncate: lo escrito entre la última lectura y el truncado puede faltar")
            self.eve_off = 0
        self.eve_ino = st.st_ino
        with open(EVE, "rb") as f:
            f.seek(self.eve_off)
            datos = f.read(st.st_size - self.eve_off)
        corte = datos.rfind(b"\n") + 1  # solo líneas completas
        if corte:
            self.eve_out.write(datos[:corte])
            self.eve_out.flush()
            self.eve_off += corte
            self.eve_bytes += corte

    # -- ciclo ----------------------------------------------------------------
    def correr(self) -> None:
        a = self.a
        self.desde = time.time() - a.margen_previo
        ini = contadores(a.interfaz)
        (self.dir / "contadores-inicio.json").write_text(json.dumps(ini, indent=1, sort_keys=True))
        st = EVE.stat()
        self.eve_off, self.eve_ino = st.st_size, st.st_ino  # el EVE de la ejecución empieza ahora
        self.evento("inicio", ejecucion=a.ejecucion, pid=os.getpid(), desde_epoch=self.desde,
                    eve_desplazamiento_inicial=self.eve_off, hasta_epoch=a.hasta_epoch,
                    version_script_sha256=sha256(Path(__file__)))
        while not self.parar:
            self.pasada_pcap()
            self.pasada_eve()
            if a.hasta_epoch and time.time() >= a.hasta_epoch:
                self.evento("fin_programado")
                break
            if (self.dir / "PARAR").exists():
                self.evento("fin_por_fichero_parar")
                break
            libre = shutil.disk_usage("/").free
            if libre < a.libre_minimo_gb * 1e9:
                self.evento("parada_por_espacio", libre_bytes=libre)
                break
            for _ in range(int(a.cada * 2)):
                if self.parar:
                    break
                time.sleep(0.5)
        # Margen posterior: espera a que tcpdump cierre el fichero que cubre el final.
        time.sleep(ROTACION_S + 2)
        self.pasada_pcap()
        self.pasada_eve()
        fin = contadores(a.interfaz)
        (self.dir / "contadores-fin.json").write_text(json.dumps(fin, indent=1, sort_keys=True))
        self.eve_out.close()
        eve_f = self.dir / "eve" / ("eve-%s.json" % a.ejecucion)
        man = {"ejecucion": a.ejecucion, "pcap_ficheros": len(self.copiados), "pcap_bytes": self.bytes_pcap,
               "eve_bytes": self.eve_bytes, "eve_sha256": sha256(eve_f),
               "inventario_sha256": None, "inicio": ini["utc"], "fin": fin["utc"],
               "delta_nic_rx_dropped": (fin["nic_rx_dropped"] - ini["nic_rx_dropped"])
               if None not in (fin["nic_rx_dropped"], ini["nic_rx_dropped"]) else None,
               "delta_nic_rx_packets": (fin["nic_rx_packets"] - ini["nic_rx_packets"])
               if None not in (fin["nic_rx_packets"], ini["nic_rx_packets"]) else None,
               "ubicacion": str(self.dir)}
        self.inv.close()
        man["inventario_sha256"] = sha256(self.dir / "inventario.jsonl")
        self.evento("fin", **{k: man[k] for k in ("pcap_ficheros", "pcap_bytes", "eve_bytes")})
        self.ev.close()
        (self.dir / "manifiesto.json").write_text(json.dumps(man, indent=1, sort_keys=True))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ejecucion", required=True)
    p.add_argument("--raiz", default="/home/m4rk/cyberflow-v2/capturas")
    p.add_argument("--interfaz", default="ens37")
    p.add_argument("--cada", type=float, default=15.0, help="segundos entre pasadas (el anillo se poda a 15 min)")
    p.add_argument("--margen-previo", type=float, default=30.0, help="segundos de PCAP anteriores al inicio")
    p.add_argument("--hasta-epoch", type=float, default=0.0, help="fin programado (epoch UTC); 0 = hasta PARAR o SIGTERM")
    p.add_argument("--libre-minimo-gb", type=float, default=4.0, help="condición de parada por espacio en /")
    a = p.parse_args()
    arch = Archivador(a)
    signal.signal(signal.SIGTERM, arch.senal)
    signal.signal(signal.SIGINT, arch.senal)
    arch.correr()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
