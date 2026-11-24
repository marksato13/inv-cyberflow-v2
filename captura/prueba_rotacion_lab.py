#!/usr/bin/env python3
"""Prueba controlada de continuidad EVE/PCAP del archivador, en Sensor1, sin tocar Suricata.

Un escritor sintético añade líneas EVE numeradas (seq) a <dir>/eve.json con O_APPEND, como
Suricata, y reabre el fichero con SIGHUP. Un generador crea PCAP de 5 s en <dir>/anillo con
nombres live-AAAAMMDDhhmmss.pcap y conserva solo los últimos 8 (anillo). El archivador real
(captura/archivar_v2.py) sigue ambos. Durante la prueba se provocan, a horas fijas:

  t=20  copytruncate con logrotate (compress)       t=40  segundo copytruncate (.1.gz rota a .2.gz)
  t=60  rename+create (mv y SIGHUP)                  t=80  sustitución del fichero por otro inodo
  t=100 borrado y reaparición a los 7 s              t=115 línea partida 6 s
  t=125 línea corrupta                               t=70  PCAP borrado antes de copiar (salto de nombres)

Al final compara las seq escritas con las archivadas y lista lo que el archivador declaró en
huecos.jsonl / huecos-pcap.jsonl. Sale 0 siempre: el veredicto va en resultado.json.
"""
from __future__ import annotations

import json
import os
import signal
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

AQUI = Path(__file__).resolve().parent
ARCH = AQUI / "archivar_v2.py"
DUR = 140
TASA = 400  # líneas/s (una carga EVE alta del laboratorio ronda decenas por segundo)


class Escritor(threading.Thread):
    def __init__(self, ruta: Path):
        super().__init__(daemon=True)
        self.ruta, self.seq, self.fin = ruta, 0, False
        self.reabrir = threading.Event()
        self.partida = threading.Event()
        self.corrupta = threading.Event()
        self.fd = os.open(ruta, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)

    def linea(self, n: int) -> bytes:
        return (json.dumps({"timestamp": "%.6f" % time.time(), "event_type": "flow", "seq": n,
                            "relleno": "x" * 150}) + "\n").encode()

    def run(self):
        periodo = 1.0 / TASA
        sig = time.monotonic()
        while not self.fin:
            if self.reabrir.is_set():
                os.close(self.fd)
                self.fd = os.open(self.ruta, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
                self.reabrir.clear()
            if self.partida.is_set():
                self.partida.clear()
                self.seq += 1
                l = self.linea(self.seq)
                os.write(self.fd, l[:40]); time.sleep(6); os.write(self.fd, l[40:])
            if self.corrupta.is_set():
                self.corrupta.clear()
                os.write(self.fd, b'{"corrupta": \n')
            self.seq += 1
            os.write(self.fd, self.linea(self.seq))
            sig += periodo
            time.sleep(max(0.0, sig - time.monotonic()))
        os.close(self.fd)


def pcap(ruta: Path, t: float, n: int = 20):
    cab = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    trama = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
    cuerpo = b"".join(struct.pack("<IIII", int(t + i * 0.2), int(((t + i * 0.2) % 1) * 1e6), len(trama), len(trama)) + trama
                      for i in range(n))
    ruta.write_bytes(cab + cuerpo)


def main() -> int:
    d = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/v2-rotacion-%d" % time.time())
    (d / "anillo").mkdir(parents=True)
    (d / "raiz").mkdir()
    eve = d / "eve.json"
    eve.touch()
    (d / "lr.conf").write_text("%s {\n  copytruncate\n  rotate 3\n  compress\n  missingok\n}\n" % eve)
    esc = Escritor(eve)
    ide = "V2-ROTACION-%s" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    t0 = time.time()
    hasta = t0 + DUR + 10
    log = []

    def nota(que, **k):
        log.append(dict(k, que=que, t=round(time.time() - t0, 3)))

    borrar_pcap = {"hecho": False}

    def anillo():
        while time.time() < hasta + 30:
            ahora = time.time()
            nombre = time.strftime("live-%Y%m%d%H%M%S.pcap", time.gmtime(ahora))
            pcap(d / "anillo" / nombre, ahora)
            if 70 <= ahora - t0 < 75 and not borrar_pcap["hecho"]:
                # Se borra el anterior antes de que el archivador lo considere cerrado.
                previos = sorted((d / "anillo").glob("live-*.pcap"))
                if len(previos) >= 2:
                    previos[-2].unlink()
                    borrar_pcap["hecho"] = True
                    nota("pcap_borrado", fichero=previos[-2].name)
            for viejo in sorted((d / "anillo").glob("live-*.pcap"))[:-8]:
                viejo.unlink()
            time.sleep(5 - (time.time() % 5) + 0.01)

    hilo_anillo = threading.Thread(target=anillo, daemon=True)
    hilo_anillo.start()
    time.sleep(6)
    esc.start()
    arch = subprocess.Popen([sys.executable, str(ARCH), "--ejecucion", ide, "--raiz", str(d / "raiz"),
                             "--anillo", str(d / "anillo"), "--eve", str(eve), "--interfaz", "lo",
                             "--margen-previo", "5", "--hasta-epoch", str(hasta), "--margen-final-s", "20",
                             "--libre-minimo-gb", "1", "--cada", "2"],
                            stdout=open(d / "archivador.txt", "w"), stderr=subprocess.STDOUT)
    nota("archivador", pid=arch.pid)

    def a_las(s):
        time.sleep(max(0.0, t0 + s - time.time()))

    a_las(20); r = subprocess.run(["/usr/sbin/logrotate", "-f", "-s", str(d / "lr.state"), str(d / "lr.conf")], capture_output=True, text=True)
    nota("copytruncate_1", rc=r.returncode, err=r.stderr[-200:], seq=esc.seq)
    a_las(40); r = subprocess.run(["/usr/sbin/logrotate", "-f", "-s", str(d / "lr.state"), str(d / "lr.conf")], capture_output=True, text=True)
    nota("copytruncate_2", rc=r.returncode, err=r.stderr[-200:], seq=esc.seq)
    a_las(60); os.rename(eve, d / "eve.json.renombrado"); time.sleep(1.5); esc.reabrir.set()
    nota("rename_create", seq=esc.seq)
    a_las(80)
    (d / "eve.json.sustituto").write_bytes(b"".join((json.dumps({"timestamp": "0", "event_type": "flow", "seq": -i}) + "\n").encode() for i in range(1, 51)))
    os.replace(d / "eve.json.sustituto", eve); time.sleep(1.5); esc.reabrir.set()
    nota("sustitucion", seq=esc.seq, lineas_ajenas=50)
    a_las(100); os.rename(eve, d / "eve.json.borrado"); nota("borrado", seq=esc.seq)
    time.sleep(7); esc.reabrir.set(); nota("reaparece", seq=esc.seq)
    a_las(115); esc.partida.set(); nota("linea_partida", seq=esc.seq)
    a_las(125); esc.corrupta.set(); nota("linea_corrupta", seq=esc.seq)
    a_las(DUR); esc.fin = True; esc.join(); nota("escritor_fin", seq=esc.seq)
    rc = arch.wait(timeout=180)
    nota("archivador_fin", rc=rc)

    run = d / "raiz" / ide
    vistas, ajenas, malas = [], 0, 0
    for l in open(run / "eve" / ("eve-%s.json" % ide), "rb"):
        try:
            s = json.loads(l)["seq"]
        except Exception:  # noqa: BLE001
            malas += 1; continue
        if s < 0:
            ajenas += 1
        else:
            vistas.append(s)
    vset = set(vistas)
    faltan = [i for i in range(1, esc.seq + 1) if i not in vset]
    tramos = []
    for i in faltan:
        if tramos and tramos[-1][1] == i - 1:
            tramos[-1][1] = i
        else:
            tramos.append([i, i])
    leer = lambda p: [json.loads(x) for x in open(p)] if p.exists() else []
    huecos_eve, huecos_pcap = leer(run / "eve" / "huecos.jsonl"), leer(run / "huecos-pcap.jsonl")
    man = json.loads((run / "manifiesto.json").read_text())
    res = {"ejecucion": ide, "directorio": str(d), "escritas": esc.seq, "archivadas_propias": len(vistas),
           "duplicadas": len(vistas) - len(vset), "faltan": len(faltan), "tramos_faltantes": tramos[:50],
           "lineas_del_sustituto_archivadas": ajenas, "lineas_no_json_en_salida": malas,
           "huecos_eve_declarados": [{k: h[k] for k in ("tipo", "lineas_recuperadas", "lineas_perdidas_estimadas")} for h in huecos_eve],
           "huecos_pcap_declarados": huecos_pcap, "manifiesto": {k: man.get(k) for k in ("estado", "motivo", "eve_huecos", "eve_corruptas", "pcap_huecos", "pcap_ficheros")},
           "cronologia": log}
    (d / "resultado.json").write_text(json.dumps(res, indent=1, ensure_ascii=False))
    print(json.dumps(res, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
