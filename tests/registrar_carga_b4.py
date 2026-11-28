#!/usr/bin/env python3
"""Mide la EVE sintética de 49 h y observa la captura permanente de Sensor1.

No inicia V2 ni modifica servicios. Conserva la salida del medidor y cada muestra.
"""
import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
from pathlib import Path


def ejecutar(*args):
    p = subprocess.run(args, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(f"{' '.join(args)}: rc={p.returncode}: {p.stderr.strip()}")
    return p.stdout


def ultimo_stats(ruta):
    with ruta.open("rb") as f:
        tam = f.seek(0, 2)
        for n in (1024 * 1024, 8 * 1024 * 1024, 64 * 1024 * 1024):
            f.seek(max(0, tam - n))
            lineas = f.read().splitlines()
            for linea in reversed(lineas[1:] if n < tam else lineas):
                if b'"event_type":"stats"' not in linea and b'"event_type": "stats"' not in linea:
                    continue
                evento = json.loads(linea)
                if evento.get("event_type") == "stats":
                    stats = evento["stats"]
                    captura = stats["capture"]
                    return {"timestamp": evento["timestamp"], "uptime": stats.get("uptime"),
                            "kernel_packets": captura.get("kernel_packets"),
                            "kernel_drops": captura.get("kernel_drops")}
    raise RuntimeError("no se halló un stats reciente en la EVE dedicada")


def muestra(fase, eve):
    ahora = dt.datetime.now(dt.timezone.utc).isoformat()
    unidades = {}
    for nombre in ("ppi-motor-capture", "suricata"):
        propiedades = ejecutar("systemctl", "show", nombre, "-p", "ActiveState",
                              "-p", "MainPID", "-p", "NRestarts")
        unidades[nombre] = dict(linea.split("=", 1) for linea in propiedades.splitlines() if "=" in linea)
    diario = ejecutar("journalctl", "-u", "ppi-motor-capture", "-n", "80",
                      "--no-pager", "-o", "short-iso")
    lineas = [x for x in diario.splitlines() if "packets dropped by kernel" in x]
    if not lineas:
        raise RuntimeError("journalctl sin estadísticas recientes de tcpdump")
    linea = lineas[-1]
    m = re.search(r"(\d+) packets captured, (\d+) packets received by filter, (\d+) packets dropped by kernel", linea)
    if not m:
        raise RuntimeError(f"estadística tcpdump ilegible: {linea}")
    return {"fase": fase, "observado_utc": ahora, "unidades": unidades,
            "tcpdump": {"linea": linea, "capturados": int(m[1]), "recibidos": int(m[2]),
                        "descartados_kernel": int(m[3])},
            "suricata": ultimo_stats(eve)}


def registrar(eve, manifiesto, directorio, salida, medidor):
    salida.parent.mkdir(parents=True, exist_ok=True)
    medidas = []
    resultado = {"tipo": "prueba tecnica sintetica; excluida del conjunto de investigacion",
                 "codigo_medido": "268083b", "muestras": medidas}
    proc = None
    try:
        medidas.append(muestra("antes", Path("/var/log/suricata/v2/eve.json")))
        with (directorio / "medidor-stdout.txt").open("w", encoding="utf-8") as stdout, \
             (directorio / "medidor-stderr.txt").open("w", encoding="utf-8") as stderr:
            proc = subprocess.Popen([sys.executable, str(medidor),
                                     "--eve", str(eve), "--manifiesto", str(manifiesto),
                                     "--directorio", str(directorio / "salidas"),
                                     "--resumen", str(directorio / "medicion.json")],
                                    stdout=stdout, stderr=stderr)
            while proc.poll() is None:
                time.sleep(10)
                medidas.append(muestra("durante", Path("/var/log/suricata/v2/eve.json")))
            resultado["rc_medidor"] = proc.returncode
        # El timer de V1 pide estadísticas de tcpdump cada 30 s; esperar su próxima muestra.
        time.sleep(35)
        medidas.append(muestra("despues", Path("/var/log/suricata/v2/eve.json")))
        if proc.returncode:
            raise RuntimeError(f"medidor rc={proc.returncode}; véase medidor-stderr.txt")
        antes, despues = medidas[0], medidas[-1]
        resultado["evaluacion_contadores"] = {
            "muestras_durante": sum(x["fase"] == "durante" for x in medidas),
            "delta_tcpdump_descartados": despues["tcpdump"]["descartados_kernel"] - antes["tcpdump"]["descartados_kernel"],
            "delta_suricata_kernel_drops": despues["suricata"]["kernel_drops"] - antes["suricata"]["kernel_drops"],
            "mismo_pid_tcpdump": len({x["unidades"]["ppi-motor-capture"]["MainPID"] for x in medidas}) == 1,
            "mismo_pid_suricata": len({x["unidades"]["suricata"]["MainPID"] for x in medidas}) == 1,
            "sin_reinicios": all(x["unidades"][u]["NRestarts"] == "0" for x in medidas
                                for u in ("ppi-motor-capture", "suricata")),
            "ambas_activas": all(x["unidades"][u]["ActiveState"] == "active" for x in medidas
                                 for u in ("ppi-motor-capture", "suricata")),
        }
        if (resultado["evaluacion_contadores"]["delta_tcpdump_descartados"] != 0
                or resultado["evaluacion_contadores"]["delta_suricata_kernel_drops"] != 0
                or not resultado["evaluacion_contadores"]["sin_reinicios"]
                or not resultado["evaluacion_contadores"]["ambas_activas"]):
            raise RuntimeError("descartes, reinicios o servicio inactivo durante la carga")
    except Exception as e:
        resultado["error"] = str(e)
        raise
    finally:
        salida.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return resultado


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--eve", type=Path, required=True)
    p.add_argument("--manifiesto", type=Path, required=True)
    p.add_argument("--directorio", type=Path, required=True)
    p.add_argument("--salida", type=Path, required=True)
    p.add_argument("--medidor", type=Path, required=True)
    a = p.parse_args()
    a.directorio.mkdir(parents=True, exist_ok=True)
    print(json.dumps(registrar(a.eve, a.manifiesto, a.directorio, a.salida,
                              a.medidor)["evaluacion_contadores"]))
