#!/usr/bin/env python3
"""Entradas mínimas y saneadas de una ejecución para reproducir su dictamen sin los PCAP.

    python3 extracto_saneado.py --pruebas pruebas/<ID> --capturas capturas/<ID> --salida <carpeta nueva> \
        [--permitida IP ...]

Copia los ficheros de texto que leen estado_global.py, evaluar_piloto.py, revisar_criterios.py y
dictamen_casos.py (.json, .jsonl, .csv, .txt, .log). Los PCAP, comprimidos y tar se quedan fuera;
su sha256 está en SHA256SUMS de la ejecución.

Saneado:
  - las IP del experimento se conservan: las de las transacciones del generador más las --permitida;
  - cualquier otra IPv4 (terceros, NTP público…) se sustituye de forma consistente por una dirección
    de documentación (198.51.100.0/24, luego 203.0.113.0/24), así que los recuentos y las reglas por
    IP siguen dando lo mismo;
  - las direcciones de red de las subredes del laboratorio (10.10.X.0, p. ej. en «10.10.20.0/24») se
    conservan: nombran una subred, no un equipo. Sin esta regla (antes de 2026-11-26 r4) también se
    sustituían, y la configuración del espejo y las rutas de calidad_copias dejaban de ser comparables;
  - las MAC se sustituyen por 02:00:00:00:xx:yy, de forma consistente.
La correspondencia NO se escribe; SANEADO.json dice qué se incluyó, qué se dejó fuera y cuántas
direcciones se sustituyeron.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import ipaddress
import json
import re
from pathlib import Path

SUFIJOS = (".json", ".jsonl", ".csv", ".txt", ".log")
MAX_BYTES = 60_000_000
IP = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
DOC = [ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")]


class Saneador:
    def __init__(self, permitidas):
        self.permitidas = set(permitidas)
        self.ips, self.macs = {}, {}
        self.libres = [str(h) for red in DOC for h in red.hosts()]

    def ip(self, m):
        s = m.group(0)
        if any(int(o) > 255 for o in m.groups()) or s in self.permitidas:
            return s
        if s.startswith("10.10.") and s.endswith(".0"):
            return s
        if s not in self.ips:
            if not self.libres:
                raise SystemExit("demasiadas IP ajenas para el espacio de documentación")
            self.ips[s] = self.libres.pop(0)
        return self.ips[s]

    def mac(self, m):
        s = m.group(0).lower()
        if s not in self.macs:
            n = len(self.macs) + 1
            self.macs[s] = "02:00:00:00:%02x:%02x" % (n >> 8, n & 255)
        return self.macs[s]

    def texto(self, t):
        return MAC.sub(self.mac, IP.sub(self.ip, t))


def ips_experimento(pruebas: Path):
    ips = set()
    for f in glob.glob(str(pruebas / "generador" / "*" / "transacciones-*.jsonl")):
        for linea in open(f, encoding="utf-8", errors="replace"):
            ips.update(m.group(0) for m in IP.finditer(linea))
    return ips


def extraer(pruebas: Path, capturas: Path, salida: Path, permitidas=()):
    if salida.exists():
        raise SystemExit("la carpeta de salida ya existe: %s" % salida)
    perm = ips_experimento(pruebas) | set(permitidas)
    s = Saneador(perm)
    incluidos, fuera = [], []
    for raiz, nombre in ((pruebas, "pruebas"), (capturas, "capturas")):
        for f in sorted(p for p in raiz.rglob("*") if p.is_file()):
            rel = "%s/%s/%s" % (nombre, raiz.name, f.relative_to(raiz).as_posix())
            if nombre == "capturas" and f.relative_to(raiz).parts[0] == "eve":
                # El EVE completo lleva metadatos de aplicación de terceros (DNS, SNI, URL): no se
                # publica aunque las IP estén sustituidas. El dictamen no lo necesita.
                fuera.append({"fichero": rel, "bytes": f.stat().st_size,
                              "motivo": "EVE completo: metadatos de aplicación de terceros (DNS, SNI, URL)"})
                continue
            if f.suffix not in SUFIJOS or f.name == "SHA256SUMS" or f.stat().st_size > MAX_BYTES:
                fuera.append({"fichero": rel, "bytes": f.stat().st_size,
                              "motivo": "binario o captura (PCAP/comprimido)" if f.suffix not in SUFIJOS
                              else "SHA256SUMS de la ejecución" if f.name == "SHA256SUMS" else "demasiado grande"})
                continue
            d = salida / rel
            d.parent.mkdir(parents=True, exist_ok=True)
            d.write_text(s.texto(f.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
            incluidos.append(rel)
    resumen = {"version": 1, "ejecucion": pruebas.name, "incluidos": len(incluidos), "fuera": fuera,
               "ip_experimento_conservadas": sorted(perm, key=lambda x: tuple(int(o) for o in x.split("."))),
               "ip_ajenas_sustituidas": len(s.ips), "mac_sustituidas": len(s.macs),
               "regla": __doc__.split("Saneado:")[1].split("La correspondencia")[0].strip()}
    (salida / "SANEADO.json").write_text(json.dumps(resumen, indent=1, ensure_ascii=False), encoding="utf-8")
    sumas = []
    for p in sorted(salida.rglob("*")):
        if p.is_file():
            sumas.append("%s  %s" % (hashlib.sha256(p.read_bytes()).hexdigest(), p.relative_to(salida).as_posix()))
    (salida / "SHA256SUMS").write_text("\n".join(sumas) + "\n", encoding="utf-8")
    return resumen


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pruebas", required=True, type=Path)
    ap.add_argument("--capturas", required=True, type=Path)
    ap.add_argument("--salida", required=True, type=Path)
    ap.add_argument("--permitida", action="append", default=[])
    a = ap.parse_args(argv)
    r = extraer(a.pruebas, a.capturas, a.salida, a.permitida)
    print(json.dumps({k: r[k] for k in ("incluidos", "ip_ajenas_sustituidas", "mac_sustituidas")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
