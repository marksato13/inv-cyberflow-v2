#!/usr/bin/env python3
"""Archivado continuo de PCAP cerrados y líneas EVE, con huecos explícitos."""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import time
from pathlib import Path

ANILLO = Path("/var/lib/ppi-motor-capture")
EVE = Path("/var/log/suricata/eve.json")
STATS = Path("/var/log/suricata/stats.log")
PATRON = re.compile(r"^live-(\d{14})\.pcap$")
ROTACION_S = 5
GRACIA_RETIRADO_S = 30  # tiempo sin crecer antes de cerrar un inodo EVE sustituido


def ahora_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(ruta: Path) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def comprimir_verificado(ruta: Path, sha_original: str) -> dict:
    """gzip-1 sin pérdida: escribe RUTA.gz, comprueba que al descomprimir da el mismo sha256 y
    solo entonces borra el original. Si la verificación falla, conserva el original y lo dice."""
    gz = ruta.with_name(ruta.name + ".gz")
    with open(ruta, "rb") as src, gzip.GzipFile(gz, "wb", compresslevel=1, mtime=0) as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
    h = hashlib.sha256()
    with gzip.open(gz, "rb") as f:
        for trozo in iter(lambda: f.read(1 << 20), b""):
            h.update(trozo)
    if h.hexdigest() != sha_original:
        gz.unlink()
        return {"comprimido": False, "error_compresion": "sha256 tras descomprimir distinto"}
    ruta.unlink()
    return {"comprimido": True, "fichero_archivado": gz.name, "bytes_gz": gz.stat().st_size, "sha256_gz": sha256(gz)}


def nombre_a_epoch(nombre: str) -> float | None:
    m = PATRON.match(nombre)
    if not m:
        return None
    return datetime.datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc).timestamp()


def sh(orden: list[str]) -> str:
    try:
        r = subprocess.run(orden, capture_output=True, text=True, timeout=20)
        return r.stdout.strip() if r.returncode == 0 else "ERROR %s: %s" % (r.returncode, r.stderr.strip())
    except (OSError, subprocess.TimeoutExpired) as e:
        return "ERROR %s" % e


def relojes() -> dict:
    seguimiento = sh(["chronyc", "tracking"]) if shutil.which("chronyc") else sh(["timedatectl", "timesync-status"])
    return {"utc": ahora_utc(), "monotonic": time.monotonic(),
            "timedatectl_show": sh(["timedatectl", "show"]), "seguimiento_ntp": seguimiento}


def contadores(interfaz: str) -> dict:
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
    c["tcpdump_ultima_estadistica"] = sh(["journalctl", "-u", "ppi-motor-capture", "-n", "40", "--no-pager"])
    c["suricata_stats"] = sh(["tail", "-c", "200000", str(STATS)])
    return c


def marcas_pcap(ruta: Path) -> tuple[float | None, float | None]:
    """Lee cabecera libpcap y registros; conserva solo las marcas extrema."""
    with open(ruta, "rb") as f:
        cab = f.read(24)
        magic = cab[:4]
        formatos = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                    b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if len(cab) != 24 or magic not in formatos:
            raise ValueError("cabecera libpcap inválida: %s" % ruta)
        orden, escala = formatos[magic]
        primero = ultimo = None
        while (reg := f.read(16)):
            if len(reg) != 16:
                raise ValueError("registro libpcap truncado: %s" % ruta)
            seg, frac, incl, _orig = struct.unpack(orden + "IIII", reg)
            if len(f.read(incl)) != incl:
                raise ValueError("paquete libpcap truncado: %s" % ruta)
            marca = seg + frac / escala
            primero = marca if primero is None else primero
            ultimo = marca
        return primero, ultimo


class SeguidorEve:
    def __init__(self, ruta: Path, archivador: Archivador):
        self.ruta, self.arch = ruta, archivador
        self.fd = None
        self.ino = None
        self.off = 0
        self.ancla = b""
        self.ausente = False
        self.retirados: list[list] = []  # [descriptor, offset, último crecimiento]
        self.abrir(inicial=True)

    def abrir(self, inicial: bool = False) -> None:
        self.fd = open(self.ruta, "rb")
        self.ino = os.fstat(self.fd.fileno()).st_ino
        self.off = os.fstat(self.fd.fileno()).st_size if inicial else 0
        self.fd.seek(self.off)
        if self.off:
            self.fd.seek(max(0, self.off - 64))
            self.ancla = self.fd.read(self.off - max(0, self.off - 64))
        else:
            self.ancla = b""
        self.ausente = False

    def leer(self) -> bytes:
        """El offset solo avanza hasta la última línea completa."""
        self.fd.seek(self.off)
        datos = self.fd.read()
        corte = datos.rfind(b"\n") + 1
        if not corte:
            return b""
        for linea in datos[:corte].splitlines(keepends=True):
            self.arch.linea_eve(self.ruta, linea)
        self.off += corte
        self.fd.seek(max(0, self.off - 64))
        self.ancla = self.fd.read(self.off - max(0, self.off - 64))
        return datos[:corte]

    def ancla_cambiada(self, tamano: int) -> bool:
        if not self.ancla or tamano < self.off:
            return False
        self.fd.seek(self.off - len(self.ancla))
        return self.fd.read(len(self.ancla)) != self.ancla

    def hueco(self, tipo: str, causa: str, recuperados=b"", perdidos=0) -> None:
        self.arch.hueco_eve(tipo, self.ruta, causa, recuperados, perdidos)

    def recuperar_rotada(self) -> None:
        previa = self.off
        patron = self.arch.a.eve_rotada_patron
        base = Path(patron.format(ruta=str(self.ruta)))
        candidatas = [base, Path(str(base) + ".gz")]
        for p in candidatas:
            try:
                with (gzip.open(p, "rb") if p.suffix == ".gz" else open(p, "rb")) as f:
                    datos = f.read()
            except FileNotFoundError:
                continue
            if len(datos) < previa:
                self.hueco("copytruncate_irrecuperable", "copia rotada menor que offset", perdidos=previa - len(datos))
                return
            resto = datos[previa:]
            corte = resto.rfind(b"\n") + 1
            for linea in resto[:corte].splitlines(keepends=True):
                self.arch.linea_eve(self.ruta, linea)
            self.hueco("copytruncate_recuperado" if corte == len(resto) else "copytruncate_parcial",
                       str(p), recuperados=resto[:corte], perdidos=len(resto) - corte)
            return
        self.hueco("copytruncate_irrecuperable", "copia rotada ausente", perdidos=0)

    def vaciar_retirados(self, cerrar_todo: bool = False) -> None:
        for r in list(self.retirados):
            fd, off, t_crec = r
            fd.seek(off)
            datos = fd.read()
            corte = datos.rfind(b"\n") + 1
            if corte:
                for linea in datos[:corte].splitlines(keepends=True):
                    self.arch.linea_eve(self.ruta, linea)
                r[1] = off + corte
                r[2] = time.time()
                self.hueco("retirado_vaciado", "líneas escritas en el inodo anterior tras el cambio",
                           recuperados=datos[:corte], perdidos=0)
            if cerrar_todo or time.time() - r[2] > GRACIA_RETIRADO_S:
                pendiente = os.fstat(fd.fileno()).st_size - r[1]
                if pendiente > 0:
                    self.hueco("linea_incompleta", "inodo anterior cerrado con línea sin terminar", perdidos=pendiente)
                fd.close()
                self.retirados.remove(r)

    def pasada(self) -> None:
        self.vaciar_retirados()
        try:
            st = self.ruta.stat()
        except FileNotFoundError:
            recuperado = b""
            if self.fd:
                recuperado = self.leer()
            if not self.ausente:
                self.hueco("eve_ausente", "ruta borrada o inaccesible", recuperados=recuperado, perdidos=0)
                self.ausente = True
            return
        if self.fd is None:
            self.abrir()
        elif st.st_ino != self.ino:
            estuvo_ausente = self.ausente
            recuperado = self.leer()  # el descriptor viejo permite vaciar rename+create
            # El escritor (Suricata hasta su SIGHUP) puede seguir escribiendo en el inodo viejo:
            # se retira, no se cierra, y se sigue vaciando hasta que deje de crecer.
            self.retirados.append([self.fd, self.off, time.time()])
            self.fd = None
            self.abrir()
            self.hueco("inodo_cambiado", "rename+create o sustitución; descriptor anterior leído",
                       recuperados=recuperado, perdidos=0)
            if estuvo_ausente:
                self.hueco("eve_reaparecido", "ruta sustituida tras ausencia", perdidos=0)
        elif st.st_size < self.off or self.ancla_cambiada(st.st_size):
            self.recuperar_rotada()
            self.off = 0
            self.ancla = b""
        self.leer()
        self.ausente = False


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
        self.procesados: set[str] = set()
        self.vistos: set[str] = set()
        self.ultimo_epoch = None
        self.ultima_marca = None
        self.ultimo_pcap = None
        self.parar = False
        self.bytes_pcap = self.eve_bytes = 0
        self.eve_huecos = self.pcap_huecos = self.eve_corruptas = 0
        self.vol_pcap = self.vol_eve = 0
        self.vol_minuto = int(time.time() // 60)
        self.seguidores = []
        self.ini = None

    def jsonl(self, ruta: Path, obj: dict) -> None:
        with open(ruta, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, sort_keys=True, ensure_ascii=False) + "\n")

    def evento(self, tipo: str, **k) -> None:
        self.ev.write(json.dumps(dict(k, tipo=tipo, utc=ahora_utc()), sort_keys=True) + "\n")
        self.ev.flush()

    def hueco_eve(self, tipo: str, ruta: Path, causa: str, recuperados=b"", perdidos=0) -> None:
        reg = {"tipo": tipo, "ruta": str(ruta), "causa": causa, "utc": ahora_utc(),
               "bytes_recuperados": len(recuperados), "lineas_recuperadas": recuperados.count(b"\n"),
               "bytes_perdidos_estimados": perdidos,
               "lineas_perdidas_estimadas": max(1, perdidos // 200) if perdidos else (1 if "irrecuperable" in tipo else 0)}
        self.jsonl(self.dir / "eve" / "huecos.jsonl", reg)
        if "irrecuperable" in tipo or tipo in ("eve_ausente", "linea_incompleta", "copytruncate_parcial"):
            self.eve_huecos += 1

    def hueco_pcap(self, tipo: str, **k) -> None:
        self.pcap_huecos += 1
        self.jsonl(self.dir / "huecos-pcap.jsonl", dict(k, tipo=tipo, utc=ahora_utc()))

    def linea_eve(self, ruta: Path, linea: bytes) -> None:
        try:
            json.loads(linea)
        except (ValueError, UnicodeDecodeError) as e:
            self.eve_corruptas += 1
            self.jsonl(self.dir / "eve" / "corruptas.jsonl",
                       {"ruta": str(ruta), "utc": ahora_utc(), "error": str(e), "linea_hex": linea.hex()})
            return
        self.eve_out.write(linea)
        self.eve_out.flush()
        self.eve_bytes += len(linea)
        self.vol_eve += len(linea)

    def senal(self, signum, _f) -> None:
        self.parar = True
        self.evento("senal", nombre=signal.Signals(signum).name)

    def pasada_pcap(self) -> None:
        nombres = sorted(n for n in os.listdir(self.a.anillo) if PATRON.match(n))
        presentes = set(nombres)
        for n in sorted(self.vistos - presentes - self.procesados):
            # Se vio (abierto o cerrado) y desapareció sin copiarse: pérdida segura.
            ep = nombre_a_epoch(n)
            if ep is not None and ep >= self.desde - ROTACION_S:
                self.hueco_pcap("borrado_antes_de_copiar", fichero=n)
            self.procesados.add(n)
        self.vistos |= presentes
        for n in nombres[:-1]:  # cerrado solo si hay uno posterior
            if n in self.procesados:
                continue
            ep = nombre_a_epoch(n)
            if ep is None or ep < self.desde - ROTACION_S:
                continue
            src, dst = Path(self.a.anillo) / n, self.dir / "pcap" / n
            try:
                shutil.copy2(src, dst)
            except FileNotFoundError:
                self.hueco_pcap("borrado_antes_de_copiar", fichero=n)
                self.procesados.add(n)
                continue
            primero, ultimo = marcas_pcap(dst)
            # Con el ruido de fondo del espejo siempre hay paquetes: falta un fichero si el
            # siguiente nombre llega a 2 rotaciones (antes se exigía más de 2 y uno solo pasaba).
            if self.ultimo_epoch is not None and ep - self.ultimo_epoch >= 2 * ROTACION_S:
                self.hueco_pcap("salto_nombres", anterior_epoch=self.ultimo_epoch, siguiente=n,
                                segundos=ep - self.ultimo_epoch)
            if self.ultima_marca is not None and primero is not None and primero - self.ultima_marca > 2 * ROTACION_S:
                self.hueco_pcap("salto_paquetes", anterior_epoch=self.ultima_marca,
                                siguiente_epoch=primero, segundos=primero - self.ultima_marca)
            if ultimo is not None:
                self.ultima_marca = ultimo
            reg = {"fichero": n, "inicio_nombre_epoch": ep, "primer_paquete_epoch": primero,
                   "ultimo_paquete_epoch": ultimo, "bytes": dst.stat().st_size,
                   "sha256": sha256(dst), "copiado_utc": ahora_utc()}
            if getattr(self.a, "comprimir", False):
                reg.update(comprimir_verificado(dst, reg["sha256"]))
            self.jsonl(self.dir / "inventario.jsonl", reg)
            self.copiados.add(n)
            self.procesados.add(n)
            self.ultimo_epoch = ep
            self.ultimo_pcap = n
            self.bytes_pcap += reg["bytes"]
            self.vol_pcap += reg["bytes"]

    def pasada_eve(self) -> None:
        for seguidor in self.seguidores:
            seguidor.pasada()

    def libre_gb(self) -> float:
        st = os.statvfs(self.dir)
        return st.f_bavail * st.f_frsize / 1e9

    def estado(self, estado: str, motivo: str = "") -> None:
        reg = {"estado": estado, "motivo": motivo, "libre_gb": self.libre_gb(),
               "ultimo_pcap_copiado": self.ultimo_pcap, "eve_huecos": self.eve_huecos,
               "pcap_huecos": self.pcap_huecos, "utc": ahora_utc()}
        temporal = self.dir / "estado.json.tmp"
        temporal.write_text(json.dumps(reg, sort_keys=True), encoding="utf-8")
        temporal.replace(self.dir / "estado.json")

    def volumen(self, forzar=False) -> None:
        minuto = int(time.time() // 60)
        if forzar or minuto != self.vol_minuto:
            self.jsonl(self.dir / "volumen.jsonl", {"minuto_epoch": self.vol_minuto * 60,
                       "pcap_bytes": self.vol_pcap, "eve_bytes": self.vol_eve, "utc": ahora_utc()})
            self.vol_minuto, self.vol_pcap, self.vol_eve = minuto, 0, 0

    def fin_copiado(self) -> bool:
        hasta = self.a.hasta_epoch
        if not hasta:
            return True
        nombres = sorted((nombre_a_epoch(n), n) for n in os.listdir(self.a.anillo) if nombre_a_epoch(n) is not None)
        return any(ep <= hasta < siguiente and siguiente - ep <= 2 * ROTACION_S and n in self.copiados
                   for (ep, n), (siguiente, _) in zip(nombres, nombres[1:]))

    def cerrar(self, motivo: str, incompleta: bool) -> None:
        self.volumen(forzar=True)
        try:
            self.pasada_eve()
            for s in self.seguidores:
                s.vaciar_retirados(cerrar_todo=True)
                if s.fd:
                    pendiente = os.fstat(s.fd.fileno()).st_size - s.off
                    if pendiente > 0:
                        s.hueco("linea_incompleta", "cierre de sesión", perdidos=pendiente)
        except Exception as e:
            incompleta = True
            motivo = "cierre_eve: %s" % e
        for s in self.seguidores:
            if s.fd:
                s.fd.close()
        fin = contadores(self.a.interfaz)
        (self.dir / "contadores-fin.json").write_text(json.dumps(fin, indent=1, sort_keys=True))
        (self.dir / "relojes-fin.json").write_text(json.dumps(relojes(), indent=1, sort_keys=True))
        self.eve_out.close()
        self.inv.close()
        man = {"ejecucion": self.a.ejecucion, "estado": "incompleta" if incompleta or self.eve_huecos or self.pcap_huecos or self.eve_corruptas else "completa",
               "motivo": motivo, "pcap_ficheros": len(self.copiados), "pcap_bytes": self.bytes_pcap,
               "pcap_completo": self.pcap_huecos == 0, "pcap_huecos": self.pcap_huecos,
               "eve_bytes": self.eve_bytes, "eve_sha256": sha256(self.dir / "eve" / ("eve-%s.json" % self.a.ejecucion)),
               "eve_completo": self.eve_huecos == 0 and self.eve_corruptas == 0,
               "eve_huecos": self.eve_huecos, "eve_corruptas": self.eve_corruptas,
               "inventario_sha256": sha256(self.dir / "inventario.jsonl"),
               "inicio": self.ini["utc"] if self.ini else None, "fin": fin["utc"],
               "delta_nic_rx_dropped": (fin["nic_rx_dropped"] - self.ini["nic_rx_dropped"])
               if self.ini and None not in (fin.get("nic_rx_dropped"), self.ini.get("nic_rx_dropped")) else None,
               "delta_nic_rx_packets": (fin["nic_rx_packets"] - self.ini["nic_rx_packets"])
               if self.ini and None not in (fin.get("nic_rx_packets"), self.ini.get("nic_rx_packets")) else None,
               "ubicacion": str(self.dir)}
        (self.dir / "manifiesto.json").write_text(json.dumps(man, indent=1, sort_keys=True))
        self.evento("fin", estado=man["estado"], motivo=motivo)
        self.ev.close()
        self.estado("fallo" if man["estado"] == "incompleta" else "terminado", motivo)

    def correr(self) -> int:
        self.desde = time.time() - self.a.margen_previo
        incompleta = False
        motivo = "fin_programado"
        try:
            ini = contadores(self.a.interfaz)
            self.ini = ini
            (self.dir / "contadores-inicio.json").write_text(json.dumps(ini, indent=1, sort_keys=True))
            (self.dir / "relojes-inicio.json").write_text(json.dumps(relojes(), indent=1, sort_keys=True))
            self.seguidores = [SeguidorEve(Path(p), self) for p in self.a.eve]
            self.evento("inicio", ejecucion=self.a.ejecucion, pid=os.getpid(), desde_epoch=self.desde,
                        hasta_epoch=self.a.hasta_epoch, version_script_sha256=sha256(Path(__file__)))
            self.estado("ok")
            while True:
                self.pasada_pcap()
                self.pasada_eve()
                self.volumen()
                if self.libre_gb() < self.a.libre_minimo_gb:
                    incompleta, motivo = True, "espacio"
                    break
                self.estado("ok")
                if self.parar or (self.dir / "PARAR").exists():
                    incompleta, motivo = True, "parada"
                    self.a.hasta_epoch = time.time()
                    limite = self.a.hasta_epoch + self.a.margen_final_s
                    while time.time() < limite and not self.fin_copiado():
                        self.pasada_pcap()
                        self.pasada_eve()
                        self.volumen()
                        if self.libre_gb() < self.a.libre_minimo_gb:
                            motivo = "espacio"
                            break
                        self.estado("ok")
                        time.sleep(min(self.a.cada, 5.0))
                    if not self.fin_copiado():
                        self.hueco_pcap("final_no_copiado", hasta_epoch=self.a.hasta_epoch)
                    break
                if self.a.hasta_epoch and time.time() >= self.a.hasta_epoch + self.a.margen_final_s:
                    if self.fin_copiado():
                        break
                    incompleta, motivo = True, "pcap_final_no_cerrado"
                    self.hueco_pcap("final_no_copiado", hasta_epoch=self.a.hasta_epoch)
                    break
                time.sleep(min(self.a.cada, 5.0))
        except Exception as e:
            incompleta, motivo = True, "%s: %s" % (type(e).__name__, e)
            self.evento("excepcion", motivo=motivo)
            self.estado("fallo", motivo)
        self.cerrar(motivo, incompleta)
        return 1 if incompleta or self.eve_huecos or self.pcap_huecos or self.eve_corruptas else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ejecucion", required=True)
    p.add_argument("--raiz", default="/home/m4rk/cyberflow-v2/capturas")
    p.add_argument("--anillo", default=str(ANILLO))
    p.add_argument("--eve", action="append", default=None, help="ruta EVE (repetible)")
    p.add_argument("--eve-rotada-patron", default="{ruta}.1")
    p.add_argument("--interfaz", default="ens37")
    p.add_argument("--cada", type=float, default=5.0)
    p.add_argument("--margen-previo", type=float, default=30.0)
    p.add_argument("--hasta-epoch", type=float, default=0.0)
    p.add_argument("--margen-final-s", type=float, default=60.0)
    p.add_argument("--libre-minimo-gb", type=float, default=4.0)
    p.add_argument("--comprimir", action=argparse.BooleanOptionalAction, default=True,
                   help="gzip-1 sin pérdida de cada PCAP, verificado por sha256 antes de borrar la copia sin comprimir")
    a = p.parse_args()
    a.eve = a.eve or [str(EVE)]
    arch = Archivador(a)
    signal.signal(signal.SIGTERM, arch.senal)
    signal.signal(signal.SIGINT, arch.senal)
    try:
        return arch.correr()
    except Exception as e:
        motivo = "%s: %s" % (type(e).__name__, e)
        try:
            arch.estado("fallo", motivo)
            (arch.dir / "manifiesto.json").write_text(json.dumps(
                {"ejecucion": a.ejecucion, "estado": "incompleta", "motivo": motivo,
                 "eve_completo": False, "pcap_completo": False,
                 "eve_huecos": arch.eve_huecos, "pcap_huecos": arch.pcap_huecos}, indent=1))
        except OSError:
            pass  # un disco lleno puede impedir incluso el registro de fallo
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
