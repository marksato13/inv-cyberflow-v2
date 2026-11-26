"""Paso de stats de Suricata en cerrar_v2.sh (revisión 7), con una EVE sintética en una carpeta temporal.

Dos niveles:
  - suricata_stats.ventana_cierre: extracción correcta, muestra posterior retrasada, reintentos
    agotados, EVE ausente, EVE ilegible y manifiesto ilegible;
  - el FRAGMENTO REAL de cerrar_v2.sh, ejecutado con bash y un `ssh` falso que ejecuta la orden en
    local: argumentos, rc registrado, que el cierre continúa y que C9 lee la salida.
No toca ninguna ejecución original ni el laboratorio.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import revisar_criterios as rc  # noqa: E402
import suricata_stats as ss  # noqa: E402

T0 = dt.datetime(2026, 11, 26, 9, 0, 0, tzinfo=dt.timezone.utc).timestamp()


def iso(s):
    return dt.datetime.fromtimestamp(T0 + s, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def linea(s, kd=0):
    return json.dumps({"timestamp": iso(s), "event_type": "stats",
                       "stats": {"uptime": 1000 + s, "capture": {"kernel_packets": 100 + s, "kernel_drops": kd}}}) + "\n"


def flujo(s):
    return json.dumps({"timestamp": iso(s), "event_type": "flow", "src_ip": "192.0.2.7"}) + "\n"


class Base(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = Path(t.name)
        self.eve = self.d / "eve.json"
        self.sal = self.d / "ventana.jsonl"

    def escribir(self, hasta_s, desde_s=-40):
        self.eve.write_text("".join(linea(s) + flujo(s + 1) for s in range(desde_s, hasta_s + 1, 8)))


class VentanaCierre(Base):
    # periodo [T0, T0+100]; muestras cada 8 s desde T0-40 (…, -8, 0, 8, …, 96, 104)
    def test_extraccion_satisfactoria_al_primer_intento(self):
        self.escribir(104 + 16)
        esperas = []
        rc_, r = ss.ventana_cierre([self.eve], T0, T0 + 100, 30, self.sal, 4, 6, esperas.append)
        self.assertEqual((rc_, r["evaluacion"]["estado"], len(r["intentos"]), esperas), (0, "presente", 1, []))
        self.assertNotIn("192.0.2.7", self.sal.read_text())

    def test_muestra_posterior_retrasada_se_espera(self):
        self.escribir(96)                                    # aún no existe la de 104 s
        llegadas = iter([None, lambda: self.escribir(104)])
        def dormir(s):
            f = next(llegadas)
            if f:
                f()
        rc_, r = ss.ventana_cierre([self.eve], T0, T0 + 100, 30, self.sal, 4, 6, dormir)
        self.assertEqual(rc_, 0)
        self.assertEqual([x["estado"] for x in r["intentos"]], ["insuficiente", "insuficiente", "presente"])
        self.assertTrue(self.sal.exists())

    def test_reintentos_agotados_dejan_evidencia_insuficiente(self):
        self.escribir(96)
        esperas = []
        rc_, r = ss.ventana_cierre([self.eve], T0, T0 + 100, 30, self.sal, 4, 6, esperas.append)
        self.assertEqual((rc_, len(r["intentos"]), esperas), (3, 4, [6, 6, 6]))
        self.assertEqual(r["evaluacion"]["motivo"], "sin muestra en o después del fin")

    def test_otra_insuficiencia_no_se_reintenta(self):
        self.escribir(104, desde_s=8)                       # falta la muestra anterior al inicio
        esperas = []
        rc_, r = ss.ventana_cierre([self.eve], T0, T0 + 100, 30, self.sal, 4, 6, esperas.append)
        self.assertEqual((rc_, len(r["intentos"]), esperas), (3, 1, []))

    def test_eve_ausente_no_deja_salida_ni_una_vieja(self):
        self.sal.write_text(linea(0))                       # salida de un intento anterior
        rc_, r = ss.ventana_cierre([self.d / "no-existe.json"], T0, T0 + 100, 30, self.sal, 4, 6, lambda s: None)
        self.assertEqual((rc_, r["estado"]), (4, "eve_ilegible"))
        self.assertFalse(self.sal.exists())

    def test_eve_ilegible_es_falta_de_evidencia(self):
        self.eve.write_bytes(b"\x00\xff basura sin json\n{\"event_type\":\"stats\", cortado\n")
        rc_, r = ss.ventana_cierre([self.eve], T0, T0 + 100, 30, self.sal, 2, 6, lambda s: None)
        self.assertEqual((rc_, r["evaluacion"]["estado"]), (3, "sin_eventos"))

    def test_manifiesto_ilegible_rc5(self):
        self.escribir(120)
        (self.d / "m.json").write_text("{no es json")
        self.assertEqual(ss.main(["ventana", str(self.eve), "--manifiesto", str(self.d / "m.json"),
                                  "--salida", str(self.sal)]), 5)


def bash():
    # en Windows, Git Bash; el bash.exe de WSL (System32, WindowsApps) no ve las rutas de Windows
    for c in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if c and Path(c).exists() and not re.search(r"System32|WindowsApps", c, re.I):
            return c
    return None


def fragmento_cierre() -> str:
    t = (RAIZ / "operacion" / "cerrar_v2.sh").read_text(encoding="utf-8")
    i = t.index("# Suricata (C9): muestras stats")
    j = t.index("\n", t.index("log suricata_stats_ventana")) + 1
    return t[i:j]


def ruta(p: Path) -> str:
    return str(p).replace("\\", "/")


def ruta_path(p: Path) -> str:
    """Para PATH en Git Bash, donde «:» separa entradas: C:/x -> /c/x."""
    s = ruta(p)
    return "/" + s[0].lower() + s[2:] if re.match(r"^[A-Za-z]:/", s) else s


@unittest.skipUnless(bash(), "sin bash")
class FragmentoCerrar(Base):
    """El fragmento de cerrar_v2.sh, tal cual, con ssh y python3 sustituidos por equivalentes locales."""

    def setUp(self):
        super().setUp()
        # como en Sensor1 (~/cyberflow-v2), una ruta sin espacios: el fragmento no cita $S1 ni $P
        if " " in str(self.d):
            candidatos = [os.environ.get("LOCALAPPDATA", "") + "\\Temp", "/tmp", str(Path.home())]
            base = next((c for c in candidatos if c and " " not in c and Path(c).is_dir()), None)
            if base is None:
                self.skipTest("sin carpeta temporal sin espacios")
            self.d = Path(tempfile.mkdtemp(prefix="cf-cierre-", dir=base))
            self.addCleanup(shutil.rmtree, self.d, True)
            self.eve, self.sal = self.d / "eve.json", self.d / "ventana.jsonl"

    def correr(self, eve_presente=True, manifiesto="{}"):
        S1, P, E = self.d / "s1", self.d / "s1" / "pruebas" / "V2-X", self.d / "E"
        (S1 / "codigo" / "operacion").mkdir(parents=True)
        shutil.copy(RAIZ / "operacion" / "suricata_stats.py", S1 / "codigo" / "operacion")
        (S1 / "capturas" / "V2-X").mkdir(parents=True)
        (S1 / "capturas" / "V2-X" / "manifiesto.json").write_text(manifiesto)
        (P / "registros").mkdir(parents=True)
        E.mkdir()
        bin_ = self.d / "bin"
        bin_.mkdir()
        eve = ruta(self.eve) if eve_presente else ruta(self.d / "no-existe.json")
        # ssh falso: descarta opciones y host, sustituye la EVE de Sensor1 por la sintética y ejecuta
        (bin_ / "ssh").write_text(
            "#!/bin/bash\nwhile [[ $1 == -* ]]; do [[ $1 == -o ]] && shift; shift; done\nshift\n"
            "cmd=\"$*\"; cmd=\"${cmd//\\/var\\/log\\/suricata\\/v2\\/eve.json/%s}\"\n"
            "cmd=\"${cmd//python3/\\\"%s\\\" -I -X utf8}\"\necho \"$cmd\" >> \"%s/ordenes.txt\"\neval \"$cmd\"\n"
            % (eve, ruta(Path(sys.executable)), ruta(self.d)), newline="\n")
        guion = ("set -euo pipefail\nexport PATH=\"%s:$PATH\"\nS1=%s\nP=%s\nE=%s\nID=V2-X\n"
                 "log() { echo \"$1 $2\" >> \"$E/log.txt\"; }\n%s\necho CONTINUA >> \"$E/log.txt\"\n"
                 % (ruta_path(bin_), ruta(S1), ruta(P), ruta(E), fragmento_cierre()))
        g = self.d / "paso.sh"
        g.write_text(guion, newline="\n")
        os.chmod(bin_ / "ssh", 0o755)
        r = subprocess.run([bash(), ruta(g)], capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=120)
        log = (E / "log.txt").read_text() if (E / "log.txt").exists() else ""
        return r, log, P, S1

    def manifiesto(self):
        return json.dumps({"inicio": iso(0).replace("+0000", "Z"), "fin": iso(100).replace("+0000", "Z")})

    def test_fragmento_extrae_y_c9_lo_usa(self):
        self.escribir(104 + 16)
        r, log, P, S1 = self.correr(manifiesto=self.manifiesto())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(log, r"suricata_stats_ventana rc=0 ")
        self.assertIn("CONTINUA", log)
        orden = (self.d / "ordenes.txt").read_text()
        self.assertIn("--reintentos 4 --espera 6", orden)
        self.assertIn("--manifiesto %s/capturas/V2-X/manifiesto.json" % ruta(S1), orden)
        salida = P / "registros" / "suricata-stats-ventana-V2-X.jsonl"
        self.assertTrue(salida.exists())
        x = rc.suricata(S1 / "capturas" / "V2-X", True, P)
        self.assertEqual((x["ok"], x["valor"]["estado"]), (True, "presente"))

    def test_fragmento_eve_ausente_registra_rc4_y_continua(self):
        r, log, P, S1 = self.correr(eve_presente=False, manifiesto=self.manifiesto())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(log, r"suricata_stats_ventana rc=4 ")
        self.assertIn("CONTINUA", log)
        self.assertIsNone(rc.suricata(S1 / "capturas" / "V2-X", True, P)["ok"])

    def test_fragmento_manifiesto_ilegible_registra_rc5_y_continua(self):
        self.escribir(120)
        r, log, P, S1 = self.correr(manifiesto="{roto")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(log, r"suricata_stats_ventana rc=5 ")
        self.assertIn("CONTINUA", log)

    def test_el_paso_va_antes_de_revisar_criterios(self):
        t = (RAIZ / "operacion" / "cerrar_v2.sh").read_text(encoding="utf-8")
        self.assertLess(t.index("suricata_stats.py ventana"), t.index("revisar_criterios.py --pruebas"))
        self.assertTrue(re.search(r"\|\| rc_ventana=\$\?", t))


if __name__ == "__main__":
    unittest.main()
