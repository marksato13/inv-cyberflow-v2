"""Comprobación sensor1_anillo de preflight_lab.sh: el FRAGMENTO REAL, con bash y un `ssh` falso que
ejecuta la orden en local sobre un anillo temporal (en lugar de /var/lib/ppi-motor-capture)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tests.test_cierre_ventana import RAIZ, bash, ruta, ruta_path


def fragmento() -> str:
    t = (RAIZ / "operacion" / "preflight_lab.sh").read_text(encoding="utf-8")
    i = t.index("# El anillo que copia el archivador V2")
    j = t.index("\n", t.index("ok sensor1_anillo fallo \"ultimo PCAP")) + 1
    return t[i:j]


@unittest.skipUnless(bash(), "sin bash")
class PreflightAnillo(unittest.TestCase):
    def setUp(self):
        base = next((c for c in (os.environ.get("LOCALAPPDATA", "") + "\\Temp", "/tmp", tempfile.gettempdir())
                     if c and " " not in c and Path(c).is_dir()), None)
        if base is None:
            self.skipTest("sin carpeta temporal sin espacios")
        self.d = Path(tempfile.mkdtemp(prefix="cf-preflight-", dir=base))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.anillo = self.d / "anillo"
        self.anillo.mkdir()

    def correr(self):
        b = self.d / "bin"
        b.mkdir(exist_ok=True)
        (b / "ssh").write_text(
            "#!/bin/bash\nwhile [[ $1 == -* ]]; do shift; done\nshift\n"
            "cmd=\"$*\"; cmd=\"${cmd//\\/var\\/lib\\/ppi-motor-capture/%s}\"\neval \"$cmd\"\n" % ruta(self.anillo),
            newline="\n")
        os.chmod(b / "ssh", 0o755)
        g = self.d / "p.sh"
        g.write_text("set -u\nexport PATH=\"%s:$PATH\"\nfallos=0\n"
                     "ok() { printf '{\"comprobacion\":\"%%s\",\"resultado\":\"%%s\",\"detalle\":\"%%s\"}\\n' \"$1\" \"$2\" \"$3\"; }\n"
                     "%s" % (ruta_path(b), fragmento()), newline="\n")
        r = subprocess.run([bash(), ruta(g)], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def pcap(self, antiguedad_s):
        f = self.anillo / ("live-%d.pcap" % (1000 + antiguedad_s))
        f.write_bytes(b"x")
        t = time.time() - antiguedad_s
        os.utime(f, (t, t))

    def test_anillo_al_dia(self):
        self.pcap(60)
        self.pcap(2)
        x = self.correr()
        self.assertEqual((x["comprobacion"], x["resultado"]), ("sensor1_anillo", "ok"))

    def test_anillo_parado_aunque_la_unidad_siga_activa(self):
        self.pcap(40)
        x = self.correr()
        self.assertEqual(x["resultado"], "fallo")
        self.assertIn("hace 4", x["detalle"])

    def test_anillo_vacio(self):
        x = self.correr()
        self.assertEqual((x["resultado"], x["detalle"]), ("fallo", "anillo: sin_ficheros"))


if __name__ == "__main__":
    unittest.main()
