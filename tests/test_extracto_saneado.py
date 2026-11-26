"""extracto_saneado.py: conserva las IP del experimento y sustituye de forma consistente las ajenas."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "operacion"))
import extracto_saneado as es  # noqa: E402


class Extracto(unittest.TestCase):
    def test_saneado(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            p, c = t / "pruebas" / "V2-X", t / "capturas" / "V2-X"
            (p / "generador" / "V2-X").mkdir(parents=True)
            c.mkdir(parents=True)
            (p / "generador" / "V2-X" / "transacciones-P1.jsonl").write_text(
                json.dumps({"origen_ip": "10.10.20.21", "destino_ip": "10.10.30.10"}) + "\n")
            (p / "inventario.json").write_text(json.dumps(
                [{"ip": "10.10.60.45", "regla": "ajena"}, {"ip": "10.10.20.21", "regla": "poblacion"},
                 {"ip": "10.10.60.45", "mac": "AA:BB:CC:DD:EE:FF", "version": "3.12.3"}]))
            (c / "x.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
            r = es.extraer(p, c, t / "salida", ["10.10.10.20"])
            texto = (t / "salida" / "pruebas" / "V2-X" / "inventario.json").read_text()
            self.assertNotIn("10.10.60.45", texto)
            self.assertNotIn("AA:BB", texto.upper().replace("02:00", ""))
            self.assertIn("10.10.20.21", texto)
            self.assertIn("3.12.3", texto)
            self.assertEqual(texto.count("198.51.100.1"), 2)          # consistente
            self.assertEqual(r["ip_ajenas_sustituidas"], 1)
            self.assertEqual(r["fuera"][0]["fichero"], "capturas/V2-X/x.pcap")
            self.assertTrue((t / "salida" / "SHA256SUMS").exists())
            with self.assertRaises(SystemExit):
                es.extraer(p, c, t / "salida")


if __name__ == "__main__":
    unittest.main()
