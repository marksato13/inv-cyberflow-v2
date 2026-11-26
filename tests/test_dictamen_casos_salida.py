"""dictamen_casos.py: rechaza, antes de copiar, una salida igual a las pruebas o dentro de ellas
(reanálisis r5: --salida dentro de --pruebas anidó la copia sin fin)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import dictamen_casos as dc  # noqa: E402


class Salida(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base = Path(t.name)
        self.P = self.base / "pruebas" / "V2-X"
        (self.P / "registros").mkdir(parents=True)
        (self.P / "resultado-global.json").write_text(json.dumps({"global": "aprobada"}))
        (self.P / "registros" / "a.jsonl").write_text("{}\n")

    def ficheros(self):
        return sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*"))

    def rechaza(self, salida):
        antes = self.ficheros()
        with self.assertRaises(SystemExit) as e:
            dc.main(["V2-X", "--pruebas", str(self.P), "--capturas", str(self.base / "capturas"), "--salida", str(salida)])
        self.assertIn("dentro de las pruebas", str(e.exception))
        self.assertEqual(self.ficheros(), antes)          # no se creó nada: se rechaza antes de copiar

    def test_salida_dentro_de_las_pruebas(self):
        self.rechaza(self.P / "casos-r5")

    def test_salida_igual_a_las_pruebas(self):
        self.rechaza(self.P)

    def test_salida_dentro_escrita_con_rodeo(self):
        self.rechaza(self.base / "otra" / ".." / "pruebas" / "V2-X" / "registros" / ".." / "casos")

    def test_copiar_tambien_se_protege(self):
        with self.assertRaises(SystemExit):
            dc.copiar(self.P, self.P / "dentro")
        self.assertFalse((self.P / "dentro").exists())

    def test_salida_fuera_se_acepta_y_no_anida(self):
        s = self.base / "casos"
        dc.comprobar_salida(self.P, s)                    # no lanza
        dc.copiar(self.P, s / "correcta" / "pruebas" / "V2-X")
        copiados = [p for p in s.rglob("*") if p.is_file()]
        self.assertEqual(len(copiados), 2)
        self.assertFalse(any("correcta" in p.parts[p.parts.index("correcta") + 1:] for p in copiados))


if __name__ == "__main__":
    unittest.main()