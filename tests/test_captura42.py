"""El programa continuo de 42 h reproduce, segundo a segundo, los factores de J1..J7."""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "generador"))
import programa as prg  # noqa: E402

PROG = RAIZ / "programas"


class TestCaptura42(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c42 = prg.cargar(PROG / "captura-42h.json")
        cls.j = {j: prg.cargar(PROG / ("jornada-%s.json" % j)) for j in ("J1", "J2", "J3", "J4", "J5", "J6", "J7")}

    def test_duracion_segmentos_y_particion(self):
        self.assertEqual(self.c42["duracion_s"], 42 * 3600)
        self.assertEqual([s["id"] for s in self.c42["segmentos"]], ["J1", "J2", "J3", "J4", "J5", "J6", "J7"])
        self.assertEqual(self.c42["horas_por_particion"], {"entrenamiento": 24, "calibracion": 9, "desarrollo": 9})
        self.assertTrue(all(b["fin_s"] - b["inicio_s"] == 10800 for b in self.c42["bloques"]))

    def test_factores_iguales_a_cada_jornada(self):
        # Cada 30 s y en cada borde (±1 s) de fases, pulsos y segmentos.
        bordes = set(range(0, 42 * 3600, 30))
        for tr in self.c42["fases"] + self.c42["pulsos"] + self.c42["segmentos"]:
            for x in (tr["inicio_s"], tr["fin_s"]):
                bordes.update({x - 1, x})
        for t in sorted(b for b in bordes if 0 <= b < 42 * 3600):
            i = t // 21600
            jid = "J%d" % (i + 1)
            for perfil in prg.PERFILES_V1:
                f42, fase, _ = prg.factor(self.c42, perfil, t)
                fj, fasej, _ = prg.factor(self.j[jid], perfil, t - i * 21600)
                self.assertAlmostEqual(f42, fj, places=9, msg="%s t=%s %s" % (perfil, t, jid))
                self.assertEqual(fase["segmento"], jid)
                self.assertEqual(fase["id"], "%s-%s" % (jid, fasej["id"]))

    def test_semillas_unicas_y_distintas_de_las_jornadas(self):
        s42 = {s for b in self.c42["bloques"] for s in b["semillas"].values()}
        sj = {s for p in self.j.values() for b in p["bloques"] for s in b["semillas"].values()}
        self.assertEqual(len(s42), 14 * 6)
        self.assertFalse(s42 & sj)

    def test_huellas_de_origen(self):
        import hashlib
        for s in self.c42["segmentos"]:
            h = hashlib.sha256((PROG / ("jornada-%s.json" % s["id"])).read_bytes()).hexdigest()
            self.assertEqual(h, s["programa_origen_sha256"])


if __name__ == "__main__":
    unittest.main()
