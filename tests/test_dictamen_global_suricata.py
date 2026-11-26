"""Dictamen global con los stats de Suricata alterados (revisión 7), sobre una COPIA temporal de las
entradas publicadas de VD4 (aprobada en r6). Solo cambia la ventana de stats; los originales no se tocan.

  - pérdida dentro del periodo                         -> no_aprobada (criterio:C9)
  - pérdida dentro del periodo con un hueco de 24 s    -> no_aprobada (el fallo manda sobre la falta)
  - pérdida solo en el intervalo que cruza el inicio   -> indeterminada (falta:criterio:C9)
  - sin uptime                                         -> indeterminada
  - sin alterar                                        -> aprobada
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import suricata_stats as ss  # noqa: E402

ID = "V2-VD4-20261126T141333Z"
B1 = RAIZ / "evidencias" / "bloque1"
E = B1 / "entradas-r4" / ID
COMPLEMENTOS = [B1 / "suricata-r5" / ID, B1 / "suricata-r6" / ID]
VENTANA = B1 / "suricata-r6" / ID / "pruebas" / ID / "registros" / ("suricata-stats-ventana-%s.jsonl" % ID)


@unittest.skipUnless(E.is_dir() and VENTANA.is_file(), "faltan las entradas publicadas de VD4")
class DictamenGlobalSuricata(unittest.TestCase):
    def preparar(self, alterar):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        t = Path(t.name)
        P, K = t / ID, t / "capturas" / ID
        shutil.copytree(E / "pruebas" / ID, P)
        shutil.copytree(E / "capturas" / ID, K)
        for C in COMPLEMENTOS:
            if (C / "capturas" / ID).is_dir():
                shutil.copytree(C / "capturas" / ID, K, dirs_exist_ok=True)
            if (C / "pruebas" / ID).is_dir():
                shutil.copytree(C / "pruebas" / ID, P, dirs_exist_ok=True)
        # una sola fuente de stats (la ventana), para que la alteración no la tape otra copia
        for f in (K / "eve").glob("suricata-stats-*.jsonl"):
            f.unlink()
        m = json.loads((K / "manifiesto.json").read_text(encoding="utf-8"))
        ini, fin = ss.epoch(m["inicio"]), ss.epoch(m["fin"])
        ev = [json.loads(x) for x in VENTANA.read_text(encoding="utf-8").splitlines() if x.strip()]
        ev = alterar(ev, ini, fin)
        f = P / "registros" / VENTANA.name
        f.write_text("".join(json.dumps(e) + "\n" for e in ev), encoding="utf-8")
        py = [sys.executable, "-I", "-X", "utf8"]
        op = RAIZ / "operacion"
        r = subprocess.run(py + [str(op / "revisar_criterios.py"), "--pruebas", str(P), "--capturas", str(K)],
                           capture_output=True, stdin=subprocess.DEVNULL, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        r = subprocess.run(py + [str(op / "estado_global.py"), ID, "--pruebas", str(P), "--ejecucion-dir",
                                 str(P / "registros"), "--captura-dir", str(K)],
                           capture_output=True, stdin=subprocess.DEVNULL, text=True, encoding="utf-8")
        g = json.JSONDecoder().raw_decode(r.stdout)[0]
        crit = json.loads((P / "criterios-revisados.json").read_text(encoding="utf-8"))["criterios"]
        sur = [x for x in crit["C9"]["comprobaciones"] if x["que"].startswith("Suricata")][0]
        return g, sur

    @staticmethod
    def sumar(ev, desde_t, n):
        """+n a kernel_drops en todas las muestras desde el instante desde_t (pérdida en el intervalo
        que termina en la primera de ellas)."""
        for e in ev:
            if ss.epoch(e["timestamp"]) >= desde_t:
                e["stats"]["capture"]["kernel_drops"] += n
        return ev

    def test_sin_alterar_aprobada(self):
        g, sur = self.preparar(lambda ev, i, f: ev)
        self.assertEqual((g["global"], sur["valor"]["estado"]), ("aprobada", "presente"))

    def test_perdida_dentro_del_periodo_no_aprobada(self):
        g, sur = self.preparar(lambda ev, i, f: self.sumar(ev, i + 600, 3))
        self.assertEqual((sur["ok"], sur["valor"]["estado"], sur["valor"]["delta_kernel_drops_atribuible"]), (False, "perdida", 3))
        self.assertIn("criterio:C9", g["motivos"])
        self.assertEqual(g["global"], "no_aprobada")

    def test_perdida_con_hueco_de_24_s_no_aprobada(self):
        def alterar(ev, i, f):
            # quita las muestras de (i+600, i+624): hueco de unos 24-32 s, y la pérdida cae dentro
            ev = [e for e in ev if not (i + 600 < ss.epoch(e["timestamp"]) < i + 624)]
            return self.sumar(ev, i + 624, 3)
        g, sur = self.preparar(alterar)
        v = sur["valor"]
        self.assertEqual((sur["ok"], v["estado"], v["delta_kernel_drops_atribuible"]), (False, "perdida", 3))
        self.assertTrue(any(x.startswith("huecos") for x in v["falta_evidencia"]))
        self.assertEqual(g["global"], "no_aprobada")

    def test_perdida_solo_en_el_intervalo_que_cruza_el_inicio_indeterminada(self):
        def alterar(ev, i, f):
            primera_dentro = min(ss.epoch(e["timestamp"]) for e in ev if ss.epoch(e["timestamp"]) > i)
            return self.sumar(ev, primera_dentro, 2)
        g, sur = self.preparar(alterar)
        v = sur["valor"]
        self.assertEqual((sur["ok"], v["estado"], v["delta_kernel_drops_ampliado"]), (None, "perdida_no_localizada", 2))
        self.assertIn("falta:criterio:C9", g["motivos"])
        self.assertNotIn("criterio:C9", g["motivos"])
        self.assertEqual(g["global"], "indeterminada")

    def test_sin_uptime_indeterminada(self):
        def alterar(ev, i, f):
            for e in ev:
                e["stats"].pop("uptime", None)
            return ev
        g, sur = self.preparar(alterar)
        self.assertEqual((sur["ok"], sur["valor"]["estado"]), (None, "insuficiente"))
        self.assertEqual(g["global"], "indeterminada")


if __name__ == "__main__":
    unittest.main()
