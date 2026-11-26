"""kernel_drops de Suricata: presente con cero, ausente, sin eventos, lectura fallida y reinicio."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import revisar_criterios as rc  # noqa: E402
import suricata_stats as ss  # noqa: E402
import vigia_v2 as vg  # noqa: E402


def stats(seg, uptime, kp, kd="nada"):
    cap = {"kernel_packets": kp, "errors": 0}
    if kd != "nada":
        cap["kernel_drops"] = kd
    return {"timestamp": "2026-11-26T09:%02d:%02d.000000+0000" % divmod(seg, 60), "event_type": "stats",
            "stats": {"uptime": uptime, "capture": cap}}


class Evaluar(unittest.TestCase):
    def test_presente_con_cero_no_es_ausente(self):
        r = ss.evaluar([stats(0, 100, 10, 0), stats(8, 108, 20, 0)])
        self.assertEqual(r["estado"], "presente")
        self.assertEqual(r["delta_kernel_drops"], 0)
        self.assertEqual(r["delta_kernel_packets"], 10)

    def test_ausente_nunca_se_convierte_en_cero(self):
        r = ss.evaluar([stats(0, 100, 10, 0), stats(8, 108, 20)])
        self.assertEqual(r["estado"], "ausente")
        self.assertIsNone(r["delta_kernel_drops"])

    def test_sin_eventos(self):
        r = ss.evaluar([])
        self.assertEqual(r["estado"], "sin_eventos")
        self.assertIsNone(r["delta_kernel_drops"])

    def test_reinicio_suma_tramos_y_se_marca(self):
        r = ss.evaluar([stats(0, 100, 10, 1), stats(8, 108, 20, 3), stats(16, 5, 2, 0), stats(24, 13, 9, 4)])
        self.assertEqual(r["estado"], "reinicio")
        self.assertEqual(r["delta_kernel_drops"], 2 + 4)
        self.assertEqual(len(r["reinicios"]), 1)

    def test_extraer_conserva_solo_stats_y_ordena(self):
        with tempfile.TemporaryDirectory() as t:
            eve = Path(t) / "eve.json"
            filas = [stats(8, 108, 20, 0), {"event_type": "flow", "src_ip": "10.10.20.21"}, stats(0, 100, 10, 0)]
            eve.write_text("".join(json.dumps(x) + "\n" for x in filas) + '{"event_type":"stats", cortado')
            r = ss.extraer([eve], Path(t) / "s.jsonl")
            lineas = [json.loads(x) for x in (Path(t) / "s.jsonl").read_text().splitlines()]
            self.assertEqual(r["eventos"], 2)
            self.assertEqual([x["stats"]["uptime"] for x in lineas], [100, 108])
            self.assertNotIn("10.10.20.21", (Path(t) / "s.jsonl").read_text())


class C9(unittest.TestCase):
    def cap(self, filas, nombre="eve-V2-X.json"):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        CAP = Path(t.name) / "capturas" / "V2-X"
        (CAP / "eve").mkdir(parents=True)
        (CAP / "eve" / nombre).write_text("".join(json.dumps(x) + "\n" for x in filas))
        return CAP

    def test_estados(self):
        self.assertIs(rc.suricata(self.cap([stats(0, 100, 10, 0), stats(8, 108, 20, 0)]), True)["ok"], True)
        self.assertIsNone(rc.suricata(self.cap([stats(0, 100, 10)]), True)["ok"])          # ausente
        self.assertIsNone(rc.suricata(self.cap([{"event_type": "flow"}]), True)["ok"])     # sin eventos
        self.assertIsNone(rc.suricata(Path(tempfile.gettempdir()) / "no-existe-cf", True)["ok"])
        self.assertIs(rc.suricata(self.cap([stats(0, 100, 10, 0), stats(8, 3, 1, 0)]), True)["ok"], False)
        x = rc.suricata(self.cap([stats(0, 100, 10, 0), stats(8, 108, 20, 2)]), False)
        self.assertIs(x["ok"], False)
        self.assertIn("decide C7", x["nota"])

    def test_extracto_publicado_equivale_y_no_duplica(self):
        filas = [stats(0, 100, 10, 0), stats(8, 108, 20, 0)]
        CAP = self.cap(filas)
        (CAP / "eve" / "suricata-stats-V2-X.jsonl").write_text("".join(json.dumps(x) + "\n" for x in filas))
        self.assertEqual(rc.suricata(CAP, True)["valor"]["eventos"], 2)


class Vigia(unittest.TestCase):
    def setUp(self):
        self.tmp = RAIZ / "tests" / ("temporal-" + uuid.uuid4().hex)
        self.tmp.mkdir(mode=0o777)
        self.addCleanup(shutil.rmtree, self.tmp)
        self.a = SimpleNamespace(ejecucion="V2-P0", estado_remoto="/captura/estado.json",
                                 permiso_remoto="/p", v2ctl_remoto="/v2ctl.py",
                                 registro=str(self.tmp / "vigia.jsonl"), max_fallos=3, latido_max_s=60,
                                 cada=10, supervision_cada_s=1)

    def test_leer_stats_distingue_estados(self):
        self.assertEqual(vg.leer_stats(json.dumps(stats(0, 1, 1, 0)))["kernel_drops_estado"], "presente")
        self.assertEqual(vg.leer_stats(json.dumps(stats(0, 1, 1, 0)))["kernel_drops"], 0)
        r = vg.leer_stats(json.dumps(stats(0, 1, 1)))
        self.assertEqual((r["kernel_drops_estado"], r["kernel_drops"]), ("ausente", None))
        self.assertEqual(vg.leer_stats("")["kernel_drops_estado"], "sin_stats")

    def correr(self, lecturas, fallo_eve_en=()):
        reloj, i = [1000.0], [0]
        def comando(orden):
            if orden[1] == "sensor1" and orden[2].startswith("cat "):
                return json.dumps({"estado": "ok", "utc": "1970-01-01T00:16:40Z", "libre_gb": 10})
            if orden[1] == "sw-core-stack":
                return "Gi2/0/19 is up, line protocol is up\nFull-duplex, 1000Mb/s\n0 output drops"
            if "v2/eve.json" in orden[2]:
                if i[0] in fallo_eve_en:
                    raise RuntimeError("ssh caído")
                return json.dumps(lecturas[i[0]])
            if orden[2] == "date +%s.%N":
                return str(reloj[0])
            return ""
        v = vg.Vigia(self.a, ejecutor=comando, reloj=lambda: reloj[0])
        for k in range(len(lecturas)):
            i[0], reloj[0] = k, 1000.0 + k
            v.paso()
        sup = [json.loads(x) for x in (self.tmp / "supervision.jsonl").read_text().splitlines()]
        f = self.tmp / "invalidaciones.jsonl"
        inv = [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
        return sup, inv

    def test_reinicio_invalida_y_rehace_la_base(self):
        # 10 drops antes del reinicio; tras él, 0 -> 3: sin rehacer la base, 3 < 10 quedaría oculto
        sup, inv = self.correr([stats(0, 100, 50, 10), stats(8, 4, 5, 0), stats(16, 12, 9, 3)])
        self.assertEqual([x["condicion"] for x in inv], ["reinicio_suricata", "kernel_drops"])
        self.assertTrue(sup[1]["suricata_reinicio"])

    def test_lectura_fallida_no_es_cero(self):
        sup, inv = self.correr([stats(0, 100, 50, 0), stats(8, 108, 60, 0)], fallo_eve_en=(1,))
        self.assertEqual(sup[1]["kernel_drops_estado"], "lectura_fallida")
        self.assertIsNone(sup[1]["kernel_drops"])
        self.assertIn("eve_error", sup[1])
        self.assertEqual(inv, [])


if __name__ == "__main__":
    unittest.main()
