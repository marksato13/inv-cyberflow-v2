"""revisar_criterios.py: C7 y C9–C13 revisados con evidencia; lo prolongado, aparte."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import estado_global as eg  # noqa: E402
import revisar_criterios as rc  # noqa: E402

CONT = """=== utc x
=== switch GigabitEthernet2/0/19
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: {d19}
=== switch GigabitEthernet1/0/23
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
=== switch GigabitEthernet2/0/23
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 24
=== sensor1
ens37_rx_missed_errors 0
ens37_rx_errors 0
softnet_dropped 0
nov 26 tcpdump[1]: tcpdump: 5 packets captured, 5 packets received by filter, 0 packets dropped by kernel
=== aislamiento_v1
srvdmz_limitados 0
srvdmz_bloqueados 0
agente_aplicar {aplicar}
dc1_nft_lineas 0
"""


class Revisar(unittest.TestCase):
    def test_reglas_de_ok(self):
        self.assertIs(rc.criterio([rc.c("a", True)])["ok"], True)
        self.assertIs(rc.criterio([rc.c("a", True), rc.c("b", False)])["ok"], False)
        self.assertIsNone(rc.criterio([rc.c("a", True)], falta=["x"])["ok"])
        self.assertIsNone(rc.criterio([])["ok"])
        # lo prolongado no cambia el resultado de lo comprobable
        self.assertIs(rc.criterio([rc.c("a", True)], prolongada=["49 h"])["ok"], True)

    def carpeta(self, d19_fin=100, aplicar=0, ntp_fin_sensor1=True):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        P = Path(t.name) / "V2-X"
        E = P / "registros"
        E.mkdir(parents=True)
        (E / "contadores-lab-inicio.txt").write_text(CONT.format(d19=100, aplicar=0))
        (E / "contadores-lab-fin.txt").write_text(CONT.format(d19=d19_fin, aplicar=aplicar))
        (E / "calidad-espejo-sondeo.json").write_text(json.dumps(
            {"segundos_por_clase": {"sin_descartes": 100, "con_descartes": 0, "indeterminado": 0}}))
        (E / "extremo-captura.json").write_text(json.dumps({"descartados_nucleo": 0}))
        pre = [{"comprobacion": k, "resultado": "ok", "detalle": "x"} for k in
               ("ntp_sensor1", "ntp_clientes", "ntp_srvdmz", "ntp_dc1", "exclusion_v1", "srvdmz_sets_vacios",
                "agente_v1_sombra", "dc1_sin_restricciones")]
        (E / "preflight-lab.jsonl").write_text("".join(json.dumps(x) + "\n" for x in pre))
        for h in ("srvdmz", "10.10.10.20") + (("sensor1",) if ntp_fin_sensor1 else ()):
            (E / ("relojes-fin-%s.txt" % h)).write_text("NTPSynchronized=yes\n")
        (E / "exclusion-v1.json").write_text(json.dumps({"cubierto": True}))
        return P

    def test_c9_delta_de_drops(self):
        self.assertIs(rc.c9(self.carpeta(), self.carpeta() / "registros")["ok"], True)
        P = self.carpeta(d19_fin=101)
        r = rc.c9(P, P / "registros")
        self.assertIs(r["ok"], False)
        self.assertTrue(r["requiere_duracion_prolongada"])
        self.assertTrue(r["pendiente_otra_comprobacion"])   # Suricata kernel_drops no medible

    def test_c13_aislamiento_al_final(self):
        P = self.carpeta(aplicar=1)
        self.assertIs(rc.c13(P, P / "registros")["ok"], False)

    def test_c10_sin_ntp_final_de_un_equipo_queda_sin_decidir(self):
        P = self.carpeta(ntp_fin_sensor1=False)
        r = rc.c10(P, P / "registros", P / "generador" / "V2-X")
        self.assertIsNone(r["ok"])
        self.assertTrue(any("sensor1" in f for f in r["falta_evidencia"]))


class Integracion(unittest.TestCase):
    def evaluar(self, duracion, ok7=True):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        p = Path(t.name) / "pruebas" / "V2-X"
        (p / "registros").mkdir(parents=True)
        (p / "registros" / "lanzamiento.json").write_text(json.dumps({"duracion_s": duracion}))
        crit = {k: {"ok": True} for k in [f"C{i}" for i in range(1, 14)] + ["C11b"]}
        for k in ("C7", "C9", "C10", "C11", "C12", "C13"):
            crit[k] = {"ok": None, "revisar": True}
        (p / "criterios.json").write_text(json.dumps(crit))
        rev = {k: {"ok": True, "requiere_duracion_prolongada": ["algo de 49 h"]} for k in ("C9", "C10", "C11", "C12", "C13")}
        rev["C7"] = {"ok": ok7, "requiere_duracion_prolongada": ["rotación"], "pendiente_otra_comprobacion": ["x"]}
        (p / "criterios-revisados.json").write_text(json.dumps({"criterios": rev}))
        return eg.evaluar("V2-X", p, None, Path(t.name) / "capturas" / "V2-X")

    def test_corta_no_cuenta_lo_prolongado_y_lo_conserva_aparte(self):
        r = self.evaluar(1440)
        self.assertFalse([m for m in r["motivos"] if m.startswith("falta:criterio")])
        self.assertFalse([m for m in r["motivos"] if "prolongada" in m])
        self.assertEqual(set(r["pendientes_duracion_prolongada"]), {"C7", "C9", "C10", "C11", "C12", "C13"})
        self.assertIn("C7", r["pendientes_otra_comprobacion"])
        self.assertIn("verificacion_corta", r["alcance"])

    def test_larga_lo_prolongado_sigue_pendiente(self):
        r = self.evaluar(176400)
        self.assertIn("falta:prolongada:C7", r["motivos"])

    def test_criterio_revisado_que_falla_no_aprueba(self):
        r = self.evaluar(1440, ok7=False)
        self.assertIn("criterio:C7", r["motivos"])


if __name__ == "__main__":
    unittest.main()
