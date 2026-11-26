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
        P = Path(t.name) / "pruebas" / "V2-X"          # como en el laboratorio: pruebas/<ID>, capturas/<ID>
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
        eve = Path(t.name) / "capturas" / "V2-X" / "eve"
        eve.mkdir(parents=True)
        (eve / "eve-V2-X.json").write_text("".join(json.dumps(
            {"timestamp": "2026-11-26T09:00:0%d.0+0000" % i, "event_type": "stats",
             "stats": {"uptime": 100 + i, "capture": {"kernel_packets": 10 + i, "kernel_drops": 0}}}) + "\n"
            for i in range(2)))
        return P

    def test_c9_delta_de_drops(self):
        P = self.carpeta()
        self.assertIs(rc.c9(P, P / "registros", True)["ok"], True)
        P = self.carpeta(d19_fin=101)
        (P / "registros" / "calidad-espejo-sondeo.json").write_text(json.dumps(
            {"segundos_por_clase": {"sin_descartes": 100, "con_descartes": 1, "indeterminado": 0}}))
        # Δ != 0 con descartes también en la captura: se cuantifica y decide C7 (PROTOCOLO §10)
        self.assertIs(rc.c9(P, P / "registros", False)["ok"], False)
        r = rc.c9(P, P / "registros", True)
        self.assertIs(r["ok"], True)
        self.assertIn("decide C7", r["comprobaciones"][0]["nota"])
        self.assertIsNone(rc.c9(P, P / "registros", None)["ok"])
        self.assertTrue(r["requiere_duracion_prolongada"])
        # kernel_drops de Suricata se mide (EVE dedicada): ya no queda pendiente de otra comprobación
        self.assertEqual(r["pendiente_otra_comprobacion"], [])
        self.assertEqual(r["comprobaciones"][-1]["valor"]["estado"], "presente")

    def test_c9_delta_fuera_de_la_captura_con_sondeo_limpio_vd4(self):
        P = self.carpeta(d19_fin=172)
        r = rc.c9(P, P / "registros", False)       # aunque C7 fallara: el Δ no es de la captura
        self.assertIs(r["comprobaciones"][0]["ok"], True)
        self.assertIn("fuera del intervalo", r["comprobaciones"][0]["nota"])
        (P / "registros" / "calidad-espejo-sondeo.json").write_text(json.dumps(
            {"segundos_por_clase": {"sin_descartes": 100, "con_descartes": 2, "indeterminado": 0}}))
        self.assertIs(rc.c9(P, P / "registros", False)["ok"], False)

    def test_c9_segundos_sin_sondeo_es_falta_no_fallo(self):
        P = self.carpeta()
        (P / "registros" / "calidad-espejo-sondeo.json").write_text(json.dumps(
            {"segundos_por_clase": {"sin_descartes": 100, "con_descartes": 0, "indeterminado": 30}}))
        self.assertIsNone(rc.c9(P, P / "registros", True)["ok"])

    def test_c13_aislamiento_al_final(self):
        P = self.carpeta(aplicar=1)
        self.assertIs(rc.c13(P, P / "registros")["ok"], False)

    def test_c10_sin_ntp_final_de_un_equipo_queda_sin_decidir(self):
        P = self.carpeta(ntp_fin_sensor1=False)
        r = rc.c10(P, P / "registros", P / "generador" / "V2-X")
        self.assertIsNone(r["ok"])
        self.assertTrue(any("sensor1" in f for f in r["falta_evidencia"]))


class Integracion(unittest.TestCase):
    def evaluar(self, duracion, ok7=True, tipo=None):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        p = Path(t.name) / "pruebas" / "V2-X"
        (p / "registros").mkdir(parents=True)
        lz = {"duracion_s": duracion} if tipo is None else {"duracion_s": duracion, "tipo_ejecucion": tipo}
        (p / "registros" / "lanzamiento.json").write_text(json.dumps(lz))
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

    def test_tipo_inferido_en_lanzamientos_anteriores(self):
        r = self.evaluar(1440)
        self.assertEqual((r["tipo_ejecucion"], r["tipo_inferido_por_duracion"]), ("verificacion_dirigida", True))

    def test_verificacion_dirigida_declarada(self):
        r = self.evaluar(1440, tipo="verificacion_dirigida")
        self.assertFalse([m for m in r["motivos"] if "prolongada" in m or "otra:" in m])
        self.assertFalse(r["tipo_inferido_por_duracion"])

    def test_piloto_final_exige_las_otras_comprobaciones(self):
        r = self.evaluar(1800, tipo="piloto_final")
        self.assertIn("falta:otra:C7", r["motivos"])
        self.assertFalse([m for m in r["motivos"] if "prolongada" in m])
        self.assertNotEqual(r["global"], "aprobada")
        self.assertIn("piloto_final", r["alcance"])

    def test_captura_definitiva_exige_prolongadas_aunque_sea_corta(self):
        r = self.evaluar(1440, tipo="captura_definitiva")
        self.assertIn("falta:prolongada:C9", r["motivos"])
        self.assertIn("falta:otra:C7", r["motivos"])

    def test_tipo_desconocido_no_aprueba(self):
        r = self.evaluar(1440, tipo="prueba_rara")
        self.assertIn("falta:tipo_ejecucion", r["motivos"])
        self.assertIn("falta:prolongada:C7", r["motivos"])
        self.assertNotEqual(r["global"], "aprobada")

    def test_lanzador_exige_el_tipo_antes_de_nada(self):
        s = (Path(__file__).resolve().parents[1] / "operacion" / "lanzar_v2.sh").read_text(encoding="utf-8")
        self.assertLess(s.index("CF_TIPO_EJECUCION debe ser"), s.index("candado crear"))
        self.assertIn('"tipo_ejecucion": tipo', s)
        v = (Path(__file__).resolve().parents[1] / "operacion" / "verificacion_dirigida.sh").read_text(encoding="utf-8")
        self.assertIn("CF_TIPO_EJECUCION=verificacion_dirigida", v)

    def test_criterio_revisado_que_falla_no_aprueba(self):
        r = self.evaluar(1440, ok7=False)
        self.assertIn("criterio:C7", r["motivos"])


if __name__ == "__main__":
    unittest.main()
