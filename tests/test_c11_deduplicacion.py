"""C11 y la deduplicación (Bloque 3): qué queda pendiente según la verificación de la extracción."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import revisar_criterios as rc  # noqa: E402


class C11Deduplicacion(unittest.TestCase):
    def c11(self, deduplicacion):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        P = Path(t.name)
        (P / "extraccion").mkdir()
        ver = {"filas_verificadas": 40, "diferencias": [], "sin_futuro_ok": True, "paridad_motor_ok": True,
               "referencia": "x", "constantes": []}
        if deduplicacion is not None:
            ver["deduplicacion"] = deduplicacion
        (P / "extraccion" / "verificacion.json").write_text(json.dumps(ver), encoding="utf-8")
        (P / "extraccion" / "resumen.json").write_text(json.dumps(
            {"orden_eve": {"tardios_descartados": 0}, "orden_pcap": {"tardias_descartadas": 0}}), encoding="utf-8")
        (P / "extraccion" / "inventario_ips.json").write_text(json.dumps([{"ip": "10.10.20.21", "regla": "r"}]),
                                                             encoding="utf-8")
        (P / "pasos-analisis.jsonl").write_text('{"paso":"extraer","rc":0}\n{"paso":"verificar","rc":0}\n',
                                              encoding="utf-8")
        return rc.c11(P, P)

    def test_extraccion_anterior_sigue_con_el_defecto_de_v1(self):
        r = self.c11(None)
        self.assertEqual(r["ok"], True)
        self.assertTrue(any("RST idénticos" in x for x in r["pendiente_otra_comprobacion"]))

    def test_misma_funcion_en_el_motor_cierra_el_pendiente(self):
        r = self.c11({"motor_referencia": "deduplicar_v2.deduplicar_espejo_v2", "motor_misma_funcion": True})
        self.assertEqual((r["ok"], r["pendiente_otra_comprobacion"]), (True, []))

    def test_motor_con_la_de_v1_deja_pendiente_la_paridad(self):
        r = self.c11({"motor_referencia": "v3.deduplicar_espejo", "motor_misma_funcion": False})
        self.assertEqual(len(r["pendiente_otra_comprobacion"]), 1)
        self.assertIn("v3.deduplicar_espejo", r["pendiente_otra_comprobacion"][0])


if __name__ == "__main__":
    unittest.main()
