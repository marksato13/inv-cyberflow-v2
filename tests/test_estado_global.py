"""Dictamen global con evidencias sintéticas, sin red."""
from __future__ import annotations

import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import estado_global as eg  # noqa: E402


class TestEstadoGlobal(unittest.TestCase):
    def setUp(self):
        self.base = RAIZ / "tests" / ("temporal-" + uuid.uuid4().hex)
        self.base.mkdir()
        self.addCleanup(shutil.rmtree, self.base)
        self.id = "V2-PRUEBA-20261125T150000Z"
        self.p = self.base / "pruebas" / self.id
        self.e = self.p / "registros"
        self.c = self.base / "capturas" / self.id
        self.g = self.p / "generador" / self.id
        for d in (self.e, self.c, self.g, self.p / "extraccion", self.p / "conciliacion"):
            d.mkdir(parents=True, exist_ok=True)
        self.escribir(self.g / "manifiesto-fin.json", {"estado": "completa"})
        self.escribir(self.c / "manifiesto.json", {"estado": "completa"})
        self.escribir(self.e / "lanzamiento.json", {"real": {}})
        self.escribir(self.e / "exclusion-v1.json", {"cubierto": True})
        self.jsonl(self.e / "vigia.jsonl", {"tipo": "archivador_terminado"})
        self.jsonl(self.e / "supervision.jsonl", {
            "enlace_valido": True, "output_drops": 0, "kernel_drops": 0,
            "eve_huecos": 0, "pcap_huecos": 0, "libre_gb": 10,
            "desfase_sensor1_s": 0, "desfase_clientes_s": 0})
        for n in ("resumen.json", "verificacion.json"):
            self.escribir(self.p / "extraccion" / n, {})
        self.escribir(self.p / "extraccion" / "trazabilidad.json", {"trazabilidad_ok": True})
        for n in ("entradas_if.csv", "ventanas_meta.csv"):
            (self.p / "extraccion" / n).write_text("ventana_id\n")
        self.escribir(self.p / "conciliacion" / "conciliacion-resumen.json", {})
        (self.p / "conciliacion" / "conciliacion.jsonl").write_text("{}\n")
        (self.e / "analisis-salida.txt").write_text(
            "conciliar rc=0\nextraer rc=0\nverificar rc=0\nmetadatos rc=0\n")
        self.escribir(self.p / "criterios.json", {
            **{f"C{i}": {"ok": True} for i in range(1, 14)}, "C11b": {"ok": True}})
        self.sondeo(("sin_descartes", 0, 100))
        self.copias()
        self.dns()

    def copias(self, clases=None, entrada_completa=True):
        clases = {"completo": 100} if clases is None else clases
        self.escribir(self.p / "calidad-copias-espejo.json", {
            "resultado_global": "examinado_completo" if entrada_completa else "incompleto",
            "entrada_completa": entrada_completa,
            "denominadores": {"eventos": sum(clases.values()), "eventos_por_clase": clases}})

    def dns(self, pcap_dc1=True, declara_pcap=True, sueltos=0, explicados=0, **total):
        base = {"transacciones": 10, "comprobadas": 10, "sin_discrepancias": 10, "discrepancias": 0,
                "no_determinables": 0, "indeterminado_dc1": 0, "ambiguas": 0}
        base.update(total)
        self.escribir(self.p / "calidad-contraste-dns.json", {
            "total": base, "sin_transaccion": {"total": sueltos, "items": [], "truncados": 0},
            "sin_transaccion_clasificacion": {"explicados": explicados, "no_explicados": sueltos - explicados},
            "tramas_ilegibles": {"total": 0, "items": [], "truncados": 0},
            "parametros": {"pcap_dc1": pcap_dc1}})
        arranque = {"evento": "arranque", "version": "2.0.0"}
        if declara_pcap:
            arranque["pcap"] = "/var/log/cyberflow-v2/dns.pcap"
        (self.e / ("dns-%s.jsonl" % self.id)).write_text(json.dumps(arranque) + "\n")

    def sondeo(self, *tramos):
        self.escribir(self.e / "calidad-espejo-sondeo.json", {"intervalos": [
            {"clase": c, "desde": d, "hasta": h} for c, d, h in tramos]})

    def escribir(self, p, obj):
        p.write_text(json.dumps(obj))

    def jsonl(self, p, obj):
        with p.open("a") as f:
            f.write(json.dumps(obj) + "\n")

    def evaluar(self):
        return eg.evaluar(self.id, self.p, self.e, self.c)

    def pasos(self, **rc):
        base = dict.fromkeys(eg.PASOS_OBLIGATORIOS, 0)
        base.update(rc)
        with (self.e / "pasos-analisis.jsonl").open("w") as f:
            for k, v in base.items():
                if v is not None:
                    f.write(json.dumps({"paso": k, "rc": v}) + "\n")

    def test_pasos_estructurados_aprobada(self):
        self.pasos()
        r = self.evaluar()
        self.assertEqual((r["global"], r["dictamen"], r["codigo_salida"]), ("aprobada", "aprobado", 0))

    def test_sin_sondeo_nunca_es_sin_perdidas(self):
        self.pasos()
        for caso in ({"error": "registro ausente o vacío"}, None):
            if caso is None:
                (self.e / "calidad-espejo-sondeo.json").unlink()
            else:
                self.escribir(self.e / "calidad-espejo-sondeo.json", caso)
            r = self.evaluar()
            self.assertEqual((r["espejo"], r["global"]), ("sin_datos", "indeterminada"))
            self.assertIn("falta:espejo", r["motivos"])

    def test_sondeo_con_hueco_y_con_descartes(self):
        self.pasos()
        self.sondeo(("indeterminado", 0, 30), ("sin_descartes", 30, 100))
        r = self.evaluar()
        self.assertEqual((r["espejo"], r["global"]), ("indeterminado", "indeterminada"))
        self.sondeo(("sin_descartes", 0, 30), ("con_descartes", 30, 32))
        r = self.evaluar()
        self.assertEqual((r["espejo"], r["global"]), ("con_descartes", "no_aprobada"))
        self.assertIn("espejo:con_descartes", r["motivos"])

    def test_fallo_cobertura_no_queda_oculto(self):
        # antes de 26-nov cobertura y fronteras no entraban en el dictamen
        self.pasos(cobertura=1)
        r = self.evaluar()
        self.assertEqual((r["global"], r["codigo_salida"]), ("no_aprobada", 1))
        self.assertIn("analisis:fallo:cobertura", r["motivos"])

    def test_paso_ausente_indeterminada(self):
        self.pasos(fronteras=None)
        r = self.evaluar()
        self.assertEqual((r["global"], r["codigo_salida"]), ("indeterminada", 2))
        self.assertIn("falta:paso:fronteras", r["motivos"])

    def test_fallo_deliberado_97(self):
        self.pasos(extraer=97)
        self.assertEqual(self.evaluar()["dictamen"], "fallido")

    def test_aprobada(self):
        self.assertEqual(self.evaluar()["global"], "aprobada")

    def test_falta_evidencia_indeterminada(self):
        (self.p / "criterios.json").unlink()
        self.assertEqual(self.evaluar()["global"], "indeterminada")

    def test_archivador_incompleto_no_aprobada(self):
        self.escribir(self.c / "manifiesto.json", {"estado": "incompleta", "motivo": "espacio"})
        self.assertEqual(self.evaluar()["global"], "no_aprobada")

    def test_pruebas_parada_no_aprobadas(self):
        for caso in ("espacio", "archivador", "vigia"):
            with self.subTest(caso=caso):
                self.escribir(self.g / "manifiesto-fin.json",
                              {"estado": "incompleta", "motivo": caso})
                self.jsonl(self.e / "prueba-parada.jsonl", {"provocado": caso})
                self.assertEqual(self.evaluar()["global"], "no_aprobada")
