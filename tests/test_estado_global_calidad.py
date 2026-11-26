"""Política de calidad integrada en el dictamen (revisión del 26-nov).

Antes, `calidad_copias` y `calidad_dns` podían fallar sin impedir una aprobación. Estas pruebas
fijan que una pérdida relevante, una entrada dañada o una evidencia obligatoria ausente producen
el estado que dice docs/BLOQUE1-POLITICA-CALIDAD.md.
"""
from __future__ import annotations

from test_estado_global import TestEstadoGlobal as Base


class TestCalidadEnDictamen(Base):
    def dictamen(self):
        self.pasos()
        return self.evaluar()

    # -- base -----------------------------------------------------------------------------------
    def test_todo_completo_aprueba(self):
        r = self.dictamen()
        self.assertEqual((r["calidad_copias"], r["calidad_dns"], r["global"]),
                         ("completo", "completo", "aprobada"))

    # -- fallo: la evidencia existe y muestra un defecto -------------------------------------
    def test_perdida_de_copia_en_la_poblacion_es_fallo(self):
        for clase in ("falta_copia", "vlan_incorrecta"):
            with self.subTest(clase=clase):
                self.copias({"completo": 99, clase: 1})
                r = self.dictamen()
                self.assertEqual((r["calidad_copias"], r["global"], r["codigo_salida"]),
                                 ("perdida", "no_aprobada", 1))
                self.assertIn("calidad_copias:perdida", r["motivos"])

    def test_captura_danada_es_fallo(self):
        self.copias(entrada_completa=False)
        r = self.dictamen()
        self.assertEqual((r["calidad_copias"], r["global"]), ("entrada_danada", "no_aprobada"))

    def test_discrepancia_dns_es_fallo(self):
        self.dns(discrepancias=1, sin_discrepancias=9)
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("discrepancia", "no_aprobada"))
        self.assertIn("calidad_dns:discrepancia", r["motivos"])

    def test_dns_con_error_de_entrada_es_fallo(self):
        self.escribir(self.p / "calidad-contraste-dns.json", {"total": {}, "error": "PCAP truncado"})
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("entrada_danada", "no_aprobada"))

    def test_perdida_no_queda_tapada_por_una_falta(self):
        # Fallo e indeterminación a la vez: gana el fallo.
        self.copias({"completo": 99, "falta_copia": 1})
        (self.p / "calidad-contraste-dns.json").unlink()
        r = self.dictamen()
        self.assertEqual(r["global"], "no_aprobada")
        self.assertIn("falta:calidad_dns", r["motivos"])

    # -- indeterminación: falta evidencia o no decide -----------------------------------------
    def test_sin_comprobador_de_copias_es_indeterminada(self):
        (self.p / "calidad-copias-espejo.json").unlink()
        r = self.dictamen()
        self.assertEqual((r["calidad_copias"], r["global"]), ("sin_datos", "indeterminada"))
        self.assertIn("falta:calidad_copias", r["motivos"])

    def test_copias_ambiguas_o_sin_eventos_son_indeterminadas(self):
        for clases, estado in (({"completo": 99, "ambiguo": 1}, "indeterminado"),
                               ({"completo": 99, "clase_nueva": 1}, "indeterminado"),
                               ({}, "sin_eventos")):
            with self.subTest(clases=clases):
                self.copias(clases)
                r = self.dictamen()
                self.assertEqual((r["calidad_copias"], r["global"]), (estado, "indeterminada"))

    def test_sin_contraste_dns_es_indeterminada(self):
        (self.p / "calidad-contraste-dns.json").unlink()
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("sin_datos", "indeterminada"))

    def test_pcap_dc1_declarado_y_no_usado_es_indeterminada(self):
        # El caso de E3 publicado: el registrador escribió el PCAP y el contraste no lo usó.
        self.dns(pcap_dc1=False, declara_pcap=True)
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("falta_pcap_dc1", "indeterminada"))
        self.assertIn("falta:calidad_dns", r["motivos"])

    def test_registrador_sin_pcap_no_exige_pcap(self):
        self.dns(pcap_dc1=False, declara_pcap=False)
        self.assertEqual(self.dictamen()["calidad_dns"], "completo")

    def test_evento_sin_transaccion_no_explicado_es_indeterminada(self):
        self.dns(sueltos=6, explicados=4)
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("indeterminado", "indeterminada"))

    def test_transaccion_no_comprobada_es_indeterminada(self):
        for campo in ("ambiguas", "indeterminado_dc1", "no_determinables"):
            with self.subTest(campo=campo):
                self.dns(**{campo: 1, "comprobadas": 9, "sin_discrepancias": 9})
                self.assertEqual(self.dictamen()["global"], "indeterminada")

    def test_dns_sin_transacciones_es_indeterminada(self):
        self.dns(transacciones=0, comprobadas=0, sin_discrepancias=0)
        self.assertEqual(self.dictamen()["calidad_dns"], "sin_transacciones")

    def test_resultado_dns_antiguo_sin_clasificacion_no_aprueba_sueltos(self):
        self.dns()
        d = self.leer_json(self.p / "calidad-contraste-dns.json")
        d.pop("sin_transaccion_clasificacion")
        d["sin_transaccion"]["total"] = 6
        self.escribir(self.p / "calidad-contraste-dns.json", d)
        self.assertEqual(self.dictamen()["calidad_dns"], "indeterminado")

    # -- explicados: se registran y no cambian el estado ---------------------------------------
    def test_solo_sondas_explicadas_aprueba(self):
        self.dns(sueltos=6, explicados=6)
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("completo", "aprobada"))

    def test_sondas_explicadas_por_firma_ya_no_aprueban(self):
        # clasificación de la primera revisión (id + prefijo, sin «relaciones»)
        self.dns(sueltos=6, explicados=6, formato_antiguo=True)
        self.assertEqual(self.dictamen()["calidad_dns"], "indeterminado")

    def test_sondas_explicadas_por_registro_reconstruido_no_aprueban(self):
        self.dns(sueltos=6, explicados=6, reconstruidos=6)
        r = self.dictamen()
        self.assertEqual((r["calidad_dns"], r["global"]), ("indeterminado", "indeterminada"))

    # -- referencia independiente del extremo (srv-dmz) ------------------------------------------
    def test_perdida_vista_por_el_extremo_es_fallo(self):
        for k in ({"sin_sensor": 1}, {"solo_extremo": 1}):
            with self.subTest(**k):
                self.extremo(**k)
                r = self.dictamen()
                self.assertEqual((r["calidad_extremo"], r["global"]), ("perdida", "no_aprobada"))
                self.assertIn("calidad_extremo:perdida", r["motivos"])

    def test_extremo_ausente_es_indeterminado(self):
        (self.p / "calidad-extremo.json").unlink()
        r = self.dictamen()
        self.assertEqual((r["calidad_extremo"], r["global"]), ("sin_datos", "indeterminada"))
        self.assertIn("falta:calidad_extremo", r["motivos"])
        (self.e / "extremo-captura.json").unlink()
        self.assertEqual(self.dictamen()["calidad_extremo"], "sin_datos")

    def test_referencia_incompleta_no_decide(self):
        for k in ({"descartes": 3}, {"estado_captura": "sin_estadisticas"}, {"periodo": False},
                  {"sin_extremo": 2}):
            with self.subTest(**k):
                self.extremo(**k)
                r = self.dictamen()
                self.assertEqual((r["calidad_extremo"], r["global"]), ("indeterminado", "indeterminada"))

    def test_copia_danada_del_extremo_es_fallo(self):
        (self.e / ("extremo-%s.pcap.danado" % self.id)).write_bytes(b"x")
        self.assertEqual(self.dictamen()["calidad_extremo"], "entrada_danada")

    # -- sondas del preflight frente al periodo útil ----------------------------------------------
    def test_sonda_en_periodo_util_es_fallo(self):
        self.sonda(estado="contaminacion_en_periodo_util")
        r = self.dictamen()
        self.assertEqual((r["calidad_sonda"], r["global"]), ("contaminacion", "no_aprobada"))

    def test_sin_registro_de_sondas_es_indeterminado(self):
        for k in ({"presente": False}, {"estado": "sin_registro"}, {"version": 1}):
            with self.subTest(**k):
                self.sonda(**k)
                self.assertEqual(self.dictamen()["global"], "indeterminada")

    def test_sonda_con_registro_reconstruido_no_aprueba(self):
        self.sonda(fuentes=("reconstruido",))
        self.assertEqual(self.dictamen()["calidad_sonda"], "indeterminado")

    # -- guardas planificadas frente a exclusiones por incidente -------------------------------
    def test_guardas_e_incidentes_se_informan_por_separado(self):
        self.escribir(self.p / "extraccion" / "trazabilidad.json", {
            "trazabilidad_ok": True, "ventanas": 100, "excluidas": 30,
            "exclusion_por_regla": {"E1:arranque": 23, "E5:fuera_del_programa": 2, "E2:hueco_captura": 5}})
        r = self.dictamen()
        self.assertEqual(r["exclusiones"]["guardas_planificadas"], {"E1:arranque": 23, "E5:fuera_del_programa": 2})
        self.assertEqual(r["exclusiones"]["por_incidente"], {"E2:hueco_captura": 5})

    def test_exclusiones_no_convierten_perdida_en_aprobada(self):
        self.escribir(self.p / "extraccion" / "trazabilidad.json", {
            "trazabilidad_ok": True, "exclusion_por_regla": {"E2:hueco_captura": 50}})
        self.copias({"completo": 99, "falta_copia": 1})
        self.assertEqual(self.dictamen()["global"], "no_aprobada")

    def leer_json(self, p):
        import json
        return json.loads(p.read_text())
