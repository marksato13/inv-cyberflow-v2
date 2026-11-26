"""Coordinación de copias con la captura (transferir.py), vigilancia de referencias
(vigilar_referencias.py), su integración en el dictamen y en lanzar/cerrar."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import estado_global as eg  # noqa: E402
import transferir as tr  # noqa: E402
import vigilar_referencias as vr  # noqa: E402


def sin_procesos(orden, **_):
    return subprocess.CompletedProcess(orden, 0, "", "")


class Transferir(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        b = Path(self.t.name)
        self._orig = tr.BASE, tr.CANDADO, tr.REGISTRO
        tr.BASE, tr.CANDADO, tr.REGISTRO = b, b / "CAPTURA_EN_CURSO", b / "transferencias.jsonl"
        self.addCleanup(lambda: setattr(tr, "BASE", self._orig[0]) or setattr(tr, "CANDADO", self._orig[1])
                        or setattr(tr, "REGISTRO", self._orig[2]))
        self.copias = []

    def scp(self, orden, **_):
        if orden[0] == "scp":
            self.copias.append(orden)
        return subprocess.CompletedProcess(orden, 0, "", "")

    def test_con_candado_no_se_copia_y_queda_registrado(self):
        self.assertEqual(tr.crear_candado("V2-X", holgura=0), tr.LIBRE)
        self.assertEqual(tr.copiar(["a", "b"], ejecutar=self.scp), tr.OCUPADO)
        self.assertEqual(self.copias, [])
        self.assertEqual(tr.leer_registro()[-1]["tipo"], "rechazada")

    def test_proceso_de_captura_vivo_sin_candado_tampoco(self):
        def vivo(orden, **_):
            salida = "123 python3 archivar_v2.py --ejecucion V2-X" if "sensor1" in orden else ""
            return subprocess.CompletedProcess(orden, 0, salida, "")
        libre, motivo = tr.estado(ejecutar=vivo)
        self.assertFalse(libre)
        self.assertIn("sensor1", motivo)

    def test_equipo_sin_respuesta_no_se_da_por_libre(self):
        libre, _ = tr.estado(ejecutar=lambda o, **_: subprocess.CompletedProcess(o, 255, "", ""))
        self.assertFalse(libre)

    def test_libre_copia_y_registra_inicio_y_fin(self):
        self.assertEqual(tr.copiar(["a", "b"], ejecutar=self.scp), 0)
        self.assertEqual(len(self.copias), 1)
        self.assertEqual([x["tipo"] for x in tr.leer_registro()], ["inicio", "fin"])

    def test_candado_espera_la_holgura_tras_la_ultima_copia(self):
        reloj = [1000.0]
        orig = tr.ahora
        tr.ahora = lambda: reloj[0]
        self.addCleanup(lambda: setattr(tr, "ahora", orig))
        tr.registrar(tipo="inicio", inicio_epoch=990.0, pid=1)
        tr.registrar(tipo="fin", inicio_epoch=990.0, fin_epoch=995.0, pid=1)
        esperas = []
        def dormir(s):
            esperas.append(s)
            reloj[0] += s
        self.assertEqual(tr.crear_candado("V2-X", holgura=60, dormir=dormir), tr.LIBRE)
        self.assertGreaterEqual(reloj[0], 1055.0)
        self.assertTrue(esperas)

    def test_copia_sin_fin_impide_arrancar(self):
        reloj = [1000.0]
        orig = tr.ahora
        tr.ahora = lambda: reloj[0]
        self.addCleanup(lambda: setattr(tr, "ahora", orig))
        tr.registrar(tipo="inicio", inicio_epoch=999.0, pid=7)        # copia en curso (sin fin)
        def dormir(s):
            reloj[0] += s
        self.assertEqual(tr.crear_candado("V2-X", holgura=60, dormir=dormir, espera_max_s=30), tr.OCUPADO)
        self.assertFalse(tr.CANDADO.exists())

    def test_segundo_candado_rechazado_y_quitar_solo_el_propio(self):
        self.assertEqual(tr.crear_candado("V2-A", holgura=0), tr.LIBRE)
        self.assertEqual(tr.crear_candado("V2-B", holgura=0), tr.OCUPADO)
        self.assertEqual(tr.quitar_candado("V2-B"), tr.OCUPADO)
        self.assertTrue(tr.CANDADO.exists())
        self.assertEqual(tr.quitar_candado("V2-A"), tr.LIBRE)
        self.assertFalse(tr.CANDADO.exists())

    def test_solapes_con_el_intervalo_de_captura(self):
        reg = [dict(tipo="inicio", inicio_epoch=100, pid=1), dict(tipo="fin", inicio_epoch=100, fin_epoch=105, pid=1),
               dict(tipo="inicio", inicio_epoch=300, pid=2), dict(tipo="fin", inicio_epoch=300, fin_epoch=303, pid=2),
               dict(tipo="inicio", inicio_epoch=500, pid=3)]
        self.assertEqual(tr.solapes(200, 400, reg)["estado"], "copias_durante_captura")
        self.assertEqual(len(tr.solapes(200, 400, reg)["copias_en_captura"]), 1)
        self.assertEqual(tr.solapes(110, 290, reg)["estado"], "sin_copias")
        # una copia abierta (sin fin) toca cualquier intervalo posterior a su inicio
        self.assertEqual(tr.solapes(600, 700, reg)["estado"], "copias_durante_captura")

    def test_externa_registra_antes_de_copiar(self):
        orig = tr.estado
        tr.estado = lambda ejecutar=None: orig(ejecutar=sin_procesos)
        self.addCleanup(lambda: setattr(tr, "estado", orig))
        rc, token = tr.externa_inicio("portatil")
        self.assertEqual(rc, tr.LIBRE)
        ident, inicio = token.split()
        self.assertEqual(tr.ultima_copia_fin(tr.leer_registro()) is not None, True)
        tr.externa_fin(ident, float(inicio), 0)
        self.assertEqual([x["tipo"] for x in tr.leer_registro()], ["inicio", "fin"])


def args(**k):
    base = dict(ejecucion="V2-X", salida=None, pid=None, generador_desde=100, generador_hasta=1000,
                hasta_epoch=2000, cada_s=20, minimo_gb_srvdmz=1.0, minimo_gb_dc1=1.0,
                sin_progreso_s=180, sin_lectura_s=90, inicio=0)
    base.update(k)
    return SimpleNamespace(**base)


class Vigilancia(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.salida = Path(self.t.name) / "referencias.jsonl"
        self.reloj = [0.0]
        self.estado = {"srvdmz": dict(vivo=True, bytes=0, libre=10e9), "dc1": dict(vivo=True, bytes=0, libre=30e9)}
        self.paradas = []

    def ejecutor(self, host, orden, timeout=25):
        eq = "srvdmz" if host == "srvdmz" else "dc1"
        if "pkill -INT" in orden or "systemctl stop" in orden:
            self.paradas.append(eq)
            self.estado[eq]["vivo"] = False
            return 0, ""
        s = self.estado[eq]
        if s.get("caido"):
            return 255, ""
        if eq == "srvdmz":
            return 0, "%s\n%d\n%d\n" % ("vivo" if s["vivo"] else "muerto", s["bytes"], s["libre"])
        return 0, "%s\n%d\n%d\n%d\n" % ("active" if s["vivo"] else "inactive", s["bytes"], 100, s["libre"])

    def vig(self, **k):
        return vr.Vigilante(args(salida=str(self.salida), pid=str(Path(self.t.name) / "p"), **k),
                            ejecutor=self.ejecutor, reloj=lambda: self.reloj[0], dormir=lambda s: None)

    def correr(self, v, hasta, crece=True):
        while self.reloj[0] <= hasta:
            if crece:
                for s in self.estado.values():
                    s["bytes"] += 1000
            v.paso()
            self.reloj[0] += 20

    def registro(self):
        return [json.loads(x) for x in self.salida.read_text(encoding="utf-8").splitlines()]

    def cerrar(self, v):
        v.escribir(tipo="inicio")
        self.correr(v, 1100)
        v.escribir(tipo="fin", motivo="parado_por_cierre")
        return vr.analizar(self.registro())

    def test_todo_bien_completo(self):
        r = self.cerrar(self.vig())
        self.assertEqual(r["estado"], "completo", r["motivos"])

    def test_proceso_caido(self):
        v = self.vig()
        v.escribir(tipo="inicio")
        self.correr(v, 400)
        self.estado["srvdmz"]["vivo"] = False
        self.correr(v, 1100)
        v.escribir(tipo="fin", motivo="parado_por_cierre")
        r = vr.analizar(self.registro())
        self.assertEqual(r["estado"], "incompleta")
        self.assertIn("srvdmz:proceso_caido", r["motivos"])

    def test_sin_progreso_durante_la_generacion(self):
        v = self.vig()
        v.escribir(tipo="inicio")
        self.correr(v, 300)
        self.correr(v, 900, crece=False)
        v.escribir(tipo="fin", motivo="parado_por_cierre")
        r = vr.analizar(self.registro())
        self.assertIn("srvdmz:sin_progreso", r["motivos"])
        self.assertIn("dc1:sin_progreso", r["motivos"])

    def test_sin_crecer_fuera_de_la_generacion_no_es_incidente(self):
        v = self.vig(generador_desde=0, generador_hasta=200)
        v.escribir(tipo="inicio")
        self.correr(v, 200)
        self.correr(v, 1100, crece=False)
        v.escribir(tipo="fin", motivo="parado_por_cierre")
        self.assertEqual(vr.analizar(self.registro())["estado"], "completo")

    def test_espacio_bajo_parada_coordinada_y_declarada(self):
        v = self.vig()
        v.escribir(tipo="inicio")
        self.correr(v, 400)
        self.estado["dc1"]["libre"] = 0.5e9
        self.correr(v, 1100)
        v.escribir(tipo="fin", motivo="parado_por_cierre")
        r = vr.analizar(self.registro())
        self.assertEqual(self.paradas, ["dc1"])
        self.assertEqual(r["estado"], "incompleta")
        self.assertIn("dc1:espacio_bajo", r["motivos"])
        self.assertNotIn("dc1:proceso_caido", r["motivos"])     # parada propia, no caída

    def test_equipo_sin_lectura(self):
        v = self.vig()
        v.escribir(tipo="inicio")
        self.correr(v, 300)
        self.estado["srvdmz"]["caido"] = True
        self.correr(v, 1100)
        v.escribir(tipo="fin", motivo="parado_por_cierre")
        self.assertIn("srvdmz:sin_supervision", vr.analizar(self.registro())["motivos"])

    def test_sin_registro_no_es_completo(self):
        self.assertEqual(vr.analizar([])["estado"], "sin_datos")
        self.assertEqual(vr.analizar([{"tipo": "inicio"}])["estado"], "incompleta")


class Dictamen(unittest.TestCase):
    """Con lanzamiento que declara vigilancia y coordinación, su evidencia es obligatoria."""

    def preparar(self, refs=None, transfer=None, declarar=True):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        p = Path(t.name) / "pruebas" / "V2-X"
        e = p / "registros"
        e.mkdir(parents=True)
        lz = {"duracion_s": 1440}
        if declarar:
            lz.update(vigilancia_referencias={}, coordinacion_transferencias={})
        (e / "lanzamiento.json").write_text(json.dumps(lz))
        if refs is not None:
            (e / "calidad-referencias.json").write_text(json.dumps(refs))
        if transfer is not None:
            (e / "transferencias.json").write_text(json.dumps(transfer))
        return eg.evaluar("V2-X", p, None, Path(t.name) / "capturas" / "V2-X")

    def test_declarado_y_ausente_es_falta(self):
        r = self.preparar()
        self.assertIn("falta:referencias", r["motivos"])
        self.assertIn("falta:transferencias", r["motivos"])

    def test_referencia_incompleta_es_falta_no_aprobada(self):
        r = self.preparar(refs={"estado": "incompleta"}, transfer={"registro_existe": True, "estado": "sin_copias"})
        self.assertIn("falta:referencias", r["motivos"])
        self.assertEqual(r["transferencias"], "sin_copias")

    def test_copia_durante_la_captura_no_aprueba(self):
        r = self.preparar(refs={"estado": "completo"},
                          transfer={"registro_existe": True, "estado": "copias_durante_captura"})
        self.assertIn("transferencias:copias_durante_captura", r["motivos"])
        self.assertEqual(r["global"], "no_aprobada")

    def test_ejecuciones_antiguas_no_lo_exigen(self):
        r = self.preparar(declarar=False)
        self.assertNotIn("referencias", r)
        self.assertNotIn("falta:referencias", r["motivos"])


class Guiones(unittest.TestCase):
    def test_lanzar_crea_candado_antes_de_todo_y_lo_quita_al_deshacer(self):
        t = (RAIZ / "operacion" / "lanzar_v2.sh").read_text(encoding="utf-8")
        crear = t.index("transferir.py\" candado crear")
        self.assertLess(crear, t.index("exclusion_v1.py --desde"))
        self.assertLess(crear, t.index("tcpdump -i ens35"))
        d = t.index("deshacer() {")
        cuerpo = t[d:t.index("exit 1; }", d)]
        self.assertIn("candado quitar", cuerpo)
        self.assertIn("referencias.pid", cuerpo)
        self.assertLess(t.index("archivar_v2.py --ejecucion"), t.index("vigilar_referencias.py\" vigilar"))
        self.assertLess(t.index("vigilar_referencias.py\" vigilar"), t.index("v2ctl.py iniciar"))
        self.assertIn('"vigilancia_referencias"', t)
        self.assertIn('"coordinacion_transferencias"', t)

    def test_cerrar_para_la_vigilancia_antes_que_las_referencias_y_quita_el_candado_despues(self):
        t = (RAIZ / "operacion" / "cerrar_v2.sh").read_text(encoding="utf-8")
        vig = t.index('kill -TERM "$(cat "$E/referencias.pid")"')
        self.assertLess(vig, t.index("systemctl stop cf-v2-dns"))
        self.assertLess(vig, t.index("pkill -INT -f '[t]cpdump"))
        quitar = t.index("candado quitar")
        self.assertGreater(quitar, t.index("pkill -INT -f '[t]cpdump"))
        self.assertGreater(quitar, t.index("solapes --desde"))
        self.assertLess(quitar, t.rindex("tar -C \"$E\" -cf - ."))     # antes de reunir (paso 4)
        self.assertIn("revisar_criterios.py", t)
        self.assertTrue(re.search(r"for h in srvdmz dcadmin@10.10.10.20 sensor1 clientes", t))


if __name__ == "__main__":
    unittest.main()
