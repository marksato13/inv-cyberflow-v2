"""Pruebas sin red del programa y del generador V2 (reloj y acciones simulados)."""
from __future__ import annotations

import copy
import json
import shutil
import sys
import uuid
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "generador"))
sys.path.insert(0, str(RAIZ / "programas"))

import clientes_lab_v2 as gen  # noqa: E402
import generar_programas as gp  # noqa: E402
import programa as prg  # noqa: E402
import transacciones as tx  # noqa: E402


class RelojFalso:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def dormir(self, s):
        self.t += s


def correr(prog, perfil, ejec=None, parar_en=None):
    reloj = RelojFalso()
    d = RAIZ / "tests" / ("temporal-" + uuid.uuid4().hex)
    d.mkdir(mode=0o777)

    def ejecutar(accion, reg):
        reloj.t += 0.2  # cada acción tarda 0,2 s simulados
        if accion == "dns":
            reg.update(dns_rcode=0, dns_respuestas=["10.10.30.10"], dns_id_coincide=True)
        elif accion == "dns_inexistente":
            reg.update(dns_rcode=3, dns_respuestas=[], dns_id_coincide=True)
        elif accion == "ping":
            reg["icmp_rc"] = 0
        elif accion == "puerto_cerrado":
            reg["cerrado_como"] = "rst"
        elif accion == "abandono":
            reg.update(http_codigo=200, cortada_por_cliente=True)
        else:
            reg["http_codigo"] = next(iter(tx.ESPERADO[accion][1]))
        if parar_en is not None and reloj.t - 1000.0 >= parar_en:
            g.parar = True
            g.motivo_parada = "SIGTERM"

    g = gen.Generador(prog, "sha-prueba", perfil, gp.ORIGEN[perfil], ejec or "E-TEST", d,
                      reloj=reloj, dormir=reloj.dormir, ejecutar=ejecutar)
    estado = g.correr()
    txs = [json.loads(x) for x in (d / ("transacciones-%s.jsonl" % perfil)).read_text(encoding="utf-8").splitlines()]
    evs = [json.loads(x) for x in (d / ("eventos-%s.jsonl" % perfil)).read_text(encoding="utf-8").splitlines()]
    shutil.rmtree(d)
    return estado, txs, evs


class TestProgramas(unittest.TestCase):
    def test_todos_validos_y_contiguos(self):
        for k, p in gp.todas().items():
            prg.validar(p)
            if k.startswith("J"):
                self.assertEqual(p["duracion_s"], 21600, k)
                self.assertEqual([b["particion"] for b in p["bloques"]][0], "entrenamiento")

    def test_presupuesto_nominal_24_9_9(self):
        horas = {}
        for k, p in gp.todas().items():
            if k.startswith("J"):
                for b in p["bloques"]:
                    horas[b["particion"]] = horas.get(b["particion"], 0) + (b["fin_s"] - b["inicio_s"]) / 3600
        self.assertEqual(horas, {"entrenamiento": 24, "calibracion": 9, "desarrollo": 9})

    def test_semillas_unicas_entre_jornadas(self):
        todas = [s for p in gp.todas().values() for b in p["bloques"] for s in b["semillas"].values()]
        self.assertEqual(len(todas), len(set(todas)))

    def test_hueco_y_solape_rechazados(self):
        p = gp.todas()["J1"]
        q = copy.deepcopy(p)
        q["fases"][1]["inicio_s"] += 1
        with self.assertRaises(prg.ProgramaInvalido):
            prg.validar(q)
        q = copy.deepcopy(p)
        q["fases"][1]["inicio_s"] -= 1
        with self.assertRaises(prg.ProgramaInvalido):
            prg.validar(q)

    def test_accion_desconocida_rechazada(self):
        q = copy.deepcopy(gp.todas()["J1"])
        q["perfiles"]["ligero"]["acciones"]["exfiltrar"] = 1
        with self.assertRaises(prg.ProgramaInvalido):
            prg.validar(q)

    def test_factor_por_tiempo_transcurrido(self):
        p = gp.todas()["J4"]
        self.assertEqual(prg.factor(p, "ofimatica", 10)[0], 1.0)
        self.assertEqual(prg.factor(p, "ofimatica", 3600 + 10)[0], 0.55)
        f, fase, pulsos = prg.factor(p, "ofimatica", 3300 + 1)
        self.assertEqual((f, pulsos), (1.5, ["P1"]))
        self.assertEqual(prg.factor(p, "descargas", 3300 + 1)[0], 1.0)
        p6 = gp.todas()["J6"]
        self.assertAlmostEqual(prg.factor(p6, "ligero", 100)[0], 0.30)
        self.assertAlmostEqual(prg.factor(p6, "ligero", 1800 + 10)[0], 1.0, places=5)

    def test_regenerar_es_identico(self):
        for k, p in gp.todas().items():
            nombre = {"P0": "piloto-30min.json", "PRUEBA-CORTA": "prueba-corta.json"}.get(k, "jornada-%s.json" % k)
            ruta = RAIZ / "programas" / nombre
            if ruta.exists():
                self.assertEqual(ruta.read_bytes(), gp.serializar(p), nombre)


class TestGenerador(unittest.TestCase):
    def test_duracion_finita_y_registro_completo(self):
        prog = gp.todas()["PRUEBA-CORTA"]
        estado, txs, evs = correr(prog, "navegacion")
        self.assertEqual(estado, "completa")
        self.assertEqual(evs[0]["tipo"], "inicio")
        self.assertEqual(evs[-1]["tipo"], "fin")
        self.assertEqual(evs[-1]["transacciones"], len(txs))
        self.assertTrue(all(t["inicio_t_s"] < 240 for t in txs))
        ids = [t["transaccion_id"] for t in txs]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(t["clase"] in ("ok", "error_intencional") for t in txs))

    def test_pausa_sin_acciones(self):
        prog = gp.todas()["PRUEBA-CORTA"]
        _, txs, evs = correr(prog, "ofimatica")
        self.assertFalse([t for t in txs if 60 <= t["inicio_t_s"] < 90])
        self.assertIn("pausa", [e["tipo"] for e in evs])

    def test_cambio_de_bloque_resiembra(self):
        prog = gp.todas()["PRUEBA-CORTA"]
        _, txs, evs = correr(prog, "ofimatica")
        bl = [e for e in evs if e["tipo"] == "bloque"]
        self.assertEqual([b["bloque_id"] for b in bl], ["B1", "B2"])
        self.assertEqual(bl[1]["semilla"], prog["bloques"][1]["semillas"]["ofimatica"])

    def test_reproducible_con_misma_semilla(self):
        prog = gp.todas()["PRUEBA-CORTA"]
        _, a, _ = correr(prog, "aplicacion", "E1")
        _, b, _ = correr(prog, "aplicacion", "E2")
        self.assertEqual([(t["accion"], t["espera_previa_s"]) for t in a], [(t["accion"], t["espera_previa_s"]) for t in b])

    def test_parada_controlada_conserva_ultimo_registro(self):
        prog = gp.todas()["PRUEBA-CORTA"]
        estado, txs, evs = correr(prog, "navegacion", parar_en=30)
        self.assertEqual(estado, "interrumpida")
        self.assertEqual(evs[-1]["motivo"], "SIGTERM")
        self.assertEqual(evs[-1]["transacciones"], len(txs))
        self.assertGreater(len(txs), 0)

    def test_espera_no_cruza_cambio_de_fase(self):
        prog = gp.todas()["PRUEBA-CORTA"]
        _, txs, _ = correr(prog, "ligero")  # ritmo 12 s: esperas largas
        for t in txs:
            fase = prg.tramo_en(prog["fases"], t["inicio_t_s"])
            self.assertEqual(fase["id"], t["fase_id"])

    def test_piso_de_005_sobre_la_media(self):
        import random
        r = random.Random(1)
        media = max(1.5 / 100.0, 0.05)
        muestras = [r.expovariate(1 / media) for _ in range(20000)]
        self.assertLess(min(muestras), 0.05)  # el piso no se aplica a cada espera
        self.assertAlmostEqual(sum(muestras) / len(muestras), 0.05, delta=0.003)


class TestTLSCierre(unittest.TestCase):
    """T11 (intento 2): srv-dmz cierra TLS sin close_notify; V1 lo trataba como fin de datos."""

    def _tls(self, exc):
        import ssl
        t = tx.TLSMedido.__new__(tx.TLSMedido)
        t.cierre = None

        def hacer(_op):
            raise exc
        t._hacer = hacer
        return t

    def test_eof_abrupto_es_fin_de_datos(self):
        import ssl
        t = self._tls(ssl.SSLEOFError())
        self.assertEqual(t.recv(10), b"")
        self.assertEqual(t.cierre, "sin_close_notify")

    def test_close_notify_es_fin_de_datos(self):
        import ssl
        t = self._tls(ssl.SSLZeroReturnError())
        self.assertEqual(t.recv(10), b"")
        self.assertEqual(t.cierre, "close_notify")


class TestClasificacion(unittest.TestCase):
    D = gp.DESTINOS

    def test_dns_noerror_sin_ip_esperada_es_fallo(self):
        r = {"dns_rcode": 0, "dns_respuestas": ["1.2.3.4"], "dns_id_coincide": True}
        tx.clasificar("dns", r, self.D)
        self.assertEqual(r["clase"], "fallo_inesperado")

    def test_nxdomain_intencional(self):
        r = {"dns_rcode": 3, "dns_respuestas": [], "dns_id_coincide": True}
        tx.clasificar("dns_inexistente", r, self.D)
        self.assertEqual(r["clase"], "error_intencional")

    def test_inexistente_con_noerror_es_fallo(self):
        r = {"dns_rcode": 0, "dns_respuestas": ["10.10.30.10"], "dns_id_coincide": True}
        tx.clasificar("dns_inexistente", r, self.D)
        self.assertEqual(r["clase"], "fallo_inesperado")

    def test_post_500_es_variacion_del_servidor(self):
        r = {"http_codigo": 500}
        tx.clasificar("api_post", r, self.D)
        self.assertEqual(r["clase"], "variacion_servidor")

    def test_timeout_es_fallo(self):
        r = {"timeout": True, "excepcion": "TimeoutError: timed out"}
        tx.clasificar("web_grande", r, self.D)
        self.assertEqual(r["clase"], "fallo_inesperado")

    def test_puerto_abierto_es_fallo(self):
        r = {"cerrado_como": "abierto"}
        tx.clasificar("puerto_cerrado", r, self.D)
        self.assertEqual(r["clase"], "fallo_inesperado")

    def test_corte_por_parada_es_no_verificable(self):
        r = {"excepcion": "ConnectionResetError: reset", "parada_durante_accion": True}
        tx.clasificar("web_grande", r, self.D)
        self.assertEqual(r["clase"], "incompleta_no_verificable")

    def test_parada_no_tapa_un_exito(self):
        r = {"http_codigo": 200, "parada_durante_accion": True}
        tx.clasificar("web_grande", r, self.D)
        self.assertEqual(r["clase"], "ok")


if __name__ == "__main__":
    unittest.main()
