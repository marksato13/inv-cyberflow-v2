"""kernel_drops de Suricata (revisiones 5 y 6): estados, suficiencia temporal, conciliación con C7,
antigüedad en el vigía y dictamen global."""
from __future__ import annotations

import datetime as dt
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
import estado_global as eg  # noqa: E402
import revisar_criterios as rc  # noqa: E402
import suricata_stats as ss  # noqa: E402
import vigia_v2 as vg  # noqa: E402

T0 = dt.datetime(2026, 11, 26, 9, 0, 0, tzinfo=dt.timezone.utc).timestamp()


def iso(seg):
    return dt.datetime.fromtimestamp(T0 + seg, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def stats(seg, kp, kd="nada", uptime=None):
    cap = {"kernel_packets": kp, "errors": 0}
    if kd != "nada":
        cap["kernel_drops"] = kd
    return {"timestamp": iso(seg), "event_type": "stats",
            "stats": {"uptime": 1000 + seg if uptime is None else uptime, "capture": cap}}


def serie(n, kd=lambda i: 0, paso=8, desde=0):
    return [stats(desde + i * paso, 100 + i * 10, kd(i)) for i in range(n)]


# periodo [T0+4, T0+4+8*k]: lo acotan las muestras 0 y k+1 de una serie cada 8 s
def periodo(k):
    return T0 + 4, T0 + 4 + 8 * k


class Suficiencia(unittest.TestCase):
    def test_periodo_acotado_con_cero_es_presente(self):
        r = ss.evaluar(serie(5), *periodo(3))
        self.assertEqual((r["estado"], r["delta_kernel_drops"]), ("presente", 0))
        self.assertEqual(r["eventos_usados"], 5)

    def test_una_sola_muestra_no_certifica(self):
        r = ss.evaluar([stats(0, 100, 0)], T0, T0)
        self.assertEqual(r["estado"], "insuficiente")
        self.assertIsNone(r["delta_kernel_drops"])
        r = ss.evaluar([stats(10, 100, 0)], T0, T0 + 20)
        self.assertEqual(r["estado"], "insuficiente")

    def test_solo_muestras_interiores_no_certifican_los_bordes(self):
        r = ss.evaluar(serie(5, desde=8), T0 + 4, T0 + 44)     # ninguna en o antes del inicio
        self.assertEqual((r["estado"], r["motivo"]), ("insuficiente", "sin muestra en o antes del inicio"))
        r = ss.evaluar(serie(5), T0 + 4, T0 + 40)               # ninguna en o después del fin
        self.assertEqual((r["estado"], r["motivo"]), ("insuficiente", "sin muestra en o después del fin"))
        self.assertIsNone(r["delta_kernel_drops"])

    def test_hueco_mayor_de_16_s_no_certifica_aunque_el_contador_sea_cero(self):
        ev = serie(3) + [stats(16 + 17, 140, 0)]
        r = ss.evaluar(ev, T0 + 4, T0 + 30)
        self.assertEqual(r["estado"], "insuficiente")
        self.assertIn("huecos", r["motivo"])
        self.assertIsNone(r["delta_kernel_drops"])

    def test_sin_periodo_no_certifica(self):
        self.assertEqual(ss.evaluar(serie(5))["estado"], "insuficiente")

    def test_ausente_y_sin_eventos(self):
        self.assertEqual(ss.evaluar(serie(2) + [stats(16, 130)], *periodo(1))["estado"], "ausente")
        self.assertEqual(ss.evaluar([], *periodo(1))["estado"], "sin_eventos")

    def test_reinicio_por_uptime_discontinuo_aunque_no_retroceda(self):
        ev = serie(3) + [stats(24, 140, 0, uptime=1000 + 24 + 30)]
        self.assertEqual(ss.evaluar(ev, *periodo(2))["estado"], "reinicio")

    def test_reinicio_es_fallo_y_cuenta_lo_que_localiza(self):
        # [0,8] y [16,24] cruzan los bordes de [4,20]: sus aumentos (2 y 4) solo se localizan fuera
        ev = [stats(0, 100, 1), stats(8, 120, 3), stats(16, 2, 0, uptime=5), stats(24, 9, 4, uptime=13)]
        r = ss.evaluar(ev, *periodo(2))
        self.assertEqual((r["estado"], r["delta_kernel_drops_ampliado"]), ("reinicio", 2 + 4))

    def test_ventana_toma_la_eve_completa_con_margen(self):
        with tempfile.TemporaryDirectory() as t:
            eve = Path(t) / "eve.json"
            filas = serie(20) + [{"event_type": "flow", "src_ip": "10.10.20.21"}]
            eve.write_text("".join(json.dumps(x) + "\n" for x in filas) + '{"event_type":"stats", cortado')
            r = ss.ventana([eve], T0 + 44, T0 + 84, 10, Path(t) / "v.jsonl")
            self.assertEqual(r["evaluacion"]["estado"], "presente")
            self.assertEqual(r["eventos"], 7)                 # 40, 48 … 88 s dentro de [34, 94]
            self.assertNotIn("10.10.20.21", (Path(t) / "v.jsonl").read_text())


class C9(unittest.TestCase):
    def ejecucion(self, filas, inicio_s=4, fin_s=28, en_ventana=False):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        CAP = Path(t.name) / "capturas" / "V2-X"
        P = Path(t.name) / "pruebas" / "V2-X"
        (CAP / "eve").mkdir(parents=True)
        (P / "registros").mkdir(parents=True)
        (CAP / "manifiesto.json").write_text(json.dumps({"inicio": iso(inicio_s).replace("+0000", "Z"),
                                                         "fin": iso(fin_s).replace("+0000", "Z")}))
        dentro = [x for x in filas if inicio_s < ss.epoch(x["timestamp"]) - T0 < fin_s]
        (CAP / "eve" / "eve-V2-X.json").write_text("".join(json.dumps(x) + "\n" for x in dentro))
        if en_ventana:
            (P / "registros" / "suricata-stats-ventana-V2-X.jsonl").write_text("".join(json.dumps(x) + "\n" for x in filas))
        return CAP, P

    def test_recorte_interior_solo_es_insuficiente_y_la_ventana_lo_acota(self):
        CAP, P = self.ejecucion(serie(5))
        self.assertIsNone(rc.suricata(CAP, True, P)["ok"])
        CAP, P = self.ejecucion(serie(5), en_ventana=True)
        x = rc.suricata(CAP, True, P)
        self.assertIs(x["ok"], True)
        self.assertEqual(x["valor"]["eventos_usados"], 5)

    def test_descartes_nuevos_con_c7_verdadero_son_fallo(self):
        CAP, P = self.ejecucion(serie(5, kd=lambda i: 0 if i < 2 else 3), en_ventana=True)
        x = rc.suricata(CAP, True, P)
        self.assertIs(x["ok"], False)                    # C7 True no lo convierte en aprobado
        self.assertIn("no lo decide C7", x["nota"])

    def dictamen(self, CAP, P, x):
        (P / "registros" / "lanzamiento.json").write_text(json.dumps({"duracion_s": 1440}))
        crit = {k: {"ok": True} for k in [f"C{i}" for i in range(1, 14)] + ["C11b"]}
        for k in ("C7", "C9", "C10", "C11", "C12", "C13"):
            crit[k] = {"ok": None, "revisar": True}
        (P / "criterios.json").write_text(json.dumps(crit))
        rev = {k: {"ok": True} for k in ("C7", "C10", "C11", "C12", "C13")}
        rev["C9"] = rc.criterio([x])
        (P / "criterios-revisados.json").write_text(json.dumps({"criterios": rev}))
        return eg.evaluar("V2-X", P, None, CAP)

    def test_perdida_con_hueco_de_24_s_es_fallo_y_manda_sobre_la_falta(self):
        # periodo de 24 s, muestras justo en sus extremos, kernel_drops 0 -> 3: el hueco impide
        # certificar 0, pero no anula la pérdida demostrada dentro del periodo
        CAP, P = self.ejecucion([stats(0, 100, 0), stats(24, 200, 3)], inicio_s=0, fin_s=24, en_ventana=True)
        x = rc.suricata(CAP, True, P)
        self.assertIs(x["ok"], False)
        v = x["valor"]
        self.assertEqual((v["estado"], v["delta_kernel_drops_atribuible"], v["delta_kernel_drops_ampliado"]), ("perdida", 3, 0))
        self.assertIn("huecos mayores de 16 s", v["falta_evidencia"])
        g = self.dictamen(CAP, P, x)
        self.assertIn("criterio:C9", g["motivos"])
        self.assertEqual(g["global"], "no_aprobada")

    def test_perdida_solo_en_el_intervalo_ampliado_no_se_atribuye_ni_se_aprueba(self):
        # muestras 4 s antes y 4 s después del periodo [0,24]: el aumento puede estar fuera
        CAP, P = self.ejecucion([stats(-4, 100, 0, uptime=996), stats(28, 200, 3, uptime=1028)],
                                inicio_s=0, fin_s=24, en_ventana=True)
        x = rc.suricata(CAP, True, P)
        self.assertIsNone(x["ok"])
        v = x["valor"]
        self.assertEqual((v["estado"], v["delta_kernel_drops_atribuible"], v["delta_kernel_drops_ampliado"]),
                         ("perdida_no_localizada", 0, 3))
        self.assertEqual(v["intervalos_con_perdida"][0]["clase"], "ampliado")
        g = self.dictamen(CAP, P, x)
        # C9 entra como falta de evidencia, no como fallo (el archivador de esta ejecución mínima
        # falla por sí mismo; el dictamen completo se comprueba en test_dictamen_global_*)
        self.assertIn("falta:criterio:C9", g["motivos"])
        self.assertNotIn("criterio:C9", g["motivos"])

    def test_distingue_atribuible_y_ampliado_en_la_misma_serie(self):
        # [4,28]: +1 en [0,8] (borde), +2 en [16,24] (dentro), +5 en [24,32] (borde)
        kd = [0, 1, 1, 3, 8]
        CAP, P = self.ejecucion(serie(5, kd=lambda i: kd[i]), en_ventana=True)
        v = rc.suricata(CAP, True, P)["valor"]
        self.assertEqual((v["estado"], v["delta_kernel_drops_atribuible"], v["delta_kernel_drops_ampliado"]), ("perdida", 2, 6))

    def test_sin_uptime_no_certifica_cero(self):
        sin = lambda s, kp, kd: {"timestamp": iso(s), "event_type": "stats",
                                 "stats": {"capture": {"kernel_packets": kp, "kernel_drops": kd}}}
        CAP, P = self.ejecucion([sin(0, 100, 0), sin(8, 110, 0), sin(16, 120, 0), sin(24, 130, 0), sin(32, 140, 0)], en_ventana=True)
        x = rc.suricata(CAP, True, P)
        self.assertIsNone(x["ok"])
        self.assertEqual(x["valor"]["estado"], "insuficiente")
        self.assertIn("continuidad no verificable", x["valor"]["motivo"])
        # pero un aumento sin uptime sigue siendo pérdida demostrada
        CAP, P = self.ejecucion([sin(0, 100, 0), sin(8, 110, 0), sin(16, 120, 2), sin(24, 130, 2), sin(32, 140, 2)], en_ventana=True)
        self.assertIs(rc.suricata(CAP, True, P)["ok"], False)

    def test_dos_muestras_sin_uptime_que_acotan_no_aprueban(self):
        sin = lambda s: {"timestamp": iso(s), "event_type": "stats",
                         "stats": {"capture": {"kernel_packets": 100 + s, "kernel_drops": 0}}}
        r = ss.evaluar([sin(0), sin(8)], T0 + 2, T0 + 6)
        self.assertEqual(r["estado"], "insuficiente")
        self.assertIsNone(r["delta_kernel_drops"])

    def test_una_muestra_sin_uptime_basta_para_no_certificar(self):
        filas = serie(5)
        del filas[2]["stats"]["uptime"]
        CAP, P = self.ejecucion(filas, en_ventana=True)
        self.assertIsNone(rc.suricata(CAP, True, P)["ok"])

    def test_incremento_tras_la_ultima_supervision_lo_detecta_c9_y_el_dictamen(self):
        # las supervisiones periódicas vieron 0; el descarte llega después, entre dos muestras del periodo
        filas = serie(5, kd=lambda i: 0 if i < 3 else 1)          # [16,24] dentro de [4,28]
        CAP, P = self.ejecucion(filas, en_ventana=True)
        x = rc.suricata(CAP, True, P)
        self.assertIs(x["ok"], False)
        self.assertEqual(x["valor"]["delta_kernel_drops"], 1)
        g = self.dictamen(CAP, P, x)
        self.assertIn("criterio:C9", g["motivos"])
        self.assertEqual(g["global"], "no_aprobada")

    def test_publicado_aparte_y_ventana_no_se_duplican(self):
        filas = serie(5)
        CAP, P = self.ejecucion(filas, en_ventana=True)
        (CAP / "eve" / "suricata-stats-V2-X.jsonl").write_text("".join(json.dumps(x) + "\n" for x in filas))
        self.assertEqual(rc.suricata(CAP, True, P)["valor"]["eventos"], 5)


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
        self.assertEqual(vg.leer_stats(json.dumps(stats(0, 1, 0)))["kernel_drops_estado"], "presente")
        r = vg.leer_stats(json.dumps(stats(0, 1)))
        self.assertEqual((r["kernel_drops_estado"], r["kernel_drops"]), ("ausente", None))
        self.assertEqual(vg.leer_stats("")["kernel_drops_estado"], "sin_stats")

    def correr(self, lecturas, retraso=2.0, fallo_eve_en=()):
        reloj, i = [0.0], [0]
        def comando(orden):
            if orden[1] == "sensor1" and orden[2].startswith("cat "):
                return json.dumps({"estado": "ok", "utc": "2026-11-26T09:00:00Z", "libre_gb": 10})
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
            i[0], reloj[0] = k, ss.epoch(lecturas[k]["timestamp"]) + retraso
            v.supervision({"libre_gb": 10, "eve_huecos": 0, "pcap_huecos": 0})
        sup = [json.loads(x) for x in (self.tmp / "supervision.jsonl").read_text().splitlines()]
        f = self.tmp / "invalidaciones.jsonl"
        inv = [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
        return sup, inv

    def test_reinicio_invalida_y_rehace_la_base(self):
        # 10 drops antes del reinicio; tras él, 0 -> 3: sin rehacer la base, 3 < 10 quedaría oculto
        sup, inv = self.correr([stats(0, 50, 10, uptime=500), stats(8, 5, 0, uptime=4), stats(16, 9, 3, uptime=12)])
        self.assertEqual([x["condicion"] for x in inv], ["reinicio_suricata", "kernel_drops"])
        self.assertTrue(sup[1]["suricata_reinicio"])

    def test_incremento_invalida(self):
        sup, inv = self.correr(serie(3, kd=lambda i: 0 if i < 2 else 2))
        self.assertEqual([x["condicion"] for x in inv], ["kernel_drops"])

    def test_lectura_fallida_no_es_cero(self):
        sup, inv = self.correr(serie(2), fallo_eve_en=(1,))
        self.assertEqual(sup[1]["kernel_drops_estado"], "lectura_fallida")
        self.assertIsNone(sup[1]["kernel_drops"])
        self.assertEqual(inv, [])

    def test_lectura_obsoleta_no_se_usa(self):
        sup, inv = self.correr(serie(2), retraso=ss.ANTIGUEDAD_MAXIMA_S + 5)
        self.assertEqual(sup[0]["kernel_drops_estado"], "obsoleta")
        self.assertIsNone(sup[0]["kernel_drops"])
        self.assertEqual(sup[0]["kernel_drops_leido"], 0)
        sup, _ = self.correr(serie(1), retraso=3)
        self.assertEqual(sup[-1]["kernel_drops_estado"], "presente")
        self.assertLess(sup[-1]["stats_antiguedad_s"], ss.ANTIGUEDAD_MAXIMA_S)

    def test_sin_uptime_no_vale_como_lectura_pero_un_aumento_invalida(self):
        sin = lambda s, kd: {"timestamp": iso(s), "event_type": "stats",
                             "stats": {"capture": {"kernel_packets": 100 + s, "kernel_drops": kd}}}
        sup, inv = self.correr([sin(0, 0), sin(8, 0), sin(16, 4)])
        self.assertEqual([x["kernel_drops_estado"] for x in sup], ["sin_uptime"] * 3)
        self.assertTrue(all(x["kernel_drops"] is None for x in sup))
        self.assertEqual([x["condicion"] for x in inv], ["kernel_drops"])

    def test_uptime_que_salta_hacia_delante_es_reinicio(self):
        sup, inv = self.correr([stats(0, 50, 0), stats(8, 60, 0, uptime=1000 + 8 + 40)])
        self.assertEqual([x["condicion"] for x in inv], ["reinicio_suricata"])

    def test_supervision_obsoleta_deja_el_dictamen_sin_datos(self):
        sup, _ = self.correr(serie(2), retraso=60)
        self.assertTrue(all(x["kernel_drops"] is None for x in sup))


if __name__ == "__main__":
    unittest.main()
