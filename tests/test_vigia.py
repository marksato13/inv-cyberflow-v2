"""Parada coordinada y hombre muerto con reloj y comandos simulados."""
from __future__ import annotations

import json
import sys
import shutil
import signal
import uuid
import unittest
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "operacion"))
import vigia_v2 as vg  # noqa: E402
import v2ctl  # noqa: E402


class TestVigia(unittest.TestCase):
    def setUp(self):
        self.tmp = RAIZ / "tests" / ("temporal-" + uuid.uuid4().hex)
        self.tmp.mkdir(mode=0o777)
        self.addCleanup(shutil.rmtree, self.tmp)
        self.a = SimpleNamespace(ejecucion="V2-P0-20261125T150000Z", estado_remoto="/captura/estado.json",
                                 permiso_remoto="/ejecuciones/ID/PERMISO_CAPTURA",
                                 v2ctl_remoto="/repo/operacion/v2ctl.py",
                                 registro=str(self.tmp / "vigia.jsonl"),
                                 max_fallos=3, latido_max_s=60, cada=10)
        self.ordenes = []

    def vigia(self, estado=None, fallo=False):
        def comando(orden):
            self.ordenes.append(orden)
            if orden[1] == "sensor1":
                if fallo:
                    raise OSError("ssh caído")
                return json.dumps(estado)
            return ""
        return vg.Vigia(self.a, ejecutor=comando, reloj=lambda: 1000.0, dormir=lambda _: None)

    def paradas(self):
        return [x for x in self.ordenes if x[1] == "clientes" and " parar " in x[2]]

    def test_latido_viejo_para(self):
        v = self.vigia({"estado": "ok", "utc": "1970-01-01T00:15:00Z"})
        self.assertFalse(v.paso())
        self.assertEqual(len(self.paradas()), 1)
        self.assertIn("latido_viejo", self.paradas()[0][2])

    def test_estado_fallo_para(self):
        v = self.vigia({"estado": "fallo", "motivo": "espacio", "utc": "1970-01-01T00:16:40Z"})
        self.assertFalse(v.paso())
        self.assertEqual(len(self.paradas()), 1)
        self.assertFalse(any("touch" in x[2] for x in self.ordenes))

    def test_tres_ssh_caidos_paran(self):
        v = self.vigia(fallo=True)
        self.assertTrue(v.paso())
        self.assertTrue(v.paso())
        self.assertFalse(v.paso())
        self.assertEqual(len(self.paradas()), 1)
        self.assertEqual(len(Path(self.a.registro).read_text().splitlines()), 4)

    def test_permiso_sano_se_renueva(self):
        v = self.vigia({"estado": "ok", "utc": "1970-01-01T00:16:40Z"})
        self.assertTrue(v.paso())
        self.assertTrue(any("touch" in x[2] for x in self.ordenes))

    def test_fin_real_escribe_hasta_y_sigue_hasta_archivador(self):
        self.a.margen_fin_s = 120
        self.a.hasta_remoto = "/captura/HASTA_EPOCH"
        def comando(orden):
            self.ordenes.append(orden)
            if orden[1] == "sensor1" and orden[2].startswith("cat "):
                return json.dumps({"estado": "ok", "utc": "1970-01-01T00:16:40Z"})
            if orden[1] == "clientes" and " estado " in orden[2]:
                return json.dumps({"terminado": True, "fin_utc": "1970-01-01T00:16:30Z",
                                   "estado": "completa"})
            return ""
        v = vg.Vigia(self.a, ejecutor=comando, reloj=lambda: 1000.0)
        self.assertTrue(v.paso())
        escrituras = [o[2] for o in self.ordenes if o[1] == "sensor1" and "HASTA_EPOCH" in o[2]]
        self.assertEqual(len(escrituras), 1)
        self.assertIn("1110.0", escrituras[0])
        self.assertIn("mv", escrituras[0])
        self.assertTrue(v.hasta_escrito)

    def test_enlace_100_para(self):
        def comando(orden):
            self.ordenes.append(orden)
            if orden[1] == "sensor1" and orden[2].startswith("cat "):
                return json.dumps({"estado": "ok", "utc": "1970-01-01T00:16:40Z", "libre_gb": 10})
            if orden[1] == "sw-core-stack":
                return "GigabitEthernet2/0/19 is up, line protocol is up\nFull-duplex, 100Mb/s\n0 output drops"
            return ""
        v = vg.Vigia(self.a, ejecutor=comando, reloj=lambda: 1000.0)
        self.assertFalse(v.paso())
        self.assertIn("enlace_invalido", self.paradas()[0][2])

    def test_drops_crecientes_invalidan_sin_parar(self):
        reloj = [1000.0]
        drops = [0]
        def comando(orden):
            self.ordenes.append(orden)
            if orden[1] == "sensor1" and orden[2].startswith("cat "):
                return json.dumps({"estado": "ok", "utc": "1970-01-01T00:16:40Z", "libre_gb": 10})
            if orden[1] == "sw-core-stack":
                return "GigabitEthernet2/0/19 is up, line protocol is up\nFull-duplex, 1000Mb/s\n%d output drops" % drops[0]
            if orden[2] == "date +%s.%N":
                return str(reloj[0])
            return ""
        self.a.supervision_cada_s = 1
        v = vg.Vigia(self.a, ejecutor=comando, reloj=lambda: reloj[0])
        self.assertTrue(v.paso())
        reloj[0], drops[0] = 1001.0, 2
        self.assertTrue(v.paso())
        invalidaciones = [json.loads(x) for x in (self.tmp / "invalidaciones.jsonl").read_text().splitlines()]
        self.assertEqual(invalidaciones[0]["categoria"], "perdida_antes_sensor")
        self.assertEqual(self.paradas(), [])


class TestHombreMuerto(unittest.TestCase):
    def test_gracia_y_caducidad_con_reloj_inyectado(self):
        d = RAIZ / "tests" / ("temporal-" + uuid.uuid4().hex)
        d.mkdir(mode=0o777)
        try:
            self.assertIsNone(v2ctl.motivo_permiso(d, 100, ahora=lambda: 180,
                                                   max_s=90, gracia_s=120))
            self.assertEqual(v2ctl.motivo_permiso(d, 100, ahora=lambda: 221,
                                                  max_s=90, gracia_s=120), "sin_permiso_captura")
            permiso = d / "PERMISO_CAPTURA"
            permiso.write_text("")
            import os
            os.utime(permiso, (200, 200))
            self.assertIsNone(v2ctl.motivo_permiso(d, 100, ahora=lambda: 289))
            self.assertEqual(v2ctl.motivo_permiso(d, 100, ahora=lambda: 291), "sin_permiso_captura")
            class Hijo:
                def __init__(self):
                    self.senales = []
                def poll(self):
                    return None
                def send_signal(self, senal):
                    self.senales.append(senal)
            hijo = Hijo()
            self.assertEqual(v2ctl.detener_sin_permiso(d, {"perfil": hijo}, 100,
                                                      ahora=lambda: 291), "sin_permiso_captura")
            self.assertEqual(hijo.senales, [signal.SIGTERM])
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()


def test_enlace_span_monitoring_es_valido():
    v = vg
    raw = ("GigabitEthernet2/0/19 is up, line protocol is down (monitoring)\n"
           "  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX\n"
           "  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 215521\n")
    assert v.enlace(raw) == (True, 215521)
    assert v.enlace(raw.replace("1000Mb/s", "100Mb/s"))[0] is False
    assert v.enlace(raw.replace(" (monitoring)", ""))[0] is False
    assert v.enlace(raw.replace("is up,", "is down,"))[0] is False
