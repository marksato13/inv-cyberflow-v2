"""Conciliación v3 cliente, servidor y DNS, incluida conexión persistente."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "operacion"))
import conciliar_v2 as c

T0 = "2026-11-25T10:00:0%sZ"
BORDES = [{"evento": "arranque", "utc": "2026-11-25T09:00:00Z"},
          {"evento": "fin", "utc": "2026-11-25T11:00:00Z"}]


def tx(accion, **extra):
    t = {"transaccion_id": "X", "perfil": "P2", "accion": accion,
         "origen_ip": "10.10.20.22", "origen_puerto": 40000,
         "inicio_utc": T0 % 1, "fin_utc": T0 % 2, "clase": "ok"}
    t.update(extra)
    return t


def srv(**extra):
    s = {"cliente": "10.10.20.22", "puerto_cliente": 40000,
         "inicio_utc": T0 % 1, "fin_utc": T0 % 2,
         "codigo": 200, "resultado": "completa"}
    s.update(extra)
    return s


class TestConciliar(unittest.TestCase):
    def uno(self, t, http=(), dns=()):
        return c.conciliar([t], list(http) + BORDES, list(dns) + BORDES)["filas"][0]

    def test_obtener_correcto(self):
        self.assertEqual(self.uno(tx("obtener", http_codigo=200), [srv()])["clase"], "correcto")

    def test_codigo_discrepa(self):
        self.assertEqual(self.uno(tx("consulta", http_codigo=200),
                                  [srv(codigo=404)])["motivo"], "codigo_discrepa")

    def test_sin_registro(self):
        self.assertEqual(self.uno(tx("envio", http_codigo=201))["motivo"],
                         "sin_registro_servidor")

    def test_fuera_del_registro(self):
        t = tx("obtener", inicio_utc="2026-11-25T12:00:00Z",
               fin_utc="2026-11-25T12:00:01Z")
        self.assertEqual(self.uno(t)["clase"], "incompleta_no_verificable")

    def test_ambiguo(self):
        self.assertEqual(self.uno(tx("obtener", http_codigo=200),
                                  [srv(), srv()])["clase"], "incompleta_no_verificable")

    def test_parada(self):
        self.assertEqual(self.uno(tx("obtener", clase="incompleta_no_verificable"))["clase"],
                         "incompleta_no_verificable")

    def test_dns(self):
        q = {"utc": T0 % 1, "sentido": "consulta", "cliente": "10.10.20.22",
             "puerto_cliente": 40000, "id": 7}
        resp = dict(q, sentido="respuesta", rcode="NOERROR")
        self.assertEqual(self.uno(tx("dns", dns_id=7, dns_rcode=0),
                                  dns=[q, resp])["clase"], "correcto")

    def test_p2_mismo_puerto_dos_peticiones(self):
        cliente = [tx("obtener", transaccion_id="X1", peticion_en_conexion=1, http_codigo=200),
                   tx("obtener", transaccion_id="X2", peticion_en_conexion=2, http_codigo=200)]
        servidor = [srv(peticion_en_conexion=1), srv(peticion_en_conexion=2)]
        filas = c.conciliar(cliente, servidor + BORDES, BORDES)["filas"]
        self.assertEqual([f["clase"] for f in filas], ["correcto", "correcto"])
        self.assertEqual([f["peticion_en_conexion"] for f in filas], [1, 2])


if __name__ == "__main__":
    unittest.main()
