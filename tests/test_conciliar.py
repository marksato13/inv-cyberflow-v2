"""Conciliación cliente ↔ servidor: clases y casos límite."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "operacion"))
import conciliar_v2 as c  # noqa: E402

T0 = "2026-11-24T10:00:0%sZ"


def tx(accion, **k):
    base = {"transaccion_id": "X-%s" % accion, "perfil": "contabilidad", "accion": accion,
            "origen_ip": "10.10.20.21", "origen_puerto": 40000, "inicio_utc": T0 % 1, "fin_utc": T0 % 2,
            "clase": "ok"}
    base.update(k)
    return base


def srv(**k):
    base = {"cliente": "10.10.20.21", "puerto_cliente": 40000, "inicio_utc": T0 % 1, "fin_utc": T0 % 2,
            "codigo": 200, "resultado": "completa", "aleatorio": None}
    base.update(k)
    return base


BORDES = [{"evento": "arranque", "utc": "2026-11-24T09:00:00Z"}, {"evento": "fin", "utc": "2026-11-24T11:00:00Z"}]


class TestConciliar(unittest.TestCase):
    def uno(self, t, http=(), dns=()):
        return c.conciliar([t], list(http) + BORDES, list(dns) + BORDES)["filas"][0]

    def test_http_correcto(self):
        self.assertEqual(self.uno(tx("web_media", http_codigo=200), [srv()])["clase"], "correcto")

    def test_codigo_discrepa(self):
        f = self.uno(tx("web_media", http_codigo=200), [srv(codigo=404)])
        self.assertEqual((f["clase"], f["motivo"]), ("fallo_imprevisto", "codigo_discrepa"))

    def test_servidor_incompleto(self):
        f = self.uno(tx("web_grande", http_codigo=200), [srv(resultado="incompleta")])
        self.assertEqual(f["clase"], "fallo_imprevisto")

    def test_post_500_con_sorteo(self):
        f = self.uno(tx("api_post", http_codigo=500, clase="variacion_servidor"),
                     [srv(codigo=500, aleatorio={"tipo": "post_u", "valor": 0.05, "codigo": 500})])
        self.assertEqual(f["clase"], "variacion_servidor")

    def test_post_500_sin_sorteo_es_fallo(self):
        f = self.uno(tx("api_post", http_codigo=500), [srv(codigo=500)])
        self.assertEqual(f["clase"], "fallo_imprevisto")

    def test_sin_registro_dentro_es_fallo(self):
        self.assertEqual(self.uno(tx("api_ok", http_codigo=200))["motivo"], "sin_registro_servidor")

    def test_fuera_del_registro_no_verificable(self):
        t = tx("api_ok", http_codigo=200, inicio_utc="2026-11-24T12:00:00Z", fin_utc="2026-11-24T12:00:01Z")
        self.assertEqual(self.uno(t)["clase"], "incompleta_no_verificable")

    def test_reuso_de_puerto_otra_hora_no_empareja(self):
        viejo = srv(inicio_utc="2026-11-24T09:30:00Z", fin_utc="2026-11-24T09:30:01Z")
        self.assertEqual(self.uno(tx("api_ok", http_codigo=200), [viejo])["motivo"], "sin_registro_servidor")

    def test_ambiguo_no_verificable(self):
        self.assertEqual(self.uno(tx("api_ok", http_codigo=200), [srv(), srv()])["clase"], "incompleta_no_verificable")

    def test_parada_no_verificable(self):
        self.assertEqual(self.uno(tx("api_ok", clase="incompleta_no_verificable"))["clase"], "incompleta_no_verificable")

    def test_dns_nxdomain(self):
        q = {"utc": T0 % 1, "sentido": "consulta", "cliente": "10.10.20.21", "puerto_cliente": 40000, "id": 7}
        r = dict(q, sentido="respuesta", rcode="NXDOMAIN")
        f = self.uno(tx("dns_inexistente", dns_id=7, dns_rcode=3, clase="error_intencional"), dns=[q, r])
        self.assertEqual(f["clase"], "error_intencional")

    def test_dns_sin_respuesta_no_verificable(self):
        q = {"utc": T0 % 1, "sentido": "consulta", "cliente": "10.10.20.21", "puerto_cliente": 40000, "id": 7}
        self.assertEqual(self.uno(tx("dns", dns_id=7, dns_rcode=0), dns=[q])["clase"], "incompleta_no_verificable")

    def test_ping_por_diseno(self):
        self.assertEqual(self.uno(tx("ping"))["motivo"], "sin_registro_por_diseno")


if __name__ == "__main__":
    unittest.main()
