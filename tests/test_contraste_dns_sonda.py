"""Eventos DNS sin transacción: la sonda del preflight (revisión del 26-nov).

Fija que la regla de contraste_dns.py casa con lo que v2ctl.py emite de verdad y que un
evento sin transacción que no sea la sonda sigue dando código 1.
"""
import random
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "captura"))
sys.path.insert(0, str(RAIZ / "tests"))
import contraste_dns as c  # noqa: E402
from test_contraste_dns import ejecutar, escenario, registro  # noqa: E402


def test_constante_igual_a_la_semilla_de_v2ctl():
    fuente = (RAIZ / "operacion/v2ctl.py").read_text(encoding="utf-8")
    m = re.search(r"tx\.Cliente\([^)]*\n?\s*random\.Random\((\d+)\),\s*random\.Random\((\d+)\)\)", fuente)
    assert m, "v2ctl.py ya no crea el cliente de la sonda como se esperaba: revisar la regla"
    semilla_red = int(m.group(2))                 # 4.º argumento de Cliente = generador de ids
    assert random.Random(semilla_red).randint(0, 65535) == c.ID_SONDA_PREFLIGHT
    assert 'nombre = "portal." + prog["destinos"]["dns_zona"]' in fuente


def test_clasificar_sueltos():
    s = [{"clave": ["10.10.20.21", 1, 17611]}, {"clave": ["10.10.20.21", 2, 17611]},
         {"clave": ["10.10.20.22", 3, 99]}]
    r = c.clasificar_sueltos(s, ["portal.cf-v2.lab", "erp.cf-v2.lab", "portal.cf-v2.lab"])
    assert (r["explicados"], r["no_explicados"]) == (1, 2)
    assert r["claves_explicadas"] == [["10.10.20.21", 1, 17611]]


def test_sonda_explicada_no_da_codigo_1(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    eventos.insert(1, dict(registro(False, 1000.05, ident=17611), puerto_cliente=41000, sport=41000))
    eventos.insert(2, dict(registro(True, 1000.06, ident=17611), puerto_cliente=41000, dport=41000))
    codigo, r = ejecutar(tmp_path, [tx], eventos)
    assert r["sin_transaccion"]["total"] == 2
    assert r["sin_transaccion_clasificacion"]["explicados"] == 2
    assert r["sin_transaccion_clasificacion"]["no_explicados"] == 0
    assert codigo == 0


def test_otro_evento_sin_transaccion_sigue_dando_1(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    eventos.insert(1, dict(registro(False, 1000.05, ident=4242), puerto_cliente=41000, sport=41000))
    codigo, r = ejecutar(tmp_path, [tx], eventos)
    assert r["sin_transaccion_clasificacion"]["no_explicados"] == 1
    assert codigo == 1
