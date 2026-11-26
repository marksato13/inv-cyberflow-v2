"""Eventos DNS sin transacción: sondas del preflight (revisión del 26-nov, segunda ronda).

Un evento solo es «explicado» si casa con una sonda REGISTRADA (preflight.jsonl de v2ctl) de la
misma ejecución, con el mismo origen, puerto, id y nombre completo, y dentro de su intervalo. La
firma (id 17611 + «portal.») ya no explica nada: solo marca como «incierto» lo que se le parece.
"""
import json
import random
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "captura"))
sys.path.insert(0, str(RAIZ / "tests"))
import contraste_dns as c  # noqa: E402
from test_contraste_dns import CLIENTE, NOMBRE, escenario, registro, utc  # noqa: E402

PUERTO = 41000


def test_constante_igual_a_la_semilla_de_v2ctl():
    fuente = (RAIZ / "operacion/v2ctl.py").read_text(encoding="utf-8")
    m = re.search(r"tx\.Cliente\([^)]*\n?\s*random\.Random\((\d+)\),\s*random\.Random\((\d+)\)\)", fuente)
    assert m, "v2ctl.py ya no crea el cliente de la sonda como se esperaba: revisar la regla"
    assert random.Random(int(m.group(2))).randint(0, 65535) == c.ID_SONDA_PREFLIGHT
    assert 'nombre = "portal." + prog["destinos"]["dns_zona"]' in fuente


def sonda(**k):
    base = {"tipo": "sonda", "accion": "dns", "sonda": "dns", "contexto": "sondear", "ejecucion_id": "E1",
            "origen_ip": CLIENTE, "origen_puerto": PUERTO, "dns_id": 17611, "dns_nombre": NOMBRE,
            "inicio_utc": utc(1000.04), "fin_utc": utc(1000.07), "clase": "ok"}
    base.update(k)
    return base


def correr(tmp_path, eventos_extra, sondas=None, nombre=None):
    tx, eventos, _ = escenario(tmp_path)
    for i, ev in enumerate(eventos_extra):
        eventos.insert(1 + i, ev)
    txruta, dcruta, salida = (tmp_path / x for x in ("tx.jsonl", "dc.jsonl", "salida.json"))
    txruta.write_text(json.dumps(tx) + "\n", encoding="utf-8")
    dcruta.write_text("\n".join(json.dumps(x) for x in eventos) + "\n", encoding="utf-8")
    args = ["--transacciones", str(txruta), "--dc1", str(dcruta), "--capturas", str(tmp_path / "capturas"),
            "--salida", str(salida)]
    if sondas is not None:
        ruta = tmp_path / "preflight.jsonl"
        ruta.write_text("".join(json.dumps(x) + "\n" for x in sondas), encoding="utf-8")
        args += ["--sondas", str(ruta)]
    codigo = c.main(args)
    return codigo, json.loads(salida.read_text(encoding="utf-8"))["sin_transaccion_clasificacion"]


def ev_sonda(t=1000.05, puerto=PUERTO, ident=17611, nombre=NOMBRE, respuesta=False):
    r = registro(respuesta, t, ident=ident)
    r.update(puerto_cliente=puerto, nombre=nombre)
    r["dport" if respuesta else "sport"] = puerto
    return r


def test_sonda_registrada_se_explica_y_queda_relacionada(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda(), ev_sonda(1000.06, respuesta=True)], [sonda()])
    assert (k["explicados"], k["no_explicados"]) == (2, 0)
    rel = k["relaciones"][0]
    assert rel["ejecucion_id"] == "E1" and rel["clave"] == [CLIENTE, PUERTO, 17611]
    assert rel["fuente_registro"] == "v2ctl" and rel["nombre"] == NOMBRE
    assert codigo == 0


def test_sin_registro_la_firma_no_basta(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda()])
    assert k["explicados"] == 0 and k["inciertos"] == 1
    assert codigo == 1


def test_coincidencia_accidental_otro_puerto(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda(puerto=41001)], [sonda()])
    assert k["explicados"] == 0 and k["inciertos"] == 1
    assert "sin_sonda_con_esa_clave" in k["no_explicados_detalle"][0]["motivo"]
    assert codigo == 1


def test_coincidencia_accidental_otro_nombre_mismo_prefijo(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda(nombre="portal.otra-zona.lab")], [sonda()])
    assert k["explicados"] == 0
    assert "nombre_distinto" in k["no_explicados_detalle"][0]["motivo"]
    assert codigo == 1


def test_evento_fuera_del_intervalo_de_la_sonda(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda(t=1000.9)], [sonda()])     # fin 1000.07 + 0,5 s < 1000.9
    assert k["explicados"] == 0
    assert "fuera_del_intervalo_de_la_sonda" in k["no_explicados_detalle"][0]["motivo"]
    assert codigo == 1


def test_registro_de_otra_ejecucion_no_explica(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda()], [sonda(ejecucion_id="OTRA")])
    assert k["explicados"] == 0
    assert "registro_de_otra_ejecucion" in k["no_explicados_detalle"][0]["motivo"]
    assert codigo == 1


def test_otro_evento_sin_transaccion_sigue_dando_1(tmp_path):
    codigo, k = correr(tmp_path, [ev_sonda(ident=4242, nombre="erp.cf-v2.lab")], [sonda()])
    assert k["no_explicados"] == 1 and k["inciertos"] == 0
    assert codigo == 1


def test_reconstruido_solo_con_clave_unica_en_su_intervalo(tmp_path):
    rec = sonda(fuente="reconstruido", origen_puerto=None, inicio_utc=utc(1000.0), fin_utc=utc(1000.08))
    codigo, k = correr(tmp_path, [ev_sonda()], [rec])
    assert k["explicados"] == 1 and k["por_fuente_registro"] == {"reconstruido": 1}
    # dos claves con firma dentro del mismo intervalo: no se puede decir cuál es la sonda
    otra = tmp_path / "ambigua"
    otra.mkdir()
    codigo, k = correr(otra, [ev_sonda(), ev_sonda(1000.051, puerto=41002)], [rec])
    assert k["explicados"] == 0
    assert all("reconstruccion_ambigua" in o["motivo"] for o in k["no_explicados_detalle"])


def test_sonda_antigua_de_t1_queda_incierta(tmp_path):
    # La consulta de T1 a las 06:25:16 es anterior a la ejecución: el registro reconstruido de T1
    # (desde INI) no la contiene, así que queda incierta aunque tenga la firma exacta.
    rec = sonda(fuente="reconstruido", origen_puerto=None, inicio_utc=utc(1200.0), fin_utc=utc(1200.2))
    codigo, k = correr(tmp_path, [ev_sonda()], [rec])
    assert k["explicados"] == 0 and k["inciertos"] == 1
    assert k["no_explicados_detalle"][0]["motivo"].startswith("incierto:")
    assert codigo == 1
