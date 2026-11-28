"""Programa y ejecución simulada de los seis perfiles v3."""
import copy
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "generador"))
sys.path.insert(0, str(RAIZ / "programas"))
import clientes_lab_v2 as gen
import generar_programas as gp
import programa as prg
import transacciones as tx


class Reloj:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def dormir(self, s):
        assert s >= 0
        self.t += s


def simular(prog, perfil, duracion_accion=0.01, parar_en=None, parche_h3=None):
    reloj = Reloj()

    def ejecutar(accion, reg):
        reloj.t += duracion_accion
        if accion == "dns":
            reg.update(dns_rcode=0, dns_respuestas=["10.10.30.10"],
                       dns_id_coincide=True, dns_ttl=60, origen_puerto=40000)
        elif accion == "obtener":
            reg.update(http_codigo=200, http_content_length=reg["bytes_solicitados"],
                       bytes_cuerpo_recibidos=reg["bytes_solicitados"], origen_puerto=40001)
        elif accion == "consulta":
            reg.update(http_codigo=200, http_content_length=512,
                       bytes_cuerpo_recibidos=512, origen_puerto=40002)
        elif accion == "envio":
            reg.update(http_codigo=201, http_content_length=80,
                       bytes_cuerpo_recibidos=80, origen_puerto=40003)
        if parar_en is not None and reloj.t >= parar_en:
            g.parar = True
            g.motivo_parada = "SIGTERM"

    with tempfile.TemporaryDirectory(dir=RAIZ / "tests") as temporal:
        g = gen.Generador(prog, "sha-prueba", perfil,
                          prog["perfiles"][perfil]["origen"], "E", Path(temporal),
                          reloj=reloj, dormir=reloj.dormir, ejecutar=ejecutar)
        if parche_h3 is None:
            estado = g.correr()
        else:
            with patch.object(gen.dist, "h3", return_value=parche_h3):
                estado = g.correr()
        txs = [json.loads(x) for x in (Path(temporal) /
               ("transacciones-%s.jsonl" % perfil)).read_text(encoding="utf-8").splitlines()]
        evs = [json.loads(x) for x in (Path(temporal) /
               ("eventos-%s.jsonl" % perfil)).read_text(encoding="utf-8").splitlines()]
    return estado, txs, evs


class TestPrograma(unittest.TestCase):
    def test_piloto_abreviado_dura_30_minutos_y_cubre_siete_patrones(self):
        p = gp.piloto()
        prg.validar(p)
        self.assertEqual(p["duracion_s"], 1800)
        self.assertEqual([j["fin_s"] - j["inicio_s"] for j in p["jornadas"]],
                         [360] + [240] * 6)
        self.assertEqual([b["fin_s"] - b["inicio_s"] for b in p["bloques"]],
                         [180, 180] + [120] * 12)
        self.assertEqual([j["patron"] for j in p["jornadas"]],
                         [j["patron"] for j in gp.captura()["jornadas"]])
        for perfil in prg.PERFILES:
            estado, txs, _ = simular(p, perfil)
            self.assertEqual(estado, "completa")
            self.assertTrue(txs)
            self.assertTrue(all(t["inicio_t_s"] < 1800 and t["clase"] == "ok" for t in txs))

    def test_calendario(self):
        p = gp.captura()
        prg.validar(p)
        self.assertEqual(p["duracion_s"], 176400)
        self.assertEqual(len(p["bloques"]), 14)
        self.assertEqual(p["horas_por_particion"],
                         {"entrenamiento": 28, "calibracion": 10.5, "desarrollo": 10.5})
        def ventanas(jid, perfil, nivel):
            j = next(j for j in p["jornadas"] if j["id"] == jid)
            return [n for n in p["niveles"] if j["inicio_s"] <= n["inicio_s"] < j["fin_s"]
                    and n["perfiles"][perfil] == nivel]
        self.assertEqual(len(ventanas("J4", "P1", "aumentado")), 7)
        self.assertEqual(len(ventanas("J6", "P1", "base")), 4)
        self.assertEqual(len(ventanas("J7", "P1", "base")), 6)
        for nombre, programa in gp.todas().items():
            prg.validar(programa)
            self.assertEqual((RAIZ / "programas" / nombre).read_bytes(),
                             gp.serializar(programa))

    def test_ventanas_exactas_de_las_siete_jornadas(self):
        """Contrasta inicios, fines y perfiles con «3 Jornadas», filas 6–11 del contrato Excel."""
        p = gp.captura()
        base = 25200
        def tramos(jornada, perfil, nivel):
            inicio = (jornada - 1) * base
            fin = jornada * base
            return [(max(n["inicio_s"], inicio) - inicio, min(n["fin_s"], fin) - inicio)
                    for n in p["niveles"] if n["inicio_s"] < fin and n["fin_s"] > inicio
                    and n["perfiles"][perfil] == nivel]
        def unir(ventanas):
            juntas = []
            for a, b in ventanas:
                if juntas and juntas[-1][1] == a:
                    juntas[-1] = (juntas[-1][0], b)
                else:
                    juntas.append((a, b))
            return juntas
        for j in (1, 5):
            for perfil in prg.PERFILES:
                self.assertEqual(unir(tramos(j, perfil, "base")), [(0, base)])
        for j, activos in ((2, {"P1", "P2"}), (3, {"P3", "P4"})):
            for perfil in prg.PERFILES:
                self.assertEqual(unir(tramos(j, perfil, "aumentado")),
                                 [(0, base)] if perfil in activos else [])
        rafagas_j4 = [(h * 3600 - 300, h * 3600) for h in range(1, 8)]
        for perfil in prg.PERFILES:
            self.assertEqual(unir(tramos(4, perfil, "aumentado")),
                             rafagas_j4 if perfil in {"P1", "P2", "P4"} else [])
        periodos_j6 = [(mitad + m * 60, mitad + (m + 15) * 60)
                       for mitad in (0, 12600) for m in (30, 120)]
        rafagas_j7 = [(mitad + m * 60, mitad + (m + 3) * 60)
                      for mitad in (0, 12600) for m in (40, 100, 160)]
        for perfil in prg.PERFILES:
            self.assertEqual(tramos(6, perfil, "base"), periodos_j6)
            self.assertEqual(tramos(7, perfil, "base"), rafagas_j7)
        self.assertEqual([(b["inicio_s"], b["fin_s"], b["particion"]) for b in p["bloques"]],
                         [(j * base + h * 12600, j * base + (h + 1) * 12600,
                           gp.PARTICIONES[j][h]) for j in range(7) for h in range(2)])

    def test_rechazos_y_bordes(self):
        p = gp.transiciones()
        self.assertEqual(prg.nivel_en(p, "P1", 239), "reducido")
        self.assertEqual(prg.proximo_borde(p, "P1", 250), 360)
        self.assertEqual(prg.proximo_borde(p, "P6", 1), 60)
        self.assertFalse(prg.on_p6(p, 60))
        for cambio in ("hueco", "semilla", "factor"):
            q = copy.deepcopy(p)
            if cambio == "hueco":
                q["bloques"][1]["inicio_s"] += 1
            elif cambio == "semilla":
                q["bloques"][1]["semillas"]["P1"]["espera"] = q["bloques"][0]["semillas"]["P1"]["espera"]
            else:
                q["niveles"][0]["perfiles"]["P1"] = "desconocido"
            with self.assertRaises(prg.ProgramaInvalido):
                prg.validar(q)

    def test_comprobar(self):
        with patch.object(sys, "argv", ["generar_programas.py", "--comprobar"]):
            self.assertEqual(gp.main(), 0)


class TestGenerador(unittest.TestCase):
    def test_p6_on_off_y_cruce(self):
        _, txs, evs = simular(gp.aislados(), "P6", duracion_accion=65)
        self.assertTrue(txs)
        self.assertTrue(all(t["inicio_t_s"] % 180 < 60 for t in txs))
        self.assertTrue(any(t["cruza_borde_on"] for t in txs))
        self.assertIn("off", [e["tipo"] for e in evs])

    def test_corte_y_resiembra(self):
        p = gp.transiciones()
        _, a, evs = simular(p, "P1")
        _, b, _ = simular(p, "P1")
        self.assertEqual([t.get("bytes_solicitados") for t in a],
                         [t.get("bytes_solicitados") for t in b])
        self.assertTrue(any(e["tipo"] == "pausa_cortada" for e in evs))
        bloques = [e for e in evs if e["tipo"] == "bloque"]
        self.assertEqual([e["semillas"] for e in bloques],
                         [b["semillas"]["P1"] for b in p["bloques"]])

    def test_nivel_no_altera_tamanos(self):
        p = gp.transiciones()
        q = copy.deepcopy(p)
        q["niveles"] = [{"id": "N1", "inicio_s": 0, "fin_s": 720,
                         "perfiles": {x: "base" for x in prg.PERFILES}},
                        {"id": "N2", "inicio_s": 720, "fin_s": 1440,
                         "perfiles": {x: "base" for x in prg.PERFILES}}]
        _, a, _ = simular(p, "P1")
        _, b, _ = simular(q, "P1")
        for bid in {t["bloque_id"] for t in a}:
            sa = [t["bytes_solicitados"] for t in a if t["bloque_id"] == bid and t["accion"] == "obtener"]
            sb = [t["bytes_solicitados"] for t in b if t["bloque_id"] == bid and t["accion"] == "obtener"]
            self.assertEqual(sa[:min(len(sa), len(sb))], sb[:min(len(sa), len(sb))])

    def test_media_pausas_por_nivel(self):
        p = gp.transiciones()
        p["duracion_s"] = 120000
        p["jornadas"] = [{"id": "A", "inicio_s": 0, "fin_s": 120000,
                          "titulo": "media", "patron": "media"}]
        p["equivalencia"] = {"A": p["equivalencia"]["A"]}
        p["bloques"] = [dict(p["bloques"][0], id="A-B1", jornada="A",
                             inicio_s=0, fin_s=120000)]
        p["niveles"] = [
            {"id": "N1", "inicio_s": 0, "fin_s": 60000,
             "perfiles": {x: "base" for x in prg.PERFILES}},
            {"id": "N2", "inicio_s": 60000, "fin_s": 120000,
             "perfiles": {x: "aumentado" for x in prg.PERFILES}}]
        _, txs, _ = simular(p, "P1", duracion_accion=0)
        for nivel, media in (("base", 30), ("aumentado", 15)):
            pausas = [t["espera_previa_s"] for t in txs
                      if t["accion"] == "dns" and t["nivel"] == nivel]
            self.assertGreater(len(pausas), 1000)
            self.assertLess(abs(sum(pausas) / len(pausas) - media) / media, .1)

    def test_p2_alterna_y_reutiliza(self):
        _, txs, _ = simular(gp.piloto(), "P2", parche_h3=3)
        paginas = {}
        for t in txs:
            paginas.setdefault((t["bloque_id"], t["secuencia_id"]), []).append(t)
        paginas = [v for v in paginas.values() if len(v) == 5]
        self.assertGreater(len(paginas), 2)
        for pagina in paginas:
            http = [x for x in pagina if x["accion"] == "obtener"]
            self.assertEqual([x["peticion_en_conexion"] for x in http], [1, 2, 3, 4])
            self.assertEqual(len({x["conexion_n"] for x in http}), 1)
            self.assertEqual([x["tipo_objeto"] for x in http],
                             ["principal", "secundario", "secundario", "secundario"])
        por_bloque = {}
        for pagina in paginas:
            por_bloque.setdefault(pagina[0]["bloque_id"], []).append(pagina)
        self.assertTrue(any(len(v) >= 2 and v[0][1]["protocolo"] == "http"
                            and v[1][1]["protocolo"] == "https"
                            for v in por_bloque.values()))

    def test_p4_secuencia(self):
        _, txs, _ = simular(gp.piloto(), "P4")
        secuencias = {}
        for t in txs:
            secuencias.setdefault(t["secuencia_id"], []).append(t["accion"])
        self.assertIn(["dns", "consulta", "envio", "consulta"], list(secuencias.values()))

    def test_parada(self):
        estado, txs, evs = simular(gp.piloto(), "P1", parar_en=30)
        self.assertEqual(estado, "interrumpida")
        self.assertEqual(evs[-1]["tipo"], "fin")
        self.assertEqual(evs[-1]["transacciones"], len(txs))


class TestClientePersistente(unittest.TestCase):
    def test_dos_respuestas_en_un_socket(self):
        class SocketFalso:
            def __init__(self):
                self.respuestas = [b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nABC",
                                   b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDEFG"]
                self.enviados = []
                self.cerrado = False

            def sendall(self, datos):
                self.enviados.append(datos)

            def recv(self, _n):
                return self.respuestas.pop(0) if self.respuestas else b""

            def close(self):
                self.cerrado = True

        s = SocketFalso()
        cliente = tx.Cliente("", gp.DESTINOS)
        llamadas = []

        def conectar(ip, puerto, reg):
            llamadas.append((ip, puerto))
            reg["origen_puerto"] = 40000
            return s

        cliente._conectar = conectar
        a, b = {}, {}
        cliente.obtener(a, "127.0.0.1", 3, "principal", persistente=True)
        cliente.obtener(b, "127.0.0.1", 4, "secundario", persistente=True)
        self.assertEqual(len(llamadas), 1)
        self.assertEqual((a["origen_puerto"], b["origen_puerto"]), (40000, 40000))
        self.assertEqual((a["bytes_cuerpo_recibidos"], b["bytes_cuerpo_recibidos"]), (3, 4))
        self.assertEqual(len(s.enviados), 2)
        cliente.cerrar_pagina()
        self.assertTrue(s.cerrado)


if __name__ == "__main__":
    unittest.main()
