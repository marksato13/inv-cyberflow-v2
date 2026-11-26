"""Cobertura en conexiones HTTP persistentes (P2): varias transacciones por conexión, respuestas
de tamaños distintos, lectura del cliente en trozos y condiciones de captura (copias, reorden,
retransmisión, hueco en una sola petición, captura sin SYN, puerto reutilizado, HTTPS)."""
from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cobertura as base  # noqa: E402

cov, tcp, tx, utc = base.cov, base.tcp, base.tx, base.utc


class Caso(unittest.TestCase):
    """Mismo PCAP sintético que test_cobertura (sin heredar sus pruebas)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "pcap").mkdir()
        (self.base / "eve").mkdir()

    def pcap(self, paquetes):
        with (self.base / "pcap" / "live-19700101001640.pcap").open("wb") as f:
            f.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
            for ts, trama_ in sorted(paquetes, key=lambda x: x[0]):
                segundos = int(ts)
                f.write(struct.pack("<IIII", segundos, round((ts - segundos) * 1e6), len(trama_), len(trama_)))
                f.write(trama_)

    def medir(self, *txs):
        return cov.medir(self.base, list(txs))


def persistente(n, tamanos, peticiones=None, inicio=1000.0, paso=0.5, po=41000, proto="http"):
    """n transacciones de la misma conexión (conexion_n 7), como las escribe el generador."""
    peticiones = peticiones or [20] * n
    salida = []
    for i in range(n):
        t = tx("t%d" % (i + 1), inicio=inicio + i * paso, po=po, proto=proto,
               pd=443 if proto == "https" else 80, esperado=tamanos[i])
        t.update(fin_utc=utc(inicio + i * paso + 0.2), persistente=True, conexion_n=7,
                 peticion_en_conexion=i + 1, bytes_tcp_enviados=peticiones[i], perfil="P2",
                 accion="obtener")
        salida.append(t)
    return salida


def flujo(txs, tamanos, peticiones=None, trozo=1000, isn_c=100, isn_s=5000, quitar=(),
          copias=False, reordenar=False, retransmitir=None, syn=True, inicio=1000.0, paso=0.5):
    """Paquetes de la conexión: SYN, y por transacción la petición y la respuesta en segmentos de
    `trozo` bytes, cada segmento justo después del inicio de SU transacción. `quitar`: (tx, k)
    segmentos de respuesta que no llegan."""
    peticiones = peticiones or [20] * len(txs)
    t0 = txs[0]
    pk = []
    if syn:
        pk += [(inicio + 0.001, tcp(t0, seq=isn_c, flags=2)),
               (inicio + 0.002, tcp(t0, 1, seq=isn_s, flags=0x12))]
    oc, os_ = 0, 0
    for i, t in enumerate(txs):
        ti = inicio + i * paso
        pk.append((ti + 0.003, tcp(t0, seq=isn_c + 1 + oc, carga=b"G" * peticiones[i])))
        oc += peticiones[i]
        segs = []
        for k, a in enumerate(range(0, tamanos[i], trozo)):
            n = min(trozo, tamanos[i] - a)
            ipid = 10000 + i * 100 + k
            trama_ = tcp(t0, 1, seq=isn_s + 1 + os_ + a, carga=bytes([65 + i]) * n, ipid=ipid)
            if (i, k) not in quitar:
                segs.append((ti + 0.01 + k * 0.001, trama_))
                if copias:
                    segs.append((ti + 0.01 + k * 0.001 + 0.0001, trama_))
            if retransmitir == (i, k):
                segs.append((ti + 0.15, tcp(t0, 1, seq=isn_s + 1 + os_ + a, carga=bytes([65 + i]) * n)))
        if reordenar:
            # el último segmento llega primero (instantes invertidos, no solo el orden en el fichero)
            instantes = [ts for ts, _ in segs]
            segs = list(zip(reversed(instantes), [tr for _, tr in segs]))
        pk += segs
        os_ += tamanos[i]
    return pk


class Persistente(Caso):
    def test_varias_transacciones_tamanos_distintos(self):
        tam = [5586, 604, 12000, 1, 3333]
        txs = persistente(5, tam)
        self.pcap(flujo(txs, tam))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], tam)
        self.assertEqual([r["transferencia"] for r in filas], ["completa"] * 5)
        self.assertEqual([r["huecos"] for r in filas], [0] * 5)
        self.assertEqual([r["conexion_reutilizada"] for r in filas], [False, True, True, True, True])
        self.assertTrue(filas[0]["syn"] and filas[0]["syn_ack"])
        self.assertFalse(filas[3]["syn"])
        self.assertTrue(all(r["conexion"] and r["peticion"] and r["respuesta"] for r in filas))
        self.assertEqual(filas[2]["rango_respuesta"], [6190, 18190])

    def test_respuesta_que_llega_tras_el_inicio_de_la_siguiente(self):
        """Antes se asignaba cada paquete a la transacción de inicio más cercano: una respuesta
        larga cuyos últimos segmentos llegan cerca del inicio de la siguiente se partía."""
        tam = [40000, 500]
        txs = persistente(2, tam, paso=0.05)
        self.pcap(flujo(txs, tam, trozo=1000, paso=0.05))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], tam)
        self.assertEqual([r["transferencia"] for r in filas], ["completa", "completa"])

    def test_hueco_solo_en_su_transaccion(self):
        tam = [3000, 3000, 3000]
        txs = persistente(3, tam)
        self.pcap(flujo(txs, tam, quitar={(1, 1)}))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["transferencia"] for r in filas], ["completa", "incompleta", "completa"])
        self.assertEqual((filas[1]["bytes_vistos"], filas[1]["huecos"]), (2000, 1000))

    def test_falta_el_final_de_la_ultima(self):
        tam = [1000, 2500]
        txs = persistente(2, tam)
        self.pcap(flujo(txs, tam, quitar={(1, 2)}))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual(filas[1]["bytes_vistos"], 2000)
        self.assertEqual(filas[1]["transferencia"], "incompleta")

    def test_copias_del_espejo_y_reorden(self):
        tam = [2500, 4100]
        txs = persistente(2, tam)
        self.pcap(flujo(txs, tam, copias=True, reordenar=True))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], tam)
        self.assertEqual([r["transferencia"] for r in filas], ["completa", "completa"])
        self.assertEqual([r["copias_espejo"] for r in filas], [3, 5])
        self.assertEqual([r["retransmisiones"] for r in filas], [0, 0])

    def test_retransmision_cuenta_en_su_transaccion(self):
        tam = [2000, 2000]
        txs = persistente(2, tam)
        self.pcap(flujo(txs, tam, retransmitir=(1, 0)))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["retransmisiones"] for r in filas], [0, 1])
        self.assertEqual([r["transferencia"] for r in filas], ["completa", "completa"])

    def test_sin_syn_no_se_reparte(self):
        """Si la captura empieza con la conexión abierta, los desplazamientos no son relativos al
        ISN: no se puede saber qué bytes son de cada petición. Se declara incompleta."""
        tam = [1000, 1000]
        txs = persistente(2, tam)
        self.pcap(flujo(txs, tam, syn=False))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["transferencia"] for r in filas], ["incompleta", "incompleta"])

    def test_sin_bytes_de_alguna_no_comparable(self):
        tam = [1000, 1000]
        txs = persistente(2, tam)
        del txs[1]["bytes_tcp_enviados"]
        self.pcap(flujo(txs, tam))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["transferencia"] for r in filas], ["no comparable", "no comparable"])
        self.assertEqual(filas[0]["estado_atribucion"], "sin_reparto")

    def test_puerto_reutilizado_por_otra_conexion(self):
        a = persistente(2, [800, 900])
        b = persistente(2, [700, 600], inicio=1010.0)
        for t in b:
            t["conexion_n"] = 8
            t["transaccion_id"] += "b"
        self.pcap(flujo(a, [800, 900]) + flujo(b, [700, 600], isn_c=9000, isn_s=70000, inicio=1010.0))
        filas = self.medir(*(a + b))["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], [800, 900, 700, 600])
        self.assertEqual([r["transferencia"] for r in filas], ["completa"] * 4)

    def test_https_registros_tls_y_cierre(self):
        """HTTPS: el generador cuenta bytes crudos (registros TLS); la primera incluye el
        apretón de manos. Un cierre TLS tras la última se queda en la última."""
        tam = [4200, 1800]
        txs = persistente(2, tam, proto="https")
        pk = flujo(txs, tam)
        pk.append((1000.9, tcp(txs[0], 1, seq=5000 + 1 + sum(tam), carga=b"\x15" * 31)))
        self.pcap(pk)
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], [4200, 1831])
        self.assertEqual([r["transferencia"] for r in filas], ["completa", "completa"])

    def test_eve_tx_id_por_peticion(self):
        tam = [1000, 1000, 1000]
        txs = persistente(3, tam)
        for t, codigo in zip(txs, (200, 404, 200)):
            t["http_codigo"] = codigo
        self.pcap(flujo(txs, tam))
        t0 = txs[0]
        ev = [dict(timestamp=utc(1000.01), proto="TCP", src_ip=t0["origen_ip"], src_port=t0["origen_puerto"],
                   dest_ip=t0["destino_ip"], dest_port=t0["destino_puerto"], flow_id=77, event_type="flow")]
        ev += [dict(timestamp=utc(1000.1 + i * 0.5), flow_id=77, event_type="http", tx_id=i,
                    http=dict(status=c)) for i, c in enumerate((200, 404, 200))]
        (self.base / "eve" / "eve-E.json").write_text("".join(json.dumps(x) + "\n" for x in ev), encoding="utf-8")
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["eve_http_tx_id"] for r in filas], [0, 1, 2])
        self.assertEqual([r["eve_http_codigo"] for r in filas], [200, 404, 200])
        self.assertTrue(all(r["eve_http_coincide"] for r in filas))
        self.assertTrue(all("flow" in r["eve_tipos"] for r in filas))

    def test_lectura_del_cliente_en_trozos_no_importa(self):
        """El generador lee la respuesta en trozos de hasta 64 KiB y el cuerpo de la anterior puede
        quedar en su búfer, pero los bytes TCP que cuenta cada transacción son los leídos del
        socket entre su inicio y su fin: el reparto por posición depende solo de su suma."""
        tam = [70000, 65536, 3]
        txs = persistente(3, tam)
        self.pcap(flujo(txs, tam, trozo=1448))
        filas = self.medir(*txs)["por_transaccion"]
        self.assertEqual([r["bytes_vistos"] for r in filas], tam)
        self.assertEqual(self.medir(*txs)["total"]["reutilizadas"], 2)


if __name__ == "__main__":
    unittest.main()
