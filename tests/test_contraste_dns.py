"""Casos conocidos para el contraste de tres fuentes DNS."""
import gzip
import json
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "captura"))
import contraste_dns as c  # noqa: E402

CLIENTE = "10.10.20.21"
DC1 = "10.10.10.20"
IP_A = "10.10.30.10"
NOMBRE = "portal.cf-v2.lab"


def utc(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def mensaje(ident=7, respuesta=False, ttl=60, nombre=NOMBRE):
    q = b"".join(bytes([len(x)]) + x.encode() for x in nombre.split(".")) + b"\0"
    datos = struct.pack("!HHHHHH", ident, 0x8180 if respuesta else 0x0100,
                        1, int(respuesta), 0, 0) + q + struct.pack("!HH", 1, 1)
    if respuesta:
        datos += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(IP_A)
    return datos


def trama(respuesta=False, vlan=None, ttl=64, ident=7):
    src, dst = (DC1, CLIENTE) if respuesta else (CLIENTE, DC1)
    sport, dport = (53, 40000) if respuesta else (40000, 53)
    datos = mensaje(ident=ident, respuesta=respuesta)
    udp = struct.pack("!HHHH", sport, dport, len(datos) + 8, 0) + datos
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, ttl, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + udp
    eth = b"\0" * 12 + (b"\x81\x00" + struct.pack("!H", vlan) if vlan else b"") + b"\x08\x00"
    return eth + ip


def pcap(ruta, paquetes, nano=False):
    escala = 1_000_000_000 if nano else 1_000_000
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    with open(ruta, "wb") as f:
        f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
        for t, datos in paquetes:
            seg = int(t)
            f.write(struct.pack("<IIII", seg, round((t - seg) * escala), len(datos), len(datos)))
            f.write(datos)


def registro(respuesta=False, t=1000.2, ttl=60, ident=7, v1=False):
    r = {"utc": utc(t), "sentido": "respuesta" if respuesta else "consulta", "cliente": CLIENTE,
         "puerto_cliente": 40000, "id": ident, "nombre": NOMBRE, "tipo": "A",
         "rcode": "NOERROR", "a": [IP_A] if respuesta else []}
    if not v1:
        r.update(epoch=t, ttl=[ttl] if respuesta else [], src=DC1 if respuesta else CLIENTE,
                 sport=53 if respuesta else 40000, dst=CLIENTE if respuesta else DC1,
                 dport=40000 if respuesta else 53)
    return r


def escenario(tmp_path, *, sensor=True, respuesta=True, timeout=False, v1=False):
    tx = {"accion": "dns", "transaccion_id": "dns-1", "perfil": "P1", "ejecucion_id": "E1",
          "origen_ip": CLIENTE, "origen_puerto": 40000, "dns_id": 7, "dns_nombre": NOMBRE,
          "dns_rcode": None if timeout else 0, "dns_respuestas": [] if timeout else [IP_A],
          "dns_ttl": None if timeout else 60, "inicio_utc": utc(1000.09),
          "fin_utc": utc(1000.21), "timeout": timeout, "clase": "ok"}
    eventos = [{"evento": "arranque", "utc": utc(999)}, registro(False, 1000.1, v1=v1)]
    if respuesta:
        eventos.append(registro(True, 1000.2, v1=v1))
    eventos.append({"evento": "fin", "utc": utc(1001), "socket_descartadas": 0} if not v1
                   else {"evento": "fin", "utc": utc(1001)})
    carpeta = tmp_path / "capturas" / "pcap"
    carpeta.mkdir(parents=True)
    paquetes = []
    if sensor:
        paquetes += [(1000.099, trama(vlan=20)), (1000.101, trama(vlan=10, ttl=63))]
        if respuesta:
            paquetes += [(1000.199, trama(True, vlan=10)), (1000.201, trama(True, vlan=20, ttl=63))]
    pcap(carpeta / "live-1.pcap", paquetes)
    return tx, eventos, paquetes


def ejecutar(tmp_path, txs, eventos, *, dc_pcap=False):
    txruta, dcruta, salida = (tmp_path / x for x in ("transacciones.jsonl", "dc.jsonl", "salida.json"))
    txruta.write_text("\n".join(json.dumps(x) for x in txs) + "\n", encoding="utf-8")
    dcruta.write_text("\n".join(json.dumps(x) for x in eventos) + "\n", encoding="utf-8")
    args = ["--transacciones", str(txruta), "--dc1", str(dcruta), "--capturas", str(tmp_path / "capturas"),
            "--salida", str(salida)]
    if dc_pcap:
        pcap(tmp_path / "dc.pcap", [(1000.1, trama()), (1000.2, trama(True))], nano=True)
        args += ["--pcap", str(tmp_path / "dc.pcap")]
    codigo = c.main(args)
    return codigo, json.loads(salida.read_text(encoding="utf-8")) if salida.exists() else None


def test_todo_coincide_y_pcap_dc1(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    codigo, informe = ejecutar(tmp_path, [tx], eventos, dc_pcap=True)
    r = informe["por_transaccion"][0]
    assert codigo == 0
    assert r["estado"] == "comprobado"
    assert r["copias_consulta_sensor1"] == {"n": 2, "vlan": {"10": 1, "20": 1}}
    assert r["copias_respuesta_sensor1"]["n"] == 2
    assert r["coincidencias"]["ttl_generador_dc1"] is True
    assert informe["desfases"]["dc1_menos_sensor1"]["n"] == 2


def test_dc1_sin_copias_sensor1(tmp_path):
    tx, eventos, _ = escenario(tmp_path, sensor=False)
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    r = informe["por_transaccion"][0]
    assert codigo == 1
    assert r["consulta_dc1"] and r["copias_consulta_sensor1"]["n"] == 0
    assert "copia_consulta_vlan_20_no_sensor1" in r["discrepancias"]


def test_falta_solo_vlan_10_respuesta(tmp_path):
    tx, eventos, paquetes = escenario(tmp_path)
    pcap(tmp_path / "capturas" / "pcap" / "live-1.pcap", [p for p in paquetes if p[0] != 1000.199])
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    assert codigo == 1
    assert informe["por_transaccion"][0]["discrepancias"] == ["copia_respuesta_vlan_10_no_sensor1"]


def test_timeout_sin_consulta_dc1(tmp_path):
    tx, eventos, _ = escenario(tmp_path, sensor=False, respuesta=False, timeout=True)
    eventos = [x for x in eventos if x.get("sentido") != "consulta"]
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    r = informe["por_transaccion"][0]
    assert codigo == 1 and r["timeout"] and not r["consulta_dc1"]
    assert "consulta_no_dc1" in r["discrepancias"]
    assert informe["total"]["timeouts_con_consulta_dc1"] == 0


def test_misma_clave_repetida_es_duplicado(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    eventos.insert(2, registro(False, 1000.15))
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    r = informe["por_transaccion"][0]
    assert codigo == 1 and r["consultas_dc1"] == 2
    assert r["duplicado_o_reintento"]
    assert "consulta_duplicada_dc1" in r["discrepancias"]


def test_ttl_distinto_dc1_generador(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    eventos[2]["ttl"] = [55]
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    r = informe["por_transaccion"][0]
    assert codigo == 1 and r["coincidencias"]["ttl_generador_dc1"] is False
    assert "ttl_generador_dc1_distinto" in r["discrepancias"]


def test_v1_informa_campo_no_comprobado(tmp_path):
    tx, eventos, _ = escenario(tmp_path, v1=True)
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    r = informe["por_transaccion"][0]
    assert codigo == 0 and informe["parametros"]["registro_v1"]
    assert {x["campo"] for x in r["no_comprobado"]} >= {"ttl_dc1", "instante_nucleo_dc1", "descartes_socket"}
    assert "ttl_generador_dc1" not in r["comprobado"]


def test_socket_descartadas_indetermina_intervalo(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    eventos.insert(-1, {"evento": "estadisticas", "utc": utc(1000.3),
                        "socket_descartadas": 2, "acumulado_descartadas": 2})
    eventos[-1]["socket_descartadas"] = 2
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    assert codigo == 0
    assert informe["por_transaccion"][0]["estado"] == "indeterminado_dc1"
    assert informe["total"]["indeterminado_dc1"] == 1


def test_pcap_truncado_da_codigo_3(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    ruta = tmp_path / "capturas" / "pcap" / "live-1.pcap"
    ruta.write_bytes(ruta.read_bytes()[:-3])
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    assert codigo == 3 and informe is None


def test_trafico_poblacion_sin_transaccion(tmp_path):
    tx, eventos, _ = escenario(tmp_path)
    eventos.insert(-1, registro(False, 1000.4, ident=8))
    codigo, informe = ejecutar(tmp_path, [tx], eventos)
    assert codigo == 1 and informe["sin_transaccion"]["total"] == 1
    assert informe["sin_transaccion"]["items"][0]["fuente"] == "dc1"


def test_gzip_nano_y_csv(tmp_path):
    tx, eventos, paquetes = escenario(tmp_path)
    original = tmp_path / "capturas" / "pcap" / "live-1.pcap"
    pcap(original, paquetes, nano=True)
    comprimido = original.with_suffix(".pcap.gz")
    with gzip.open(comprimido, "wb") as f:
        f.write(original.read_bytes())
    original.unlink()
    txruta = tmp_path / "tx.jsonl"
    dcruta = tmp_path / "dc.jsonl"
    txruta.write_text(json.dumps(tx) + "\n")
    dcruta.write_text("\n".join(json.dumps(x) for x in eventos) + "\n")
    salida, csvruta = tmp_path / "salida.json", tmp_path / "salida.csv"
    assert c.main(["--transacciones", str(txruta), "--dc1", str(dcruta),
                   "--capturas", str(tmp_path / "capturas"), "--salida", str(salida),
                   "--csv", str(csvruta)]) == 0
    assert len(csvruta.read_text().splitlines()) == 2
