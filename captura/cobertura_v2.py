#!/usr/bin/env python3
"""Mide cobertura por 5-tupla y tiempo leyendo PCAP/EVE en streaming.

bytes_recibidos del generador cuenta texto plano en HTTPS; el denominador
comparable es bytes_tcp_recibidos, que incluye los registros TLS.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import datetime as dt
import gzip
import json
import re
import socket
import struct
from collections import defaultdict
from pathlib import Path

MARGEN = 2.0


def epoch(v):
    return float(v) if isinstance(v, (int, float)) else dt.datetime.fromisoformat(
        v.replace("Z", "+00:00")).timestamp()


def clave(t):
    proto = t.get("protocolo")
    proto = "tcp" if proto in ("http", "https", "tcp") else "udp" if proto == "dns" else proto
    return proto, t.get("origen_ip"), t.get("origen_puerto"), t.get("destino_ip"), t.get("destino_puerto")


def unir(rangos, a, b):
    """Une [a,b) y devuelve los bytes que todavía no estaban cubiertos."""
    nuevos = b - a
    salida = []
    puesto = False
    for x, y in rangos:
        if y < a:
            salida.append((x, y))
        elif b < x:
            if not puesto:
                salida.append((a, b))
                puesto = True
            salida.append((x, y))
        else:
            nuevos -= max(0, min(b, y) - max(a, x))
            a, b = min(a, x), max(b, y)
    if not puesto:
        salida.append((a, b))
    rangos[:] = salida
    return nuevos


def cubierto(rangos, a, b):
    return any(x <= a and b <= y for x, y in rangos)


def huecos(rangos, base):
    if base is None or not rangos:
        return None
    n, anterior = 0, base
    for a, b in rangos:
        if b <= base:
            continue
        n += max(0, a - anterior)
        anterior = max(anterior, b)
    return n


def paquetes(ruta):
    """Lee libpcap Ethernet clásico, microsegundos o nanosegundos."""
    magic = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    with (gzip.open(ruta, "rb") if str(ruta).endswith(".gz") else ruta.open("rb")) as f:
        cab = f.read(24)
        if len(cab) != 24 or cab[:4] not in magic:
            raise ValueError("cabecera PCAP inválida o truncada")
        orden, escala = magic[cab[:4]]
        if struct.unpack(orden + "HHIIII", cab[4:])[-1] != 1:
            raise ValueError("enlace PCAP no Ethernet")
        while True:
            cab = f.read(16)
            if not cab:
                return
            if len(cab) != 16:
                raise ValueError("cabecera de paquete truncada")
            segundos, sub, n, _ = struct.unpack(orden + "IIII", cab)
            if n > 16 * 1024 * 1024:
                raise ValueError("longitud de paquete inválida")
            datos = f.read(n)
            if len(datos) != n:
                raise ValueError("paquete truncado")
            yield segundos + sub / escala, datos


def decodificar(ts, d):
    if len(d) < 14:
        raise ValueError("trama Ethernet truncada")
    tipo, pos, vlan = struct.unpack_from("!H", d, 12)[0], 14, None
    while tipo in (0x8100, 0x88a8):
        if len(d) < pos + 4:
            raise ValueError("etiqueta VLAN truncada")
        vlan = struct.unpack_from("!H", d, pos)[0] & 4095
        tipo = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    if tipo != 0x0800:
        return None
    if len(d) < pos + 20:
        raise ValueError("cabecera IPv4 truncada")
    ihl = (d[pos] & 15) * 4
    largo = struct.unpack_from("!H", d, pos + 2)[0]
    if d[pos] >> 4 != 4 or ihl < 20 or largo < ihl or len(d) < pos + largo:
        raise ValueError("paquete IPv4 inválido o truncado")
    if struct.unpack_from("!H", d, pos + 6)[0] & 0x1fff:
        return None
    proto = d[pos + 9]
    o, de = socket.inet_ntoa(d[pos + 12:pos + 16]), socket.inet_ntoa(d[pos + 16:pos + 20])
    cuerpo = d[pos + ihl:pos + largo]
    p = dict(ts=ts, vlan=vlan, origen=o, destino=de)
    if proto == 6:
        if len(cuerpo) < 20:
            raise ValueError("cabecera TCP truncada")
        po, pd, seq = struct.unpack_from("!HHI", cuerpo)
        off = (cuerpo[12] >> 4) * 4
        if off < 20 or off > len(cuerpo):
            raise ValueError("longitud de cabecera TCP inválida")
        return dict(p, proto="tcp", po=po, pd=pd, seq=seq, flags=cuerpo[13], carga=cuerpo[off:])
    if proto == 17:
        if len(cuerpo) < 8:
            raise ValueError("cabecera UDP truncada")
        po, pd, n = struct.unpack_from("!HHH", cuerpo)
        if n < 8 or n > len(cuerpo):
            raise ValueError("longitud UDP inválida")
        return dict(p, proto="udp", po=po, pd=pd, carga=cuerpo[8:n])
    if proto == 1:
        if len(cuerpo) < 8:
            raise ValueError("cabecera ICMP truncada")
        tipo, _, _, ident, sec = struct.unpack_from("!BBHHH", cuerpo)
        return dict(p, proto="icmp", po=None, pd=None, tipo=tipo, ident=ident, sec=sec)
    return None


def preparar(txs):
    indice = defaultdict(list)
    estados = []
    for t in txs:
        r = dict(transaccion_id=t.get("transaccion_id"), ejecucion_id=t.get("ejecucion_id"),
                 jornada_id=t.get("jornada_id"), perfil=t.get("perfil"),
                 accion=t.get("accion"), protocolo=t.get("protocolo"),
                 origen_ip=t.get("origen_ip"), origen_puerto=t.get("origen_puerto"),
                 destino_ip=t.get("destino_ip"), destino_puerto=t.get("destino_puerto"),
                 inicio_utc=t["inicio_utc"], fin_utc=t["fin_utc"], conexion=False,
                 syn=False, syn_ack=False, rst=False, peticion=False, respuesta=False,
                 transferencia="no comparable", bytes_esperados=t.get("bytes_tcp_recibidos"),
                 bytes_tcp_enviados=t.get("bytes_tcp_enviados"),
                 bytes_aplicacion_recibidos=t.get("bytes_recibidos"),
                 bytes_vistos=0, fraccion=None, copias_espejo=0, retransmisiones=0, huecos=0,
                 desfase_aparente_s=None, estado="verificable", eve_tipos=[],
                 eve_flow_id=None, eve_http_codigo=None, eve_http_coincide=None,
                 eve_dns_rcode=None, eve_dns_coincide=None,
                 eve_tls_version=None, eve_tls_coincide=None)
        e = dict(t=t, r=r, inicio=epoch(t["inicio_utc"]), fin=epoch(t["fin_utc"]),
                 rangos=[[], []], por_vlan=[defaultdict(list), defaultdict(list)],
                 control=[defaultdict(set), defaultdict(set)],
                 isn=[None, None], primer=None, dns_id=None, icmp_id=None)
        estados.append(e)
        indice[clave(t)].append(e)
    for k, grupo in indice.items():
        grupo.sort(key=lambda e: e["inicio"])
        indice[k] = ([e["inicio"] for e in grupo],
                     max(e["fin"] - e["inicio"] for e in grupo), grupo)
    return estados, indice


def asignar(p, indice):
    k = p["proto"], p["origen"], p["po"], p["destino"], p["pd"]
    inv = p["proto"], p["destino"], p["pd"], p["origen"], p["po"]
    def vecinos(llave):
        if llave not in indice:
            return ()
        inicios, duracion, grupo = indice[llave]
        desde = bisect.bisect_left(inicios, p["ts"] - duracion - MARGEN)
        hasta = bisect.bisect_right(inicios, p["ts"] + MARGEN)
        return grupo[desde:hasta]
    candidatos = [(e, 0) for e in vecinos(k)] + [(e, 1) for e in vecinos(inv)]
    candidatos = [(e, s) for e, s in candidatos if e["inicio"] - MARGEN <= p["ts"] <= e["fin"] + MARGEN]
    return min(candidatos, key=lambda x: (abs(p["ts"] - x[0]["inicio"]), x[0]["inicio"])) if candidatos else None


def observar(e, sentido, p):
    r = e["r"]
    if sentido == 0:
        e["primer"] = p["ts"] if e["primer"] is None else min(e["primer"], p["ts"])
    if p["proto"] == "tcp":
        flags, seq, carga, vlan = p["flags"], p["seq"], p["carga"], p["vlan"]
        if flags & 2:
            r["syn" if sentido == 0 else "syn_ack"] = True
            e["isn"][sentido] = seq
        if flags & 4:
            r["rst"] = True
        if carga:
            r["peticion" if sentido == 0 else "respuesta"] = True
            base = e["isn"][sentido]
            a = (seq - base - 1) & 0xffffffff if base is not None else seq
            b = a + len(carga)
            propias = e["por_vlan"][sentido][vlan]
            copia = any(cubierto(v, a, b) for k, v in e["por_vlan"][sentido].items() if k != vlan)
            repetida = cubierto(propias, a, b)
            nuevos = unir(e["rangos"][sentido], a, b)
            if repetida:
                r["retransmisiones"] += 1
            elif copia:
                r["copias_espejo"] += 1
            elif nuevos < len(carga):
                r["retransmisiones"] += 1
            unir(propias, a, b)
            if sentido == 1:
                r["bytes_vistos"] = sum(y - x for x, y in e["rangos"][1])
        else:
            firma = seq, flags & 0x17
            propias = e["control"][sentido][vlan]
            if firma in propias:
                r["retransmisiones"] += 1
            elif any(firma in v for k, v in e["control"][sentido].items() if k != vlan):
                r["copias_espejo"] += 1
            propias.add(firma)
        r["conexion"] = r["syn"] or r["syn_ack"] or r["rst"]
    elif p["proto"] == "udp" and len(p["carga"]) >= 12:
        ident, flags = struct.unpack_from("!HH", p["carga"])
        if sentido == 0 and not flags & 0x8000:
            e["dns_id"] = ident
            r["peticion"] = True
        elif sentido == 1 and flags & 0x8000 and ident == e["dns_id"]:
            r["respuesta"] = True
            r["dns_rcode_pcap"] = flags & 15
    elif p["proto"] == "icmp":
        if sentido == 0 and p["tipo"] == 8:
            e["icmp_id"] = p["ident"], p["sec"]
            r["peticion"] = True
        elif sentido == 1 and p["tipo"] == 0 and e["icmp_id"] == (p["ident"], p["sec"]):
            r["respuesta"] = True


def leer_eve(carpeta, indice, errores):
    # Dos pasadas evitan guardar eventos ajenos: primero se identifican flow_id.
    flows = {}
    for pasada in (0, 1):
        for f in sorted((carpeta / "eve").glob("eve-*.json")):
            try:
                with f.open(encoding="utf-8") as entrada:
                    for numero, linea in enumerate(entrada, 1):
                        try:
                            ev = json.loads(linea)
                        except (ValueError, UnicodeError) as exc:
                            if pasada == 0:
                                errores.append(dict(fichero=str(f), motivo=f"línea EVE {numero} corrupta: {exc}"))
                            continue
                        if not isinstance(ev, dict):
                            if pasada == 0:
                                errores.append(dict(fichero=str(f), motivo=f"línea EVE {numero} no es un objeto"))
                            continue
                        fid = ev.get("flow_id")
                        if pasada == 0:
                            try:
                                p = dict(proto=ev.get("proto", "").lower(), origen=ev.get("src_ip"),
                                         destino=ev.get("dest_ip"), po=ev.get("src_port"),
                                         pd=ev.get("dest_port"), ts=epoch(ev["timestamp"]))
                                m = asignar(p, indice)
                            except (KeyError, ValueError, TypeError):
                                m = None
                            if m and fid is not None:
                                flows[fid] = m[0]
                        elif fid in flows:
                            e = flows[fid]
                            r = e["r"]
                            tipo = ev.get("event_type")
                            if tipo not in r["eve_tipos"]:
                                r["eve_tipos"].append(tipo)
                            r["eve_flow_id"] = fid
                            if tipo == "http":
                                if "eve_http_tx_id" in r and ev.get("tx_id") != r["eve_http_tx_id"]:
                                    continue
                                codigo = (ev.get("http") or {}).get("status")
                                if codigo is not None:
                                    r["eve_http_codigo"] = codigo
                                    r["eve_http_coincide"] = str(codigo) == str(e["t"].get("http_codigo"))
                                r["eve_http_tx_id"] = ev.get("tx_id")
                            elif tipo == "dns":
                                codigo = (ev.get("dns") or {}).get("rcode")
                                if codigo is not None:
                                    r["eve_dns_rcode"] = codigo
                                    esperado = e["t"].get("dns_rcode")
                                    nombres = {0: "NOERROR", 3: "NXDOMAIN"}
                                    r["eve_dns_coincide"] = str(codigo).upper() in {
                                        str(esperado).upper(), nombres.get(esperado, "").upper()}
                            elif tipo == "tls":
                                version = (ev.get("tls") or {}).get("version")
                                if version is not None:
                                    r["eve_tls_version"] = version
                                    esperado = e["t"].get("tls_version")
                                    r["eve_tls_coincide"] = (version == esperado or
                                        (esperado is not None and re.sub(r"[^0-9.]", "", str(version)) ==
                                         re.sub(r"[^0-9.]", "", str(esperado))))
            except OSError as exc:
                if pasada == 0:
                    errores.append(dict(fichero=str(f), motivo=str(exc)))


def agregado(estados):
    filas = [e["r"] for e in estados]
    validas = [r for r in filas if r["estado"] == "verificable"]
    comparables = [r for r in validas if isinstance(r["bytes_esperados"], int)]
    esperados = sum(r["bytes_esperados"] for r in comparables)
    vistos = sum(r["bytes_vistos"] for r in comparables)
    return dict(n=len(filas), conexion=sum(bool(r["conexion"]) for r in validas),
                peticion=sum(bool(r["peticion"]) for r in validas),
                respuesta=sum(bool(r["respuesta"]) for r in validas),
                completas=sum(r["transferencia"] == "completa" for r in validas),
                bytes_esperados=esperados, bytes_vistos=vistos,
                fraccion=vistos / esperados if esperados else None,
                no_comparables=sum(r["transferencia"] == "no comparable" for r in filas),
                no_verificables=len(filas) - len(validas),
                copias_espejo=sum(r["copias_espejo"] for r in validas),
                retransmisiones=sum(r["retransmisiones"] for r in validas),
                huecos=sum(r["huecos"] or 0 for r in validas))


def medir(capturas, transacciones):
    estados, indice = preparar(transacciones)
    errores = []
    carpeta = Path(capturas)
    ficheros = sorted(list((carpeta / "pcap").glob("*.pcap")) + list((carpeta / "pcap").glob("*.pcap.gz")),
                      key=lambda p: p.name)
    if not ficheros:
        errores.append(dict(fichero=str(carpeta / "pcap"), motivo="sin PCAP"))
    manifiesto = carpeta / "manifiesto.json"
    if manifiesto.exists():
        try:
            esperado = json.loads(manifiesto.read_text(encoding="utf-8"))["pcap_ficheros"]
            if esperado != len(ficheros):
                errores.append(dict(fichero=str(manifiesto),
                                    motivo=f"PCAP archivados: {len(ficheros)} de {esperado}"))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errores.append(dict(fichero=str(manifiesto), motivo=f"manifiesto inválido: {exc}"))
    inventario = carpeta / "inventario.jsonl"
    if inventario.exists():
        try:
            with inventario.open(encoding="utf-8") as entrada:
                for numero, linea in enumerate(entrada, 1):
                    try:
                        nombre = json.loads(linea)["fichero"]
                    except (ValueError, KeyError, TypeError) as exc:
                        errores.append(dict(fichero=str(inventario),
                                            motivo=f"línea {numero} inválida: {exc}"))
                        continue
                    if not (carpeta / "pcap" / nombre).is_file():
                        errores.append(dict(fichero=str(inventario),
                                            motivo=f"PCAP ausente: {nombre}"))
        except OSError as exc:
            errores.append(dict(fichero=str(inventario), motivo=str(exc)))
    for f in ficheros:
        try:
            for ts, datos in paquetes(f):
                try:
                    p = decodificar(ts, datos)
                except ValueError as exc:
                    errores.append(dict(fichero=str(f), motivo=str(exc)))
                    continue
                if p is not None:
                    m = asignar(p, indice)
                    if m:
                        observar(*m, p)
        except (OSError, ValueError) as exc:
            errores.append(dict(fichero=str(f), motivo=str(exc)))
    leer_eve(carpeta, indice, errores)
    for e in estados:
        r = e["r"]
        if e["primer"] is not None:
            r["desfase_aparente_s"] = e["primer"] - e["inicio"]
        if e["t"].get("protocolo") in ("http", "https", "tcp"):
            r["huecos"] = huecos(e["rangos"][1], 0 if e["isn"][1] is not None else None)
            esperado = r["bytes_esperados"]
            if isinstance(esperado, int):
                r["fraccion"] = r["bytes_vistos"] / esperado if esperado else None
                r["transferencia"] = ("completa" if r["respuesta"] and r["huecos"] == 0
                                        and r["bytes_vistos"] >= esperado else "incompleta")
        if errores:
            r["estado"] = r["transferencia"] = "no verificable"
    acciones, perfiles = defaultdict(list), defaultdict(list)
    for e in estados:
        acciones[e["r"]["accion"]].append(e)
        perfiles[e["r"]["perfil"]].append(e)
    return dict(por_transaccion=[e["r"] for e in estados],
                por_accion={k: agregado(v) for k, v in sorted(acciones.items())},
                por_perfil={k: agregado(v) for k, v in sorted(perfiles.items())},
                total=agregado(estados), errores=errores,
                parametros=dict(margen_tiempo_s=MARGEN, capturas=str(capturas),
                                pcap_ficheros=len(ficheros),
                                desfase_aparente="desfase aparente = reloj + latencia",
                                error="cualquier error de lectura invalida conservadoramente toda la ejecución",
                                bytes="carga TCP única del servidor / bytes_tcp_recibidos"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capturas", required=True)
    ap.add_argument("--transacciones", nargs="+", required=True)
    ap.add_argument("--salida", required=True)
    ap.add_argument("--csv", help="CSV opcional por transacción")
    ap.add_argument("--red", default="10.10.20.16/28", help="compatibilidad; no filtra la 5-tupla")
    a = ap.parse_args(argv)
    txs = []
    for ruta in a.transacciones:
        with open(ruta, encoding="utf-8") as f:
            txs.extend(json.loads(l) for l in f if l.strip())
    informe = medir(a.capturas, txs)
    informe["parametros"]["transacciones"] = a.transacciones
    Path(a.salida).write_text(json.dumps(informe, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.csv:
        filas = informe["por_transaccion"]
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            escritor = csv.DictWriter(f, fieldnames=list(filas[0]) if filas else ["transaccion_id"])
            escritor.writeheader()
            escritor.writerows(filas)
    print(json.dumps({"total": informe["total"], "errores": informe["errores"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
