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
    p = dict(ts=ts, vlan=vlan, origen=o, destino=de, ipid=struct.unpack_from("!H", d, pos + 4)[0])
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


def fila(t):
    return dict(transaccion_id=t.get("transaccion_id"), ejecucion_id=t.get("ejecucion_id"),
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
                eve_tls_version=None, eve_tls_coincide=None,
                conexion_n=t.get("conexion_n"), peticion_en_conexion=t.get("peticion_en_conexion"),
                conexion_reutilizada=False, transacciones_en_conexion=1,
                rango_respuesta=None, rango_peticion=None)


def preparar(txs):
    """Una CONEXIÓN agrupa las transacciones que comparten socket (HTTP persistente: misma
    5-tupla y mismo `conexion_n`, con `persistente`); el resto, una transacción por conexión.
    Los paquetes se asignan a la conexión por 5-tupla y tiempo, y los bytes de cada sentido se
    reparten después entre sus transacciones por posición en el flujo TCP (§atribuir)."""
    grupos = {}
    estados = []
    for t in txs:
        e = dict(t=t, r=fila(t), inicio=epoch(t["inicio_utc"]), fin=epoch(t["fin_utc"]))
        estados.append(e)
        tcp = clave(t)[0] == "tcp"
        if tcp and t.get("persistente") and t.get("conexion_n") is not None:
            llave = (clave(t), t.get("perfil"), t.get("conexion_n"))
        else:
            llave = ("sola", id(e))
        grupos.setdefault(llave, []).append(e)
    indice = defaultdict(list)
    conexiones = []
    for grupo in grupos.values():
        grupo.sort(key=lambda e: (e["t"].get("peticion_en_conexion") or 0, e["inicio"]))
        c = dict(txs=grupo, inicio=min(e["inicio"] for e in grupo), fin=max(e["fin"] for e in grupo),
                 rangos=[[], []], control=[set(), set()], segmentos=[set(), set()],
                 isn=[None, None], datos=[[], []], ctrl_ts=[], primer=None, dns_id=None, icmp_id=None)
        for e in grupo:
            e["c"] = c
        conexiones.append(c)
        indice[clave(grupo[0]["t"])].append(c)
    for k, grupo in indice.items():
        grupo.sort(key=lambda c: c["inicio"])
        indice[k] = ([c["inicio"] for c in grupo], max(c["fin"] - c["inicio"] for c in grupo), grupo)
    return estados, conexiones, indice


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
    candidatos = [(c, 0) for c in vecinos(k)] + [(c, 1) for c in vecinos(inv)]
    candidatos = [(c, s) for c, s in candidatos if c["inicio"] - MARGEN <= p["ts"] <= c["fin"] + MARGEN]
    return min(candidatos, key=lambda x: (abs(p["ts"] - x[0]["inicio"]), x[0]["inicio"])) if candidatos else None


def observar(c, sentido, p):
    if sentido == 0:
        c["primer"] = p["ts"] if c["primer"] is None else min(c["primer"], p["ts"])
    if p["proto"] == "tcp":
        flags, seq, carga = p["flags"], p["seq"], p["carga"]
        if flags & 2:
            c["isn"][sentido] = seq
        if carga:
            base = c["isn"][sentido]
            a = (seq - base - 1) & 0xffffffff if base is not None else seq
            b = a + len(carga)
            # Copia del espejo = el MISMO paquete IP (IP ID y bytes iguales), venga por la misma VLAN o
            # por otra (el SPAN copia de dos puertos y el router lo reenvía por otra VLAN).
            # Retransmisión = bytes ya vistos en un paquete IP distinto (IP ID nuevo).
            firma = (p.get("ipid"), a, b)
            vistos = c["segmentos"][sentido]
            nuevos = unir(c["rangos"][sentido], a, b)
            clase = "copia" if firma in vistos else "retransmision" if nuevos < len(carga) else "nuevo"
            vistos.add(firma)
            c["datos"][sentido].append((a, p["ts"], clase, base is not None))
        elif flags & 0x07:
            # Solo cuentan SYN/FIN/RST (los ACK puros se repiten legítimamente con el mismo seq).
            firma = seq, flags & 0x17
            propias = c["control"][sentido]
            clase = ("copia" if (firma, p.get("ipid")) in propias else
                     "retransmision" if any(f == firma for f, _ in propias) else "nuevo")
            propias.add((firma, p.get("ipid")))
            c["ctrl_ts"].append((p["ts"], sentido, flags, clase))
    elif p["proto"] == "udp" and len(p["carga"]) >= 12:
        r = c["txs"][0]["r"]
        ident, flags = struct.unpack_from("!HH", p["carga"])
        if sentido == 0 and not flags & 0x8000:
            c["dns_id"] = ident
            r["peticion"] = True
        elif sentido == 1 and flags & 0x8000 and ident == c["dns_id"]:
            r["respuesta"] = True
            r["dns_rcode_pcap"] = flags & 15
    elif p["proto"] == "icmp":
        r = c["txs"][0]["r"]
        if sentido == 0 and p["tipo"] == 8:
            c["icmp_id"] = p["ident"], p["sec"]
            r["peticion"] = True
        elif sentido == 1 and p["tipo"] == 0 and c["icmp_id"] == (p["ident"], p["sec"]):
            r["respuesta"] = True


def cubiertos(rangos, a, b):
    """Bytes de [a,b) cubiertos por los rangos unidos (b=None: sin límite)."""
    return sum(max(0, (y if b is None else min(b, y)) - max(a, x)) for x, y in rangos
               if (b is None or x < b) and y > a)


def tramos(c, sentido, campo):
    """Reparte el flujo de un sentido entre las transacciones de la conexión en el orden en que
    las hizo el cliente: la transacción j ocupa [suma de las anteriores, + sus bytes TCP), que el
    generador mide sobre el mismo socket (bytes crudos: en HTTPS, registros TLS). La última se
    queda también lo que llegue después (cierre TLS, FIN con datos), como en una conexión de una
    sola transacción. Sin los bytes de alguna, no se puede repartir: None."""
    n = len(c["txs"])
    medidas = [e["t"].get(campo) for e in c["txs"]]
    if n > 1 and not all(isinstance(m, int) and m >= 0 for m in medidas):
        return None
    salida, desde = [], 0
    for i, m in enumerate(medidas):
        ultimo = i == n - 1
        hasta = None if ultimo else desde + m
        salida.append((desde, hasta))
        if not ultimo:
            desde = hasta
    return salida


def atribuir(c):
    n = len(c["txs"])
    resp, pet = tramos(c, 1, "bytes_tcp_recibidos"), tramos(c, 0, "bytes_tcp_enviados")
    syn = any(f & 2 and s == 0 for _, s, f, _ in c["ctrl_ts"])
    syn_ack = any(f & 2 and s == 1 for _, s, f, _ in c["ctrl_ts"])
    for i, e in enumerate(c["txs"]):
        r = e["r"]
        r["transacciones_en_conexion"] = n
        r["conexion_reutilizada"] = i > 0
        if i == 0:
            r["syn"], r["syn_ack"] = syn, syn_ack
        if e["t"].get("protocolo") not in ("http", "https", "tcp"):
            if c["primer"] is not None:
                r["desfase_aparente_s"] = c["primer"] - e["inicio"]
            continue
        r["conexion"] = syn or syn_ack or any(f & 4 for _, _, f, _ in c["ctrl_ts"])
        if resp is None or pet is None:
            r["nota_atribucion"] = "conexión con varias transacciones sin bytes TCP de todas"
            r["estado_atribucion"] = "sin_reparto"
            continue
        (ra, rb), (pa, pb) = resp[i], pet[i]
        r["rango_respuesta"], r["rango_peticion"] = [ra, rb], [pa, pb]
        dentro = lambda a, x, y: a >= x and (y is None or a < y)
        conocida = [c["isn"][0] is not None, c["isn"][1] is not None]
        # Sin SYN en un sentido los desplazamientos son absolutos y no se pueden repartir.
        r["peticion"] = any(dentro(a, pa, pb) for a, _, _, _ in c["datos"][0]) if conocida[0] or n == 1 else False
        r["respuesta"] = any(dentro(a, ra, rb) for a, _, _, _ in c["datos"][1]) if conocida[1] or n == 1 else False
        for s, (x, y) in ((0, (pa, pb)), (1, (ra, rb))):
            for a, _, clase, _ in c["datos"][s]:
                if (conocida[s] or n == 1) and dentro(a, x, y):
                    if clase == "copia":
                        r["copias_espejo"] += 1
                    elif clase == "retransmision":
                        r["retransmisiones"] += 1
        # Control (SYN/FIN/RST): a la transacción en curso por tiempo.
        for ts, s, f, clase in c["ctrl_ts"]:
            j = max([k for k, x in enumerate(c["txs"]) if x["inicio"] - MARGEN <= ts] or [0])
            if j == i:
                if f & 4:
                    r["rst"] = True
                if clase == "copia":
                    r["copias_espejo"] += 1
                elif clase == "retransmision":
                    r["retransmisiones"] += 1
        primeros = [ts for a, ts, _, _ in c["datos"][0] if dentro(a, pa, pb)]
        if i == 0 and c["primer"] is not None:
            primeros.append(c["primer"])
        if primeros:
            r["desfase_aparente_s"] = min(primeros) - e["inicio"]
        if not conocida[1] and n > 1:
            r["bytes_vistos"], r["huecos"] = 0, None
            continue
        rangos = c["rangos"][1]
        r["bytes_vistos"] = cubiertos(rangos, ra, rb)
        if rb is None:
            # Última (o única): huecos entre su inicio y el último byte visto, como antes.
            fin = max([y for _, y in rangos] or [ra])
            r["huecos"] = (max(0, fin - ra) - cubiertos(rangos, ra, fin)) if conocida[1] else None
        else:
            r["huecos"] = (rb - ra) - r["bytes_vistos"]


def leer_eve(carpeta, indice, errores):
    # Dos pasadas evitan guardar eventos ajenos: primero se identifican flow_id.
    # Un flow de Suricata es una conexión; en HTTP persistente, tx_id (0, 1, …) es la petición
    # n.º tx_id+1 de la conexión. flow y tls son de la conexión entera.
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
                            continue
                        if fid not in flows:
                            continue
                        c = flows[fid]
                        tipo = ev.get("event_type")
                        txid = ev.get("tx_id")
                        if tipo in ("http", "fileinfo") and len(c["txs"]) > 1 and isinstance(txid, int):
                            destinos = [c["txs"][txid]] if txid < len(c["txs"]) else []
                        elif tipo in ("http", "fileinfo", "dns"):
                            destinos = c["txs"][:1]
                        else:
                            destinos = c["txs"]
                        for e in destinos:
                            r = e["r"]
                            if tipo not in r["eve_tipos"]:
                                r["eve_tipos"].append(tipo)
                            r["eve_flow_id"] = fid
                            if tipo == "http":
                                if "eve_http_tx_id" in r and txid != r["eve_http_tx_id"]:
                                    continue
                                codigo = (ev.get("http") or {}).get("status")
                                if codigo is not None:
                                    r["eve_http_codigo"] = codigo
                                    r["eve_http_coincide"] = str(codigo) == str(e["t"].get("http_codigo"))
                                r["eve_http_tx_id"] = txid
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
                                    esperado = e["t"].get("tls_version") or c["txs"][0]["t"].get("tls_version")
                                    r["eve_tls_coincide"] = (version == esperado or
                                        (esperado is not None and re.sub(r"[^0-9.]", "", str(version)) ==
                                         re.sub(r"[^0-9.]", "", str(esperado))))
            except OSError as exc:
                if pasada == 0:
                    errores.append(dict(fichero=str(f), motivo=str(exc)))


def agregado(estados):
    filas = [e["r"] for e in estados]
    validas = [r for r in filas if r["estado"] == "verificable"]
    comparables = [r for r in validas if isinstance(r["bytes_esperados"], int)
                   and r["transferencia"] != "no comparable"]
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
                huecos=sum(r["huecos"] or 0 for r in validas),
                reutilizadas=sum(bool(r.get("conexion_reutilizada")) for r in filas))


def medir(capturas, transacciones):
    estados, conexiones, indice = preparar(transacciones)
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
                        reg = json.loads(linea)
                        # Si el archivador lo comprimió, el fichero en disco es fichero_archivado (.pcap.gz).
                        nombre = reg.get("fichero_archivado") or reg["fichero"]
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
    for c in conexiones:
        atribuir(c)
    for e in estados:
        r = e["r"]
        if e["t"].get("protocolo") in ("http", "https", "tcp"):
            esperado = r["bytes_esperados"]
            if isinstance(esperado, int) and r.get("estado_atribucion") != "sin_reparto":
                r["fraccion"] = r["bytes_vistos"] / esperado if esperado else None
                r["transferencia"] = ("completa" if r["respuesta"] and r["huecos"] == 0
                                        and r["bytes_vistos"] >= esperado else "incompleta")
        if errores:
            r["estado"] = r["transferencia"] = "no verificable"
    acciones, perfiles = defaultdict(list), defaultdict(list)
    for e in estados:
        acciones[e["r"]["accion"]].append(e)
        perfiles[e["r"]["perfil"]].append(e)
    return dict(version=2,
                por_transaccion=[e["r"] for e in estados],
                por_accion={k: agregado(v) for k, v in sorted(acciones.items())},
                por_perfil={k: agregado(v) for k, v in sorted(perfiles.items())},
                total=agregado(estados), errores=errores,
                parametros=dict(margen_tiempo_s=MARGEN, capturas=str(capturas),
                                pcap_ficheros=len(ficheros),
                                desfase_aparente="desfase aparente = reloj + latencia",
                                error="cualquier error de lectura invalida conservadoramente toda la ejecución",
                                bytes="carga TCP única del servidor / bytes_tcp_recibidos",
                                atribucion=("conexión persistente (misma 5-tupla y conexion_n): cada transacción "
                                            "ocupa su tramo del flujo según los bytes TCP que midió el generador, "
                                            "en orden de petición; sin SYN no se reparte (incompleta)"),
                                limites_https=("en HTTPS el contraste es de bytes TCP (registros TLS); el tramo de "
                                               "cada petición depende de los contadores crudos del cliente; el código "
                                               "HTTP y el cuerpo no se ven en la captura ni en el EVE")))


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
            campos = list(dict.fromkeys(k for fila in filas for k in fila)) or ["transaccion_id"]
            escritor = csv.DictWriter(f, fieldnames=campos)  # filas con campos distintos según el protocolo
            escritor.writeheader()
            escritor.writerows(filas)
    print(json.dumps({"total": informe["total"], "errores": informe["errores"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
