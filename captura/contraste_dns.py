#!/usr/bin/env python3
"""Contrasta DNS del generador, el registro/PCAP de DC1 y el espejo de Sensor1.

Uso: python captura/contraste_dns.py --transacciones transacciones-P1.jsonl \
     --dc1 dns.jsonl --capturas capturas/ID --salida contraste.json [--pcap dc1.pcap]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import json
import math
import socket
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

DC1 = "10.10.10.20"
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TIPOS = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA", 12: "PTR", 33: "SRV"}
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
         b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}


class EntradaDanada(ValueError):
    """Un fichero de entrada no permite obtener un resultado fiable."""


def instante(valor):
    if isinstance(valor, (int, float)) and math.isfinite(valor):
        return float(valor)
    if isinstance(valor, str):
        return dt.datetime.fromisoformat(valor.replace("Z", "+00:00")).timestamp()
    raise ValueError("instante ausente o inválido")


def jsonl(ruta):
    with Path(ruta).open(encoding="utf-8") as entrada:
        for numero, linea in enumerate(entrada, 1):
            if not linea.strip():
                continue
            try:
                objeto = json.loads(linea)
                if not isinstance(objeto, dict):
                    raise ValueError("no es un objeto")
            except ValueError as exc:
                raise EntradaDanada(f"{ruta}:{numero}: {exc}") from exc
            yield objeto


def pcap(ruta):
    """PCAP Ethernet clásico, µs/ns y gzip; rechaza cualquier registro incompleto."""
    apertura = gzip.open if str(ruta).endswith(".gz") else open
    try:
        with apertura(ruta, "rb") as entrada:
            cab = entrada.read(24)
            if len(cab) != 24 or cab[:4] not in MAGIC:
                raise EntradaDanada(f"{ruta}: cabecera PCAP inválida o truncada")
            orden, escala = MAGIC[cab[:4]]
            mayor, menor, _zona, _sig, snap, enlace = struct.unpack(orden + "HHiIII", cab[4:])
            if (mayor, menor) != (2, 4) or enlace != 1 or not 0 < snap <= 16 * 1024 * 1024:
                raise EntradaDanada(f"{ruta}: versión, enlace o snaplen PCAP inválido")
            while True:
                cab = entrada.read(16)
                if not cab:
                    return
                if len(cab) != 16:
                    raise EntradaDanada(f"{ruta}: registro PCAP truncado")
                seg, sub, incluido, original = struct.unpack(orden + "IIII", cab)
                if sub >= escala or incluido > snap or original < incluido:
                    raise EntradaDanada(f"{ruta}: longitud o instante PCAP inválido")
                trama = entrada.read(incluido)
                if len(trama) != incluido:
                    raise EntradaDanada(f"{ruta}: trama PCAP truncada")
                yield seg + sub / escala, trama, original
    except (OSError, EOFError) as exc:
        raise EntradaDanada(f"{ruta}: {exc}") from exc


def nombre_dns(datos, pos, visitados=None):
    visitados = set() if visitados is None else visitados
    partes = []
    fin = None
    while True:
        if pos >= len(datos) or pos in visitados or len(visitados) > 128:
            raise EntradaDanada("nombre DNS truncado o puntero circular")
        visitados.add(pos)
        largo = datos[pos]
        if largo == 0:
            return ".".join(partes), (fin if fin is not None else pos + 1)
        if largo & 0xC0 == 0xC0:
            if pos + 2 > len(datos):
                raise EntradaDanada("puntero DNS truncado")
            destino = struct.unpack_from("!H", datos, pos)[0] & 0x3FFF
            fin = pos + 2 if fin is None else fin
            pos = destino
        elif largo & 0xC0 or largo > 63 or pos + 1 + largo > len(datos):
            raise EntradaDanada("etiqueta DNS inválida")
        else:
            partes.append(datos[pos + 1:pos + 1 + largo].decode("ascii", "replace"))
            pos += largo + 1


def dns(datos):
    if len(datos) < 12:
        raise EntradaDanada("mensaje DNS truncado")
    ident, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", datos)
    if qd > 20 or an > 1000:
        raise EntradaDanada("conteos DNS inválidos")
    pos = 12
    nombre, tipo = None, None
    for i in range(qd):
        n, pos = nombre_dns(datos, pos)
        if pos + 4 > len(datos):
            raise EntradaDanada("pregunta DNS truncada")
        codigo, _clase = struct.unpack_from("!HH", datos, pos)
        pos += 4
        if i == 0:
            nombre, tipo = n, TIPOS.get(codigo, codigo)
    direcciones, ttls = [], []
    for _ in range(an):
        _, pos = nombre_dns(datos, pos)
        if pos + 10 > len(datos):
            raise EntradaDanada("respuesta DNS truncada")
        codigo, clase, ttl, largo = struct.unpack_from("!HHIH", datos, pos)
        pos += 10
        if pos + largo > len(datos):
            raise EntradaDanada("RDATA DNS truncado")
        if (codigo, clase, largo) == (1, 1, 4):
            direcciones.append(socket.inet_ntoa(datos[pos:pos + 4]))
            ttls.append(ttl)
        pos += largo
    return dict(id=ident, sentido="respuesta" if flags & 0x8000 else "consulta",
                nombre=nombre, tipo=tipo, rcode=RCODES.get(flags & 15, flags & 15),
                a=direcciones, ttl=ttls)


class RecortadaNoDns(Exception):
    """Trama recortada por el snaplen (p. ej. el extracto publicado deja la gestión en 96 B) cuya
    cabecera dice que no es UDP/53: no puede ser DNS, así que no es «ilegible» para este análisis."""


def trama_dns(ts, trama, original=None):
    recortada = original is not None and original > len(trama)
    if len(trama) < 14:
        raise EntradaDanada("trama Ethernet truncada")
    etipo, pos, vlan = struct.unpack_from("!H", trama, 12)[0], 14, None
    while etipo in (0x8100, 0x88A8):
        if pos + 4 > len(trama):
            raise EntradaDanada("etiqueta VLAN truncada")
        vlan = struct.unpack_from("!H", trama, pos)[0] & 4095
        etipo = struct.unpack_from("!H", trama, pos + 2)[0]
        pos += 4
    if etipo != 0x0800:
        return None
    if pos + 20 > len(trama):
        raise EntradaDanada("IPv4 truncado")
    ihl = (trama[pos] & 15) * 4
    largo = struct.unpack_from("!H", trama, pos + 2)[0]
    if trama[pos] >> 4 != 4 or ihl < 20 or largo < ihl:
        raise EntradaDanada("IPv4 inválido o truncado")
    if pos + largo > len(trama):
        # Recortada por el snaplen: solo es ilegible si pudiera ser DNS (UDP con puerto 53 o
        # puertos no legibles). Una trama dañada (sin recorte declarado) sigue siendo ilegible.
        if recortada and pos + ihl <= len(trama):
            if trama[pos + 9] != 17:
                raise RecortadaNoDns()
            if pos + ihl + 4 <= len(trama) and 53 not in struct.unpack_from("!HH", trama, pos + ihl):
                raise RecortadaNoDns()
        raise EntradaDanada("IPv4 inválido o truncado")
    if trama[pos + 9] != 17 or struct.unpack_from("!H", trama, pos + 6)[0] & 0x1FFF:
        return None
    src = socket.inet_ntoa(trama[pos + 12:pos + 16])
    dst = socket.inet_ntoa(trama[pos + 16:pos + 20])
    ttl_ip = trama[pos + 8]
    udp = pos + ihl
    if udp + 8 > pos + largo:
        raise EntradaDanada("UDP truncado")
    sport, dport, longitud = struct.unpack_from("!HHH", trama, udp)
    if longitud < 8 or udp + longitud > pos + largo:
        raise EntradaDanada("UDP inválido o truncado")
    if 53 not in (sport, dport):
        return None
    contenido = dns(trama[udp + 8:udp + longitud])
    cliente, puerto = (src, sport) if dport == 53 else (dst, dport)
    return dict(contenido, t=ts, src=src, sport=sport, dst=dst, dport=dport,
                cliente=cliente, puerto_cliente=puerto, vlan=vlan, ttl_ip=ttl_ip,
                clave=(cliente, puerto, contenido["id"]))


ILEGIBLES = []   # tramas IPv4 que no se pudieron analizar (se informan; no abortan la lectura)
RECORTADAS_NO_DNS = [0]   # recortadas por el snaplen y con cabecera que excluye DNS


def leer_pcap(rutas, poblacion):
    """Un fichero dañado aborta (código 3); una trama mal formada dentro de un fichero sano se cuenta
    en ILEGIBLES con su instante y motivo, porque puede ser tráfico ajeno sin relación con el DNS."""
    salida = []
    for ruta in rutas:
        for ts, datos, original in pcap(ruta):
            try:
                paquete = trama_dns(ts, datos, original)
            except RecortadaNoDns:
                RECORTADAS_NO_DNS[0] += 1
                continue
            except EntradaDanada as exc:
                ILEGIBLES.append({"fichero": Path(ruta).name, "t": ts, "motivo": str(exc)})
                continue
            if paquete and paquete["cliente"] in poblacion and DC1 in (paquete["src"], paquete["dst"]):
                salida.append(paquete)
    return sorted(salida, key=lambda p: p["t"])


def leer_dc1(ruta):
    paquetes, ventanas, descartes, poblacion = [], [], [], set()
    arranque = previo = previo_acumulado = None
    v1 = False
    for reg in jsonl(ruta):
        try:
            if reg.get("evento") == "arranque":
                arranque = previo = instante(reg["utc"])
                previo_acumulado = 0
                poblacion.update(reg.get("poblacion", ()))
            elif reg.get("evento") == "estadisticas":
                ahora = instante(reg["utc"])
                if previo is not None and reg.get("socket_descartadas", 0) > 0:
                    descartes.append((previo, ahora))
                previo = ahora
                previo_acumulado = reg.get("acumulado_descartadas", previo_acumulado)
            elif reg.get("evento") == "fin":
                ahora = instante(reg["utc"])
                if arranque is not None:
                    ventanas.append((arranque, ahora))
                if previo is not None and reg.get("socket_descartadas", 0) > (previo_acumulado or 0):
                    descartes.append((previo, ahora))
                arranque = previo = None
            elif reg.get("sentido") in ("consulta", "respuesta"):
                t = instante(reg.get("epoch", reg.get("utc")))
                v1 |= "epoch" not in reg or "ttl" not in reg
                clave = (reg["cliente"], int(reg["puerto_cliente"]), int(reg["id"]))
                paquetes.append(dict(reg, t=t, clave=clave))
        except (KeyError, TypeError, ValueError) as exc:
            raise EntradaDanada(f"{ruta}: registro DC1 inválido: {exc}") from exc
    poblacion.update(p["cliente"] for p in paquetes)
    return sorted(paquetes, key=lambda p: p["t"]), ventanas, descartes, v1, poblacion


def rcode(valor):
    try:
        valor = int(valor)
    except (ValueError, TypeError):
        pass
    return RCODES.get(valor, str(valor).upper())


def resumen_numeros(valores):
    if not valores:
        return {"n": 0, "p50_s": None, "p99_s": None, "max_s": None, "max_abs_s": None}
    orden = sorted(valores)
    def percentil(p):
        return orden[max(0, math.ceil(p * len(orden)) - 1)]
    return {"n": len(orden), "p50_s": percentil(.50), "p99_s": percentil(.99),
            "max_s": orden[-1], "max_abs_s": max(map(abs, orden))}


def elegir(paquete, candidatos, margen, referencia=None):
    """Asigna por clave y tiempo; empates reales quedan sin asignar."""
    t = paquete["t"]
    posibles = [(abs(t - (referencia(c) if referencia else c["inicio"])), c)
                for c in candidatos.get(paquete["clave"], ())
                if c["inicio"] - margen <= t <= c["fin"] + margen]
    if not posibles:
        return None, False
    posibles.sort(key=lambda x: x[0])
    return (None, True) if len(posibles) > 1 and abs(posibles[0][0] - posibles[1][0]) <= 1e-6 else (posibles[0][1], False)


def limitar(items, limite):
    return {"total": len(items), "items": items[:limite], "truncados": max(0, len(items) - limite)}


# Sonda DNS del preflight (operacion/v2ctl.py): el cliente se crea con random.Random(1) como
# generador de identificadores, así que su consulta lleva siempre este id y pregunta por
# «portal.<zona>». La FIRMA (id + prefijo) ya no basta para explicar un evento (revisión del
# 26-nov): solo sirve para señalar como «incierto» un evento con aspecto de sonda que no casa con
# ninguna sonda registrada. Para explicar hace falta el registro de v2ctl (preflight.jsonl).
ID_SONDA_PREFLIGHT = 17611          # random.Random(1).randint(0, 65535)
NOMBRE_SONDA_PREFLIGHT = "portal."


def _nombre(n):
    return None if n is None else str(n).rstrip(".").lower()


def leer_sondas(rutas):
    """Sondas DNS registradas (tipo «sonda», acción «dns») de uno o más preflight.jsonl."""
    sondas = []
    for ruta in rutas or ():
        for x in jsonl(ruta):
            if x.get("tipo") == "sonda" and x.get("accion") == "dns":
                for campo in ("ejecucion_id", "origen_ip", "dns_id", "dns_nombre", "inicio_utc", "fin_utc"):
                    if x.get(campo) is None:
                        raise EntradaDanada(f"{ruta}: sonda DNS sin {campo}")
                sondas.append(dict(x, _ini=instante(x["inicio_utc"]), _fin=instante(x["fin_utc"])))
    return sondas


def clasificar_sueltos(sueltos, nombres, sondas=None, ejecuciones=None, margen=.5):
    """Relaciona cada evento sin transacción con una sonda registrada.

    Explicado = existe una sonda DNS registrada de la MISMA ejecución con el mismo origen, puerto,
    id y nombre completo, y el evento cae en [inicio − margen, fin + margen] de esa sonda. Un registro
    reconstruido (fuente «reconstruido», sin puerto) solo casa si su intervalo contiene el evento y
    la clave es la única de la firma en ese intervalo; se cuenta aparte. Todo lo demás es no
    explicado, con su motivo; una firma de sonda sin sonda que case es «incierto»."""
    sondas = sondas or []
    ejecuciones = set(ejecuciones or ())
    explicados, otros, relaciones = [], [], []
    por_motivo, por_fuente = Counter(), Counter()
    firma_en = defaultdict(list)          # (cliente, puerto) con firma de sonda -> instantes
    for s, nombre in zip(sueltos, nombres):
        if s["clave"][2] == ID_SONDA_PREFLIGHT and str(nombre or "").startswith(NOMBRE_SONDA_PREFLIGHT):
            firma_en[tuple(s["clave"][:2])].append(s["t"])
    for s, nombre in zip(sueltos, nombres):
        cliente, puerto, ident = s["clave"]
        firma = ident == ID_SONDA_PREFLIGHT and str(nombre or "").startswith(NOMBRE_SONDA_PREFLIGHT)
        casa, motivo = None, None
        if not sondas:
            motivo = "sin_registro_de_sondas"
        for x in sondas:
            if ejecuciones and x["ejecucion_id"] not in ejecuciones:
                motivo = motivo or "registro_de_otra_ejecucion"
                continue
            if x["origen_ip"] != cliente or int(x["dns_id"]) != ident:
                motivo = motivo or "sin_sonda_con_esa_clave"
                continue
            reconstruido = x.get("fuente") == "reconstruido" and x.get("origen_puerto") is None
            if not reconstruido and int(x.get("origen_puerto") or -1) != puerto:
                motivo = motivo or "sin_sonda_con_esa_clave"
                continue
            if _nombre(x["dns_nombre"]) != _nombre(nombre):
                motivo = "nombre_distinto"
                continue
            if not (x["_ini"] - margen <= s["t"] <= x["_fin"] + margen):
                motivo = "fuera_del_intervalo_de_la_sonda"
                continue
            if reconstruido:
                otras = {k for k, ts in firma_en.items() if k[0] == cliente
                         and any(x["_ini"] - margen <= t <= x["_fin"] + margen for t in ts)}
                if len(otras) != 1:
                    motivo = "reconstruccion_ambigua"
                    continue
            casa = x
            break
        if casa:
            fuente = casa.get("fuente", "v2ctl")
            explicados.append(s)
            por_fuente[fuente] += 1
            por_motivo["sonda_preflight_" + fuente] += 1
            relaciones.append({"clave": s["clave"], "fuente_evento": s["fuente"], "t": s["t"],
                               "ejecucion_id": casa["ejecucion_id"], "contexto": casa.get("contexto"),
                               "sonda_inicio_utc": casa["inicio_utc"], "sonda_fin_utc": casa["fin_utc"],
                               "nombre": nombre, "fuente_registro": fuente})
        else:
            motivo = motivo or "sin_sonda_con_esa_clave"
            if firma:
                motivo = "incierto:firma_de_sonda_sin_ejecucion_acreditada(%s)" % motivo
            otros.append(dict(s, motivo=motivo, nombre=nombre))
            por_motivo[motivo] += 1
    claves = sorted({tuple(s["clave"]) for s in explicados})
    return {"explicados": len(explicados), "no_explicados": len(otros),
            "inciertos": sum(o["motivo"].startswith("incierto") for o in otros),
            "por_motivo": dict(sorted(por_motivo.items())), "por_fuente_registro": dict(sorted(por_fuente.items())),
            "claves_explicadas": [list(k) for k in claves], "relaciones": relaciones,
            "no_explicados_detalle": otros[:100],
            "sondas_registradas": len(sondas),
            "regla": ("sonda DNS registrada en preflight.jsonl de la misma ejecución con igual origen, "
                      "puerto, id y nombre completo, y el evento dentro de [inicio − %g s, fin + %g s]"
                      % (margen, margen))}


def contrastar(transacciones, dc, sensor, dc_pcap, ventanas, descartes, v1, margen=.5, limite=100,
               sondas=None):
    filas, indice = [], defaultdict(list)
    poblacion = {t["origen_ip"] for t in transacciones}
    for t in transacciones:
        inicio, fin = instante(t["inicio_utc"]), instante(t["fin_utc"])
        if fin < inicio:
            raise EntradaDanada("transacción con fin anterior al inicio")
        clave = (t["origen_ip"], int(t["origen_puerto"]), int(t["dns_id"]))
        r = dict(transaccion_id=t.get("transaccion_id"), perfil=t.get("perfil"),
                 ejecucion_id=t.get("ejecucion_id"), clase=t.get("clase"), clave=list(clave),
                 timeout=bool(t.get("timeout")), estado="comprobado", discrepancias=[],
                 comprobado=[], no_comprobado=[], coincidencias={},
                 consulta_dc1=False, respuesta_dc1=False, consultas_dc1=0,
                 copias_consulta_sensor1={"n": 0, "vlan": {}},
                 copias_respuesta_sensor1={"n": 0, "vlan": {}},
                 instantes={"generador_inicio": inicio, "generador_fin": fin,
                            "dc1_consulta": None, "dc1_respuesta": None,
                            "sensor1_consulta_primera": None, "sensor1_consulta_segunda": None,
                            "sensor1_respuesta_primera": None, "sensor1_respuesta_segunda": None},
                 retardos_s={})
        e = dict(t=t, r=r, clave=clave, inicio=inicio, fin=fin, dc=[], sensor=[], pcap=[])
        filas.append(e)
        indice[clave].append(e)
    for grupo in indice.values():
        grupo.sort(key=lambda e: e["inicio"])
    sueltos, ambiguos, nombres_sueltos = [], [], []
    for fuente, paquetes in (("dc1", dc), ("sensor1", sensor), ("pcap_dc1", dc_pcap or [])):
        for p in paquetes:
            e, ambiguo = elegir(p, indice, margen,
                                 lambda candidato: candidato["fin"] if p["sentido"] == "respuesta"
                                 else candidato["inicio"])
            if ambiguo:
                ambiguos.append({"fuente": fuente, "clave": list(p["clave"]), "t": p["t"]})
            elif e:
                e[{"dc1": "dc", "sensor1": "sensor", "pcap_dc1": "pcap"}[fuente]].append(p)
            else:
                sueltos.append({"fuente": fuente, "clave": list(p["clave"]),
                                "sentido": p["sentido"], "t": p["t"], "vlan": p.get("vlan")})
                nombres_sueltos.append(p.get("nombre"))
    diferencias = {"dc1_menos_sensor1": [], "generador_inicio_menos_dc1_consulta": [],
                   "generador_fin_menos_dc1_respuesta": []}
    for e in filas:
        t, r = e["t"], e["r"]
        if any(a["clave"] == list(e["clave"]) and e["inicio"] - margen <= a["t"] <= e["fin"] + margen
               for a in ambiguos):
            r["estado"] = "ambiguo"
            r["no_comprobado"].append({"campo": "correspondencia", "motivo": "clave y tiempo no desambiguan"})
        dcq = [p for p in e["dc"] if p["sentido"] == "consulta"]
        dcr = [p for p in e["dc"] if p["sentido"] == "respuesta"]
        sq = [p for p in e["sensor"] if p["sentido"] == "consulta"]
        sr = [p for p in e["sensor"] if p["sentido"] == "respuesta"]
        r["consultas_dc1"] = len(dcq)
        r["consulta_dc1"], r["respuesta_dc1"] = bool(dcq), bool(dcr)
        r["duplicado_o_reintento"] = len(dcq) > 1
        for sentido, ps in (("consulta", sq), ("respuesta", sr)):
            r[f"copias_{sentido}_sensor1"] = {"n": len(ps), "vlan": dict(sorted(Counter(p["vlan"] for p in ps).items(), key=lambda x: str(x[0])))}
            tiempos = sorted(p["t"] for p in ps)
            for ordinal, valor in zip(("primera", "segunda"), tiempos[:2]):
                r["instantes"][f"sensor1_{sentido}_{ordinal}"] = valor
        for sentido, ps in (("consulta", dcq), ("respuesta", dcr)):
            if ps:
                r["instantes"][f"dc1_{sentido}"] = ps[0]["t"]
        i = r["instantes"]
        if dcq:
            r["retardos_s"]["generador_inicio_a_dc1_consulta"] = i["dc1_consulta"] - e["inicio"]
            if not v1:
                diferencias["generador_inicio_menos_dc1_consulta"].append(e["inicio"] - i["dc1_consulta"])
        if dcr:
            r["retardos_s"]["dc1_respuesta_a_generador_fin"] = e["fin"] - i["dc1_respuesta"]
            if not v1:
                diferencias["generador_fin_menos_dc1_respuesta"].append(e["fin"] - i["dc1_respuesta"])
        if dcq and dcr:
            r["retardos_s"]["dc1_consulta_a_respuesta"] = i["dc1_respuesta"] - i["dc1_consulta"]
        for sentido, ps, ds in (("consulta", sq, dcq), ("respuesta", sr, dcr)):
            if ps and ds:
                valor = ds[0]["t"] - min(p["t"] for p in ps)
                r["retardos_s"][f"sensor1_{sentido}_a_dc1"] = valor
                if not v1:
                    diferencias["dc1_menos_sensor1"].append(valor)
            a, b = (20, 10) if sentido == "consulta" else (10, 20)
            primera = next((p for p in ps if p["vlan"] == a), None)
            segunda = next((p for p in ps if p["vlan"] == b), None)
            if primera and segunda:
                r["coincidencias"][f"{sentido}_ttl_ip_entre_vlan"] = primera["ttl_ip"] - segunda["ttl_ip"] == 1
                r["comprobado"].append(f"{sentido}_ttl_ip_entre_vlan")
                if primera["ttl_ip"] - segunda["ttl_ip"] != 1 and r["estado"] == "comprobado":
                    r["discrepancias"].append(f"{sentido}_ttl_ip_entre_vlan_distinto")
        activo = any(a <= e["inicio"] and e["fin"] <= b for a, b in ventanas)
        descarte = any(a <= e["fin"] and e["inicio"] <= b for a, b in descartes)
        if r["estado"] == "ambiguo":
            pass
        elif not activo:
            r["estado"] = "no_determinable"
            r["no_comprobado"].append({"campo": "cobertura_dc1", "motivo": "fuera de arranque→fin"})
        elif descarte:
            r["estado"] = "indeterminado_dc1"
            r["no_comprobado"].append({"campo": "cobertura_dc1", "motivo": "socket_descartadas en el intervalo"})
        if v1:
            for campo, motivo in (("ttl_dc1", "registro v1 sin TTL"),
                                  ("instante_nucleo_dc1", "registro v1 solo tiene utc de lectura"),
                                  ("descartes_socket", "registro v1 sin estadísticas")):
                r["no_comprobado"].append({"campo": campo, "motivo": motivo})
        if dc_pcap is None:
            r["no_comprobado"].append({"campo": "pcap_dc1", "motivo": "PCAP DC1 no suministrado"})
        if r["estado"] == "comprobado":
            if not dcq:
                r["discrepancias"].append("consulta_no_dc1")
            if not t.get("timeout") and not dcr:
                r["discrepancias"].append("respuesta_no_dc1")
            for sentido, ps in (("consulta", sq), ("respuesta", sr)):
                if sentido == "respuesta" and (t.get("timeout") or not dcr):
                    continue
                for vlan in (20, 10):
                    if not any(p["vlan"] == vlan for p in ps):
                        r["discrepancias"].append(f"copia_{sentido}_vlan_{vlan}_no_sensor1")
            if r["duplicado_o_reintento"]:
                r["discrepancias"].append("consulta_duplicada_dc1")
            if t.get("timeout") and dcr:
                r["discrepancias"].append("timeout_con_respuesta_dc1")
        def comparar(campo, origen, observado, esperado):
            if observado is None or esperado is None:
                r["no_comprobado"].append({"campo": campo, "motivo": f"sin dato en {origen}"})
                r["coincidencias"][campo] = None
            else:
                coincide = observado == esperado
                r["coincidencias"][campo] = coincide
                r["comprobado"].append(campo)
                if not coincide and r["estado"] == "comprobado":
                    r["discrepancias"].append(f"{campo}_distinto")
        for sentido, ds, ss in (("consulta", dcq, sq), ("respuesta", dcr, sr)):
            for campo in ("nombre", "tipo"):
                esperado = t.get("dns_nombre") if campo == "nombre" else "A"
                comparar(f"{sentido}_{campo}_generador_dc1", "dc1", ds[0].get(campo) if ds else None, esperado)
            for campo in ("nombre", "tipo", "rcode", "a", "ttl"):
                if sentido == "consulta" and campo in ("rcode", "a", "ttl"):
                    continue
                if campo == "ttl" and v1:
                    continue
                if ds:
                    esperado = ds[0].get(campo)
                    for idx, p in enumerate(ss):
                        comparar(f"{sentido}_{campo}_dc1_sensor1_{idx + 1}", "sensor1", p.get(campo), esperado)
            if sentido == "respuesta" and not t.get("timeout"):
                if ds:
                    comparar("rcode_generador_dc1", "dc1", rcode(ds[0].get("rcode")), rcode(t.get("dns_rcode")))
                    comparar("a_generador_dc1", "dc1", ds[0].get("a"), t.get("dns_respuestas"))
                    if not v1:
                        ttl = ds[0].get("ttl")
                        comparar("ttl_generador_dc1", "dc1", ttl[0] if ttl else None, t.get("dns_ttl"))
                if sr:
                    comparar("rcode_generador_sensor1", "sensor1", rcode(sr[0].get("rcode")), rcode(t.get("dns_rcode")))
                    comparar("a_generador_sensor1", "sensor1", sr[0].get("a"), t.get("dns_respuestas"))
                    ttl = sr[0].get("ttl")
                    comparar("ttl_generador_sensor1", "sensor1", ttl[0] if ttl else None, t.get("dns_ttl"))
        if dc_pcap is not None:
            for sentido, ds in (("consulta", dcq), ("respuesta", dcr)):
                pcs = [p for p in e["pcap"] if p["sentido"] == sentido]
                comparar(f"{sentido}_dc1_jsonl_pcap", "pcap_dc1", len(pcs), len(ds))
                for p in pcs:
                    cercano = min(ds, key=lambda d: abs(d["t"] - p["t"])) if ds else None
                    if cercano:
                        for campo in ("nombre", "tipo", "rcode", "a", "ttl"):
                            if campo == "ttl" and v1:
                                continue
                            comparar(f"{sentido}_{campo}_dc1_pcap_{pcs.index(p) + 1}", "dc1", p.get(campo), cercano.get(campo))
        if r["estado"] == "comprobado" and r["discrepancias"]:
            r["estado"] = "discrepancia"
    resultados = [e["r"] for e in filas]
    clases = defaultdict(list)
    for r in resultados:
        clases[str(r["clase"])].append(r)
    def agregado(grupo):
        estados = Counter(r["estado"] for r in grupo)
        return {"transacciones": len(grupo), "comprobadas": estados["comprobado"] + estados["discrepancia"],
                "sin_discrepancias": estados["comprobado"], "discrepancias": estados["discrepancia"],
                "no_determinables": estados["no_determinable"], "indeterminado_dc1": estados["indeterminado_dc1"],
                "ambiguas": estados["ambiguo"],
                "consultas_dc1": sum(r["consulta_dc1"] for r in grupo),
                "respuestas_dc1": sum(r["respuesta_dc1"] for r in grupo),
                "timeouts": sum(r["timeout"] for r in grupo),
                "timeouts_con_consulta_dc1": sum(r["timeout"] and r["consulta_dc1"] for r in grupo),
                "timeouts_con_consulta_sensor1": sum(r["timeout"] and r["copias_consulta_sensor1"]["n"] > 0 for r in grupo)}
    return {"total": agregado(resultados), "por_clase": {k: agregado(v) for k, v in sorted(clases.items())},
            "desfases": {k: resumen_numeros(v) for k, v in diferencias.items()},
            "por_transaccion": resultados, "sin_transaccion": limitar(sueltos, limite),
            "sin_transaccion_clasificacion": clasificar_sueltos(
                sueltos, nombres_sueltos, sondas,
                {t.get("ejecucion_id") for t in transacciones if t.get("ejecucion_id")}, margen),
            "ambiguos": limitar(ambiguos, limite),
            "parametros": {"margen_s": margen, "ventanas_dc1": ventanas, "intervalos_socket_descartadas": descartes,
                           "registro_v1": v1, "pcap_dc1": dc_pcap is not None,
                           "sensor1_tramas_dns_poblacion": len(sensor), "dc1_tramas_dns_poblacion": len(dc),
                           "poblacion": sorted(poblacion)}}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--transacciones", nargs="+", required=True)
    ap.add_argument("--dc1", required=True, help="registro JSONL de DC1")
    ap.add_argument("--capturas", required=True, help="directorio capturas/ID")
    ap.add_argument("--pcap", help="PCAP opcional de DC1")
    ap.add_argument("--sondas", nargs="*", default=[],
                    help="preflight.jsonl de v2ctl (o registro reconstruido): explica las sondas")
    ap.add_argument("--salida", required=True)
    ap.add_argument("--csv")
    ap.add_argument("--margen-s", type=float, default=.5)
    ap.add_argument("--limite-lista", type=int, default=100)
    args = ap.parse_args(argv)
    if not math.isfinite(args.margen_s) or args.margen_s < 0 or args.limite_lista < 0:
        ap.error("margen y límite deben ser no negativos")
    try:
        txs = [t for ruta in args.transacciones for t in jsonl(ruta) if t.get("accion") == "dns"]
        dc, ventanas, descartes, v1, poblacion = leer_dc1(args.dc1)
        poblacion.update(t["origen_ip"] for t in txs)
        carpeta = Path(args.capturas) / "pcap"
        rutas = sorted(list(carpeta.glob("live-*.pcap")) + list(carpeta.glob("live-*.pcap.gz")))
        if not rutas:
            raise EntradaDanada(f"{carpeta}: no hay live-*.pcap[.gz]")
        sensor = leer_pcap(rutas, poblacion)
        dc_pcap = leer_pcap([Path(args.pcap)], poblacion) if args.pcap else None
        sondas = leer_sondas(args.sondas)
        informe = contrastar(txs, dc, sensor, dc_pcap, ventanas, descartes, v1,
                             args.margen_s, args.limite_lista, sondas)
        informe["parametros"]["sondas"] = [str(r) for r in args.sondas]
        informe["tramas_ilegibles"] = limitar(ILEGIBLES, args.limite_lista)
        if RECORTADAS_NO_DNS[0]:
            # Solo aparece con capturas recortadas (el extracto publicado); en el laboratorio es 0 y
            # el informe queda idéntico al de antes de este cambio.
            informe["tramas_recortadas_no_dns"] = RECORTADAS_NO_DNS[0]
        Path(args.salida).write_text(json.dumps(informe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if args.csv:
            with open(args.csv, "w", newline="", encoding="utf-8") as salida:
                columnas = ["transaccion_id", "perfil", "ejecucion_id", "clase", "estado", "timeout",
                            "consulta_dc1", "respuesta_dc1", "consultas_dc1", "duplicado_o_reintento",
                            "copias_consulta_sensor1", "copias_respuesta_sensor1", "coincidencias",
                            "instantes", "retardos_s", "discrepancias", "no_comprobado"]
                escritor = csv.DictWriter(salida, fieldnames=columnas)
                escritor.writeheader()
                for r in informe["por_transaccion"]:
                    escritor.writerow({k: json.dumps(r[k], ensure_ascii=False) if isinstance(r[k], (dict, list)) else r[k]
                                     for k in columnas})
        print(json.dumps({"total": informe["total"], "sin_transaccion": informe["sin_transaccion"]["total"]}, ensure_ascii=False))
        # Los eventos sin transacción explicados (sonda del preflight) no son fallo; los demás sí.
        return 1 if (informe["total"]["discrepancias"]
                     or informe["sin_transaccion_clasificacion"]["no_explicados"]
                     or informe["ambiguos"]["total"] or ILEGIBLES) else 0
    except (EntradaDanada, OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        print(f"entrada dañada: {exc}", file=sys.stderr)
        import traceback; traceback.print_exc(limit=3)
        return 3


if __name__ == "__main__":
    sys.exit(main())
