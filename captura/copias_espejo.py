#!/usr/bin/env python3
"""Comprueba las copias SPAN contra la ruta configurada de cada paquete."""
from __future__ import annotations

import argparse
import bisect
import collections
import gzip
import hashlib
import ipaddress
import json
import math
import re
import socket
import struct
from pathlib import Path

LINEA_BPS = 1e9
EXTRA_TRAMA = 20
# Población por omisión: las IP de los perfiles. Todo el tráfico experimental (HTTP/HTTPS con
# srv-dmz y DNS con DC1) tiene un cliente en un extremo. Incluir DC1 o srv-dmz enteros metía tráfico
# ajeno al estudio (DC1 con equipos de la VLAN 60 de otro proyecto: E1, 318 «falta_copia»).
IP_EXPERIMENTALES = tuple(f"10.10.20.{n}" for n in range(21, 27))
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
         b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
NOMBRE = re.compile(r"^live-\d{14}\.pcap(?:\.gz)?$")


class EntradaError(Exception):
    def __init__(self, tipo: str, detalle: str):
        super().__init__(detalle)
        self.tipo = tipo


def tramas(ruta: Path):
    """Produce registros válidos y falla expresamente ante corrupción o truncamiento."""
    try:
        with (gzip.open(ruta, "rb") if ruta.suffix == ".gz" else ruta.open("rb")) as f:
            cab = f.read(24)
            if len(cab) != 24 or cab[:4] not in MAGIC:
                raise EntradaError("ilegible", "cabecera libpcap inválida")
            orden, escala = MAGIC[cab[:4]]
            mayor, menor = struct.unpack_from(orden + "HH", cab, 4)
            snaplen = struct.unpack_from(orden + "I", cab, 16)[0]
            if (mayor, menor) != (2, 4) or snaplen == 0:
                raise EntradaError("ilegible", "versión o snaplen libpcap inválidos")
            if struct.unpack_from(orden + "I", cab, 20)[0] != 1:
                raise EntradaError("ilegible", "enlace distinto de Ethernet")
            while True:
                reg = f.read(16)
                if not reg:
                    break
                if len(reg) != 16:
                    raise EntradaError("truncado", "cabecera de registro incompleta")
                seg, frac, incl, orig = struct.unpack(orden + "IIII", reg)
                if incl > snaplen or incl > orig:
                    raise EntradaError("ilegible", "longitud de registro inválida")
                dato = f.read(incl)
                if len(dato) != incl:
                    raise EntradaError("truncado", "trama incompleta")
                yield seg + frac / escala, orig, dato
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        raise EntradaError("ilegible", str(e)) from e


def identidad(d: bytes):
    """Devuelve VLAN, identidad, IP, TTL y tipo de destino para IPv4 completo."""
    if len(d) < 14:
        return None
    tipo, pos, vlan = struct.unpack_from("!H", d, 12)[0], 14, None
    while tipo in (0x8100, 0x88a8):
        if len(d) < pos + 4:
            return None
        vlan = struct.unpack_from("!H", d, pos)[0] & 4095
        tipo = struct.unpack_from("!H", d, pos + 2)[0]
        pos += 4
    if tipo != 0x0800 or len(d) < pos + 20 or d[pos] >> 4 != 4:
        return vlan, None, None, None, None, None, None, None
    ihl = (d[pos] & 15) * 4
    if ihl < 20 or len(d) < pos + ihl:
        return vlan, None, None, None, None, None, None, None
    largo, ipid = struct.unpack_from("!HH", d, pos + 2)
    if largo < ihl or len(d) < pos + largo:
        return vlan, None, None, None, None, None, None, None
    proto, ttl = d[pos + 9], d[pos + 8]
    origen = socket.inet_ntoa(d[pos + 12:pos + 16])
    destino = socket.inet_ntoa(d[pos + 16:pos + 20])
    c = pos + ihl
    if proto == 6 and largo >= ihl + 20:
        po, pd, seq, ack = struct.unpack_from("!HHII", d, c)
        extra = (po, pd, seq, ack, d[c + 13])
    elif proto == 17 and largo >= ihl + 8:
        extra = struct.unpack_from("!HH", d, c)
    elif proto == 1 and largo >= ihl + 4:
        extra = struct.unpack_from("!BB", d, c)
    else:
        extra = ()
    clave = (proto, origen, destino, extra, ipid, largo)
    multicast = ipaddress.ip_address(destino).is_multicast or destino == "255.255.255.255" or destino.endswith(".255")
    carga = hashlib.blake2s(d[c:pos + largo], digest_size=8).digest()
    mac = d[:12]
    return vlan, clave, origen, destino, ttl, multicast, carga, mac


def configuracion(ruta: Path | None = None):
    ruta = ruta or Path(__file__).with_name("rutas_span.json")
    cfg = json.loads(ruta.read_text(encoding="utf-8"))
    redes = [(ipaddress.ip_network(x["subred"]), x["vlan"], x["puerta_enlace"])
             for x in cfg["subredes"]]
    return cfg, redes


def ruta_esperada(origen: str, destino: str, multicast: bool, redes,
                  difusion="no_determinable"):
    def buscar(ip):
        return next(((str(red), vlan, puerta) for red, vlan, puerta in redes
                     if ipaddress.ip_address(ip) in red), None)
    a, b = buscar(origen), buscar(destino)
    etiqueta = f"{a[0] if a else '?'}>{b[0] if b else '?'}"
    if multicast:
        if difusion == "dos_copias" and a:
            return etiqueta, [a[1], a[1]], None
        return etiqueta, None, "difusión o multidifusión"
    if not a or not b:
        return etiqueta, None, "dirección fuera de las subredes configuradas"
    if origen == a[2] and destino == b[2]:
        return etiqueta, None, "ambos extremos son puertas de enlace"
    if origen == a[2]:
        return etiqueta, [b[1]], None
    if destino == b[2]:
        return etiqueta, [a[1]], None
    if a[0] == b[0]:
        return etiqueta, [], None
    return etiqueta, [a[1], b[1]], None


def inventario_entrada(carpeta: Path, inventario: Path | None):
    inv = inventario or (carpeta.parent / "inventario.jsonl")
    man = carpeta.parent / "manifiesto.json"
    registros, problemas = {}, []
    if inv.exists():
        try:
            for linea in inv.read_text(encoding="utf-8").splitlines():
                if linea.strip():
                    item = json.loads(linea)
                    nombre = item.get("fichero_archivado", item["fichero"])
                    if not NOMBRE.fullmatch(nombre):
                        raise ValueError(f"nombre PCAP inválido: {nombre}")
                    registros[nombre] = item
        except (OSError, ValueError, KeyError) as e:
            problemas.append({"tipo": "inventario_ilegible", "fichero": str(inv), "detalle": str(e)})
    elif inventario:
        problemas.append({"tipo": "inventario_ausente", "fichero": str(inv)})
    if man.exists() and inventario is None:
        try:
            manifiesto = json.loads(man.read_text(encoding="utf-8"))
            if not inv.exists():
                problemas.append({"tipo": "inventario_ausente", "fichero": str(inv)})
            if not manifiesto.get("pcap_completo", True) or manifiesto.get("pcap_huecos", 0):
                problemas.append({"tipo": "manifiesto_incompleto", "fichero": str(man),
                                   "detalle": f"pcap_huecos={manifiesto.get('pcap_huecos')}"})
            if inv.exists() and manifiesto.get("pcap_ficheros") != len(registros):
                problemas.append({"tipo": "inventario_incompleto", "fichero": str(inv),
                                   "esperados": manifiesto.get("pcap_ficheros"),
                                   "registrados": len(registros)})
        except (OSError, ValueError) as e:
            problemas.append({"tipo": "manifiesto_ilegible", "fichero": str(man), "detalle": str(e)})
    if inv.exists() or inventario:
        ficheros = [carpeta / n for n in sorted(registros)]
    else:
        ficheros = sorted(x for x in carpeta.iterdir() if NOMBRE.fullmatch(x.name))
    return ficheros, registros, problemas


def percentil(valores, q):
    if not valores:
        return None
    orden = sorted(valores)
    return orden[math.ceil(q * len(orden)) - 1]


def analizar(carpeta: Path, ips: set[str] | None = None, desde=None, hasta=None,
             ventana_copia_s=0.005, inventario: Path | None = None,
             referencia: Path | None = None, margen_referencia_s=0.005,
             max_anomalias=20000, subredes: list[str] | None = None,
             rutas: Path | None = None) -> dict:
    if ventana_copia_s <= 0 or margen_referencia_s < 0 or max_anomalias < 0:
        raise ValueError("ventanas y máximo de anomalías inválidos")
    cfg, redes = configuracion(rutas)
    redes_poblacion = [ipaddress.ip_network(x) for x in subredes or []]
    ips = set(IP_EXPERIMENTALES) if ips is None and not subredes else set(ips or ())
    def en_poblacion(o, d):
        return o in ips or d in ips or any(ipaddress.ip_address(x) in red for x in (o, d)
                                          for red in redes_poblacion)

    ficheros, inventario, problemas = inventario_entrada(carpeta, inventario)
    por_clave = collections.defaultdict(list)
    por_s = collections.defaultdict(lambda: [0, 0, 0, 0])
    por_10ms = collections.Counter()
    por_vlan, por_vlan_exp = collections.Counter(), collections.Counter()
    total = exp = leidas = 0
    for fichero in ficheros:
        meta = inventario.get(fichero.name, {})
        intervalo = {"primer_paquete_epoch": meta.get("primer_paquete_epoch"),
                     "ultimo_paquete_epoch": meta.get("ultimo_paquete_epoch")}
        if not fichero.exists():
            problemas.append({"tipo": "ausente", "fichero": fichero.name, **intervalo})
            continue
        primero_leido = ultimo_leido = None
        try:
            for ts, orig, d in tramas(fichero):
                primero_leido = ts if primero_leido is None else primero_leido
                ultimo_leido = ts
                leidas += 1
                if (desde is not None and ts < desde) or (hasta is not None and ts > hasta):
                    continue
                total += 1
                dato = identidad(d)
                vlan = dato[0] if dato else None
                es_exp = bool(dato and dato[1] and en_poblacion(dato[2], dato[3]))
                bytes_trama = orig + EXTRA_TRAMA
                s = int(ts)
                por_s[s][0] += 1
                por_s[s][1] += bytes_trama
                por_10ms[int(ts * 100)] += bytes_trama
                por_vlan[str(vlan)] += bytes_trama
                if es_exp:
                    exp += 1
                    por_s[s][2] += 1
                    por_s[s][3] += bytes_trama
                    por_vlan_exp[str(vlan)] += bytes_trama
                    por_clave[dato[1]].append((ts, vlan, dato[4], fichero.name,
                                                dato[5], dato[6], dato[7]))
        except EntradaError as e:
            if intervalo["primer_paquete_epoch"] is None:
                intervalo["primer_paquete_epoch"] = primero_leido
            if intervalo["ultimo_paquete_epoch"] is None:
                intervalo["ultimo_paquete_epoch"] = ultimo_leido
            problemas.append({"tipo": e.tipo, "fichero": fichero.name, "detalle": str(e), **intervalo})

    eventos = []
    for clave, copias in por_clave.items():
        copias.sort()
        grupos = []
        for copia in copias:
            if not grupos or copia[0] - grupos[-1][0][0] > ventana_copia_s:
                grupos.append([copia])
            else:
                grupos[-1].append(copia)
        ambiguos = set()
        for i in range(1, len(grupos)):
            if grupos[i][0][0] - grupos[i - 1][0][0] < 2 * ventana_copia_s:
                ambiguos.update((i - 1, i))
        for i, grupo in enumerate(grupos):
            eventos.append((clave, grupo, i in ambiguos))
    eventos.sort(key=lambda x: x[1][0][0])
    clases = collections.Counter()
    rutas_resumen = collections.defaultdict(collections.Counter)
    faltantes_ruta = collections.defaultdict(collections.Counter)
    por_vlan_faltante = collections.Counter()
    por_segundo = collections.defaultdict(collections.Counter)
    por_fichero = collections.defaultdict(collections.Counter)
    separaciones = []
    anomalías, total_anomalias = [], 0
    indicios = {"ttl_incorrecto": 0, "orden_incorrecto": 0,
                "carga_distinta": 0, "mac_igual": 0}
    marcas_sensor = collections.defaultdict(list)
    for clave, grupo, ambiguo in eventos:
        ts, _, _, fichero, multicast, _, _ = grupo[0]
        marcas_sensor[clave].append(ts)
        etiqueta, esperado, motivo = ruta_esperada(
            clave[1], clave[2], multicast, redes, cfg.get("difusion_multidifusion", "no_determinable"))
        vistos = [x[1] for x in grupo]
        faltan = list((collections.Counter(esperado or []) - collections.Counter(vistos)).elements())
        if ambiguo:
            clase = "ambiguo"
        elif esperado is None:
            clase = "no_determinable"
        elif not esperado:
            clase = "inesperado"
        elif len(grupo) > len(esperado):
            clase = "copias_de_mas"
        elif collections.Counter(vistos) == collections.Counter(esperado):
            clase = "completo"
        elif collections.Counter(vistos) - collections.Counter(esperado):
            clase = "vlan_incorrecta"
        else:
            clase = "falta_copia"
        clases[clase] += 1
        rutas_resumen[etiqueta][clase] += 1
        por_segundo[str(int(ts))][clase] += 1
        por_fichero[fichero][clase] += 1
        if esperado is not None and clase not in ("ambiguo", "no_determinable"):
            por_vlan_faltante.update(map(str, faltan))
            faltantes_ruta[etiqueta].update(map(str, faltan))
        if len(grupo) == 2 and not ambiguo:
            separaciones.append(grupo[1][0] - grupo[0][0])
        if esperado and len(esperado) == 2 and len(grupo) >= 2:
            if grupo[0][2] - grupo[1][2] != 1:
                indicios["ttl_incorrecto"] += 1
            if vistos[:2] != esperado:
                indicios["orden_incorrecto"] += 1
            if grupo[0][5] != grupo[1][5]:
                indicios["carga_distinta"] += 1
            if grupo[0][6] == grupo[1][6]:
                indicios["mac_igual"] += 1
        if clase != "completo":
            total_anomalias += 1
            if len(anomalías) < max_anomalias:
                anomalías.append({"ts": ts, "clase": clase, "ruta": etiqueta,
                                   "fichero": fichero, "vlans_vistas": vistos,
                                   "vlans_esperadas": esperado, "vlans_faltan": faltan,
                                   "motivo": motivo, "identidad": list(clave)})

    referencia_resumen = None
    if referencia:
        ref_claves = collections.defaultdict(list)
        if not referencia.exists():
            problemas.append({"tipo": "ausente", "fichero": str(referencia),
                               "origen": "referencia"})
        else:
            try:
                for ts, _, d in tramas(referencia):
                    dato = identidad(d)
                    if dato and dato[1] and en_poblacion(dato[2], dato[3]):
                        ref_claves[dato[1]].append(ts)
            except EntradaError as e:
                problemas.append({"tipo": e.tipo, "fichero": str(referencia),
                                   "detalle": str(e), "origen": "referencia"})
        sin_copia, ejemplos, ref_total = 0, [], 0
        for clave, tiempos in ref_claves.items():
            tiempos.sort()
            sensor = sorted(marcas_sensor.get(clave, []))
            previo = None
            for ts in tiempos:
                if previo is not None and ts - previo <= ventana_copia_s:
                    continue
                previo = ts
                ref_total += 1
                i = bisect.bisect_left(sensor, ts - margen_referencia_s)
                if i == len(sensor) or sensor[i] > ts + margen_referencia_s:
                    sin_copia += 1
                    if len(ejemplos) < max_anomalias:
                        ejemplos.append({"ts": ts, "identidad": list(clave)})
        referencia_resumen = {"eventos_vistos": ref_total,
                              "eventos_con_copia_sensor": ref_total - sin_copia,
                              "eventos_sin_copia_sensor": sin_copia,
                              "sin_copia_ejemplos": ejemplos}

    pico_s = max(por_s.items(), key=lambda kv: kv[1][1], default=(None, [0, 0, 0, 0]))
    pico_10 = max(por_10ms.items(), key=lambda kv: kv[1], default=(None, 0))
    umbral = LINEA_BPS / 8 / 100
    saturados = sorted(k / 100 for k, v in por_10ms.items() if v >= umbral)
    return {
        "version": 2, "resultado_global": "incompleto" if problemas else "examinado_completo",
        "entrada_completa": not problemas,
        "integridad_entrada": {"problemas": problemas, "ficheros_esperados": len(ficheros),
                               "ficheros_con_problemas": len({x["fichero"] for x in problemas})},
        "parametros": {"carpeta": str(carpeta), "ips": sorted(ips), "subredes": subredes or [],
                       "desde": desde, "hasta": hasta, "ventana_copia_s": ventana_copia_s,
                       "margen_referencia_s": margen_referencia_s, "configuracion": str(rutas or Path(__file__).with_name("rutas_span.json"))},
        "configuracion_espejo": cfg,
        "denominadores": {"tramas_leidas": leidas, "tramas_en_ventana": total,
                          "tramas_en_poblacion": exp,
                          "eventos": len(eventos), "eventos_por_clase": dict(clases)},
        "por_ruta": {k: {"eventos": sum(v.values()), "clases": dict(v),
                        "faltantes_por_vlan": dict(faltantes_ruta[k]),
                        "fraccion_falta_por_vlan": {
                            vlan: n / sum(v.values()) for vlan, n in faltantes_ruta[k].items()}}
                     for k, v in sorted(rutas_resumen.items())},
        "por_vlan_faltante": dict(por_vlan_faltante),
        "eventos_por_segundo": {k: dict(v) for k, v in sorted(por_segundo.items())},
        "eventos_por_fichero": {f.name: {"eventos": sum(por_fichero[f.name].values()),
                                         "clases": dict(por_fichero[f.name])}
                               for f in ficheros},
        "separaciones_copias_s": {"pares": len(separaciones), "p50": percentil(separaciones, .5),
                                 "p99": percentil(separaciones, .99),
                                 "max": max(separaciones, default=None)},
        "indicios": indicios,
        "anomalias_total": total_anomalias, "anomalias": anomalías,
        "referencia": referencia_resumen,
        "limitaciones": ["Un evento ausente en todas sus copias no se detecta sin --referencia.",
                         "La referencia sólo cuenta identidades sin copia dentro del margen temporal; no prueba entrega de otras capas."],
        "bytes_por_vlan": dict(por_vlan.most_common()),
        "bytes_por_vlan_experimental": dict(por_vlan_exp.most_common()),
        "pico_1s": {"s": pico_s[0], "tramas": pico_s[1][0], "bytes": pico_s[1][1],
                    "mbps": round(pico_s[1][1] * 8 / 1e6, 2)},
        "pico_10ms": {"t": pico_10[0] / 100 if pico_10[0] is not None else None,
                      "bytes": pico_10[1],
                      "mbps_equivalentes": round(pico_10[1] * 8 * 100 / 1e6, 1)},
        "intervalos_10ms_a_linea": len(saturados),
        "intervalos_10ms_a_linea_primeros": saturados[:200],
        "por_segundo": {str(k): v for k, v in sorted(por_s.items())},
    }


def detallar(carpeta: Path, ips: set[str], umbral: float, desde=None, hasta=None, maximo=60,
             subredes=None):
    """Desglosa las ráfagas del destino con una segunda lectura en flujo."""
    ficheros, _, _ = inventario_entrada(carpeta, None)
    redes = [ipaddress.ip_network(x) for x in subredes or []]
    carga = collections.Counter()
    for f in ficheros:
        if not f.exists():
            continue
        try:
            for ts, orig, d in tramas(f):
                if (desde is not None and ts < desde) or (hasta is not None and ts > hasta):
                    continue
                carga[int(ts * 100)] += orig + EXTRA_TRAMA
        except EntradaError:
            continue
    elegidos = sorted((k for k, v in carga.items() if v >= umbral), key=lambda k: -carga[k])[:maximo]
    detalle = {k: {"vlan": collections.Counter(), "exp": collections.Counter(),
                   "pares_exp": collections.Counter(), "pares_ajenos": set()} for k in elegidos}
    for f in ficheros:
        if not f.exists():
            continue
        try:
            for ts, orig, d in tramas(f):
                if (desde is not None and ts < desde) or (hasta is not None and ts > hasta):
                    continue
                k = int(ts * 100)
                if k not in detalle:
                    continue
                b = orig + EXTRA_TRAMA
                x = detalle[k]
                r = identidad(d)
                x["vlan"][str(r[0] if r else None)] += b
                es_exp = bool(r and r[1] and
                              (r[2] in ips or r[3] in ips or
                               any(ipaddress.ip_address(ip) in red for ip in (r[2], r[3]) for red in redes)))
                x["exp"]["experimental" if es_exp else "no_experimental"] += b
                if es_exp:
                    x["pares_exp"][f"{r[2]}>{r[3]}"] += b
                elif r and r[1]:
                    x["pares_ajenos"].add((r[2], r[3]))
        except EntradaError:
            continue
    salida = []
    for k in elegidos:
        x = detalle[k]
        salida.append({"t": k / 100, "bytes": carga[k],
                       "mbps_equivalentes": round(carga[k] * 8 * 100 / 1e6, 1),
                       "por_vlan": dict(x["vlan"].most_common()), "por_tipo": dict(x["exp"]),
                       "pares_experimentales": dict(x["pares_exp"].most_common(5)),
                       "pares_ajenos_distintos": len(x["pares_ajenos"])})
    return salida


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("carpeta", type=Path)
    ap.add_argument("--salida", type=Path, required=True)
    poblacion = ap.add_mutually_exclusive_group()
    poblacion.add_argument("--ips", help="IP separadas por coma")
    poblacion.add_argument("--subredes", help="CIDR separados por coma")
    ap.add_argument("--desde", type=float)
    ap.add_argument("--hasta", type=float)
    ap.add_argument("--ventana-copia-s", type=float, default=.005)
    ap.add_argument("--inventario", type=Path)
    ap.add_argument("--referencia", type=Path)
    ap.add_argument("--margen-referencia-s", type=float, default=.005)
    ap.add_argument("--max-anomalias", type=int, default=20000)
    ap.add_argument("--detalle-umbral", type=float, default=.5)
    a = ap.parse_args(argv)
    ips = set(a.ips.split(",")) if a.ips else None
    subredes = a.subredes.split(",") if a.subredes else None
    resultado = analizar(a.carpeta, ips, a.desde, a.hasta, a.ventana_copia_s,
                         a.inventario, a.referencia, a.margen_referencia_s,
                         a.max_anomalias, subredes)
    if a.detalle_umbral > 0:
        ips_detalle = ips if ips is not None else (set() if subredes else set(IP_EXPERIMENTALES))
        resultado["detalle_10ms"] = detallar(a.carpeta, ips_detalle,
                                             a.detalle_umbral * LINEA_BPS / 8 / 100,
                                             a.desde, a.hasta, subredes=subredes)
        resultado["intervalos_10ms_sobre_umbral_detalle"] = len(resultado["detalle_10ms"])
    a.salida.write_text(json.dumps(resultado, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"resultado_global": resultado["resultado_global"],
                      "denominadores": resultado["denominadores"],
                      "integridad_entrada": resultado["integridad_entrada"]}, ensure_ascii=False))
    return 0 if resultado["entrada_completa"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
