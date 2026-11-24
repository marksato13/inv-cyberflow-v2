#!/usr/bin/env python3
"""Extracción V2 en ventanas a partir de un archivo de captura."""
# derivado de origen_v1/scripts/features/extract_multilayer_v2.py y
# origen_v1/scripts/features/extract_multilayer_v3.py @ d2c9772;
# cambios: filtro por paquete, lectura incremental, marcas e inventario.
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import pickle
import sqlite3
import sys
import tempfile
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "origen_v1" / "scripts" / "features"))
import extract_multilayer_v2 as v2  # noqa: E402
import extract_multilayer_v3 as v3  # noqa: E402

DEFAULT_POPULATION = tuple(f"10.10.20.{i}" for i in range(21, 27))
CONTROL = ("ejecucion", "ip", "ventana_inicio", "ventana_fin", "bloque",
           "motivo_marca", "n_paquetes_ventana", "n_eventos_l7_ventana")
FIELDS = CONTROL + v2.FEATURE_NAMES
GESTION = {"10.10.10.30", "10.10.20.20", "10.10.20.30"}
SERVICIOS = {"10.10.30.10", "10.10.10.20"}


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def poblacion_desde(path: Path | None) -> set[str]:
    if path is None:
        return set(DEFAULT_POPULATION)
    contenido = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        datos = json.loads(contenido)
        if isinstance(datos, dict):
            datos = datos.get("ips", datos.get("poblacion"))
    else:
        datos = [campo for fila in csv.reader(contenido.splitlines()) for campo in fila]
    if not isinstance(datos, list):
        raise ValueError("--poblacion debe contener una lista de IP")
    ips = {str(ipaddress.IPv4Address(str(x).strip())) for x in datos if str(x).strip()}
    if not ips:
        raise ValueError("población vacía")
    return ips


def fronteras_desde(path: Path | None) -> list[float]:
    if path is None:
        return []
    contenido = path.read_text(encoding="utf-8")
    datos = json.loads(contenido) if path.suffix.lower() == ".json" else contenido.replace(",", "\n").splitlines()
    if isinstance(datos, dict):
        datos = datos["fronteras"]
    return sorted({float(x) if isinstance(x, (int, float)) else v2.parse_eve_timestamp(str(x).strip())
                   for x in datos if str(x).strip()})


def _clave_pcap(p: Path) -> str:
    return p.name[:-3] if p.name.endswith(".gz") else p.name


def rutas_pcap(archivo: Path) -> list[Path]:
    """PCAP archivados, sin comprimir o en .pcap.gz (el archivador comprime por omisión)."""
    raiz = archivo / "pcap" if (archivo / "pcap").is_dir() else archivo
    rutas = sorted([*raiz.glob("live-*.pcap"), *raiz.glob("live-*.pcap.gz")], key=_clave_pcap)
    if not rutas:
        raise ValueError(f"sin live-*.pcap[.gz] en {raiz}")
    claves = [_clave_pcap(p) for p in rutas]
    if len(set(claves)) != len(claves):
        raise ValueError("el mismo PCAP aparece comprimido y sin comprimir; revisar el archivado")
    return rutas


def iter_tramas(path: Path):
    """Igual que v2.iter_pcap_frames, pero acepta .pcap.gz sin descomprimir a disco."""
    if not path.name.endswith(".gz"):
        yield from v2.iter_pcap_frames(path)
        return
    import gzip
    import struct
    with gzip.open(path, "rb") as handle:
        endian, divisor = v2._pcap_format(handle.read(4))
        resto = handle.read(20)
        if len(resto) != 20:
            raise ValueError(f"cabecera PCAP truncada: {path}")
        if struct.unpack(f"{endian}HHIIII", resto)[5] != 1:
            raise ValueError(f"solo Ethernet LINKTYPE 1 está soportado: {path}")
        registro = struct.Struct(f"{endian}IIII")
        while True:
            cab = handle.read(registro.size)
            if not cab:
                break
            if len(cab) != registro.size:
                raise ValueError(f"registro PCAP truncado: {path}")
            seg, frac, cap, _ = registro.unpack(cab)
            trama = handle.read(cap)
            if len(trama) != cap:
                raise ValueError(f"paquete PCAP truncado: {path}")
            yield seg + frac / divisor, trama


def leer_eve(archivo: Path):
    anterior = float("-inf")
    for path in sorted((archivo / "eve").glob("eve-*.json")):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                evento = json.loads(line)
                if evento.get("event_type") in {"http", "dns", "tls"} and evento.get("timestamp"):
                    ts = v2.parse_eve_timestamp(evento["timestamp"])
                    if ts < anterior:
                        raise ValueError("EVE fuera de orden temporal")
                    anterior = ts
                    yield ts, line, evento


def leer_contextos_crudos(rutas, inventario):
    """Lee fichero a fichero y registra todas las IP antes de deduplicar."""
    anterior = float("-inf")
    for path in rutas:
        for ts, frame in iter_tramas(path):
            if ts < anterior:
                raise ValueError("PCAP fuera de orden temporal; ordenar los originales antes de extraer")
            anterior = ts
            ctx = v3.parse_con_contexto(ts, frame)
            if ctx is None:
                continue
            p = ctx.packet
            for ip, peer in ((p.src_ip, p.dst_ip), (p.dst_ip, p.src_ip)):
                item = inventario.setdefault(ip, {"paquetes": 0, "bytes_ip": 0, "vlan": set(),
                                               "primero": ts, "ultimo": ts, "interlocutores": Counter()})
                item["paquetes"] += 1
                item["bytes_ip"] += p.ip_length
                item["vlan"].add(ctx.vlan)
                item["primero"] = min(item["primero"], ts)
                item["ultimo"] = max(item["ultimo"], ts)
                item["interlocutores"][peer] += 1
            yield ctx


def finalizar_pendientes(pendientes, corte, cuentas, fronteras=()):
    """Cierra copias anteriores a corte, dejando 5 ms de solape."""
    if not pendientes or pendientes[0].packet.timestamp >= corte:
        return [], pendientes
    por_bloque = {}
    for ctx in pendientes:
        bloque = sum(f <= ctx.packet.timestamp for f in fronteras)
        por_bloque.setdefault(bloque, []).append(ctx)
    conservados = []
    for grupo in por_bloque.values():
        conservados.extend(v3.deduplicar_espejo(grupo)[0])
    ids = {id(p) for p in conservados}
    terminados, siguientes = [], []
    for item in pendientes:
        if id(item.packet) not in ids:
            cuentas["copias_espejo_quitadas"] += 1
        elif item.packet.timestamp < corte:
            terminados.append(item.packet)
        else:
            siguientes.append(item)
    return terminados, siguientes


def marcar(anchor, inicio, fronteras):
    bloque = sum(f <= anchor for f in fronteras)
    piso = max([inicio] + [f for f in fronteras if f <= anchor])
    motivos = []
    if anchor - inicio < 60:
        motivos.append("arranque")
    if any(anchor - 60 < f <= anchor for f in fronteras):
        motivos.append("frontera")
    return bloque, ",".join(motivos), piso


def clave_secuencia(p):
    return repr((p.protocol, p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.tcp_seq))


def atribuir_con_estado(paquetes, estado, piso, anchor, bloque):
    """Usa V1 con sus antecedentes mínimos, persistidos fuera de RAM."""
    semillas = {}
    for p in paquetes:
        flujo = repr((bloque, v2.canonical_flow_key(p)))
        fila = estado.execute("SELECT ts, dato FROM flujos WHERE clave=?", (flujo,)).fetchone()
        if fila and fila[0] < max(anchor - 60, piso):
            previo = pickle.loads(fila[1])
            semillas[(flujo, "primero")] = previo
        if p.protocol == 6 and p.tcp_payload_length > 0:
            clave_seq = repr((bloque, clave_secuencia(p)))
            fila = estado.execute("SELECT ts, dato FROM secuencias WHERE clave=?", (clave_seq,)).fetchone()
            if fila and fila[0] < max(anchor - 60, piso):
                semillas[(clave_seq, "secuencia")] = pickle.loads(fila[1])
    # La identidad evita introducir dos veces el mismo paquete histórico.
    previos = list({(p.timestamp, repr(p)): p for p in semillas.values()}.values())
    observaciones = v2.attribute_packets(previos + list(paquetes), ipaddress.ip_network("0.0.0.0/0"))
    return [o for o in observaciones if o.timestamp > anchor - 60 and o.timestamp >= piso]


def procesar(archivo: Path, salida: Path, poblacion: set[str], fronteras: list[float]) -> dict:
    rutas = rutas_pcap(archivo)
    salida.mkdir(parents=True, exist_ok=True)
    inventario = {}
    cuentas = Counter()
    p_iter = iter(leer_contextos_crudos(rutas, inventario))
    e_iter = iter(leer_eve(archivo))
    p_next = next(p_iter, None)
    e_next = next(e_iter, None)
    if p_next is None and e_next is None:
        raise ValueError("archivo sin observaciones IPv4 ni EVE")
    inicio = min(x for x in (p_next.packet.timestamp if p_next else None, e_next[0] if e_next else None) if x is not None)
    anchor = (math.floor(inicio / 10) + 1) * 10
    contextos = deque()
    pendientes = []
    eventos = deque()
    vistos = set()
    ultimos = {}
    filas_temporales = salida / ".filas-v2.jsonl"
    estado_path = salida / ".estado-v2.sqlite"
    if estado_path.exists():
        estado_path.unlink()
    estado = sqlite3.connect(estado_path)
    estado.execute("CREATE TABLE flujos (clave TEXT PRIMARY KEY, ts REAL, dato BLOB)")
    estado.execute("CREATE TABLE secuencias (clave TEXT PRIMARY KEY, ts REAL, dato BLOB)")

    def registrar_finalizados(terminados):
        for p in terminados:
            if p.src_ip not in poblacion and p.dst_ip not in poblacion:
                cuentas["paquetes_descartados_poblacion"] += 1
                continue
            cuentas["paquetes_incluidos"] += 1
            dato = pickle.dumps(p, protocol=pickle.HIGHEST_PROTOCOL)
            bloque_p = sum(f <= p.timestamp for f in fronteras)
            estado.execute("INSERT OR IGNORE INTO flujos VALUES (?,?,?)",
                           (repr((bloque_p, v2.canonical_flow_key(p))), p.timestamp, dato))
            if p.protocol == 6 and p.tcp_payload_length > 0:
                estado.execute("INSERT OR IGNORE INTO secuencias VALUES (?,?,?)",
                               (repr((bloque_p, clave_secuencia(p))), p.timestamp, dato))

    with filas_temporales.open("w", encoding="utf-8") as tmp:
        while p_next is not None or e_next is not None:
            # Se procesa un ancla por vez; el buffer conserva sólo la historia de 60 s.
            while p_next is not None and p_next.packet.timestamp <= anchor:
                contextos.append(p_next)
                pendientes.append(p_next)
                p_next = next(p_iter, None)
            terminados, pendientes = finalizar_pendientes(pendientes, anchor - 0.005, cuentas, fronteras)
            registrar_finalizados(terminados)
            while e_next is not None and e_next[0] <= anchor:
                ts, line, ev = e_next
                if ev.get("src_ip") in poblacion or ev.get("dest_ip") in poblacion:
                    eventos.append((ts, line))
                    cuentas["eventos_incluidos"] += 1
                else:
                    cuentas["eventos_descartados_poblacion"] += 1
                e_next = next(e_iter, None)
            bloque, motivo, piso = marcar(anchor, inicio, fronteras)
            while contextos and (contextos[0].packet.timestamp < anchor - 60 - 0.005 or
                                 contextos[0].packet.timestamp < piso):
                contextos.popleft()
            while eventos and (eventos[0][0] <= anchor - 60 or eventos[0][0] < piso):
                eventos.popleft()
            # La atribución y las 28 fórmulas son exactamente las de V1.
            deduplicados, _ = v3.deduplicar_espejo(list(contextos))
            paquetes = [p for p in deduplicados if p.timestamp > anchor - 60 and p.timestamp >= piso
                        and (p.src_ip in poblacion or p.dst_ip in poblacion)]
            observaciones = atribuir_con_estado(paquetes, estado, piso, anchor, bloque)
            observaciones = [o for o in observaciones if o.entity_ip in poblacion]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8", dir=salida, delete=False) as ef:
                ef.writelines(line for _, line in eventos)
                eve_tmp = Path(ef.name)
            try:
                apps = [a for a in v2.load_app_observations(eve_tmp, ipaddress.ip_network("0.0.0.0/0"))
                        if a.entity_ip in poblacion]
            finally:
                eve_tmp.unlink()
            for item in observaciones + apps:
                vistos.add(item.entity_ip)
                ultimos[item.entity_ip] = max(ultimos.get(item.entity_ip, 0), item.timestamp)
            # build_rows sólo recibe observaciones visibles hasta este cierre.
            if observaciones or apps:
                base = v2.build_rows(archivo.name, observaciones, apps, capture_start=min(inicio, piso))
                por_ip = {(r["entity_ip"], r["window_end_utc"]): r for r in base}
            else:
                por_ip = {}
            for ip in sorted(vistos):
                r = por_ip.get((ip, utc(anchor)))
                if r is None:
                    # Entre la primera y la última observación V1 emite 28 ceros
                    # incluso cuando ya no queda tráfico en los 60 s previos.
                    r = dict.fromkeys(v2.FEATURE_NAMES, 0.0)
                fila = {"ejecucion": archivo.name, "ip": ip,
                        "ventana_inicio": utc(anchor - 10), "ventana_fin": utc(anchor),
                        "bloque": bloque, "motivo_marca": motivo,
                        "n_paquetes_ventana": sum(o.entity_ip == ip and v2.in_window(o.timestamp, anchor, 10) for o in observaciones),
                        "n_eventos_l7_ventana": sum(a.entity_ip == ip and v2.in_window(a.timestamp, anchor, 10) for a in apps)}
                fila.update({name: r[name] for name in v2.FEATURE_NAMES})
                tmp.write(json.dumps(fila, allow_nan=True) + "\n")
            anchor += 10
    terminados, _ = finalizar_pendientes(pendientes, float("inf"), cuentas, fronteras)
    registrar_finalizados(terminados)
    with (salida / "filas.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        with filas_temporales.open(encoding="utf-8") as tmp:
            for line in tmp:
                row = json.loads(line)
                if v2.parse_eve_timestamp(row["ventana_fin"]) <= math.ceil(ultimos[row["ip"]] / 10) * 10:
                    writer.writerow(row)
                    cuentas["filas"] += 1
    filas_temporales.unlink()
    estado.close()
    estado_path.unlink()
    inventario_out = []
    for ip, item in sorted(inventario.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        if ip in poblacion:
            regla = "poblacion"
        elif ip in GESTION:
            regla = "gestion_excluida"
        elif ip in SERVICIOS and any(peer in poblacion for peer in item["interlocutores"]):
            regla = "respuesta_servicio_a_poblacion"
        else:
            regla = "otra_excluida"
        inventario_out.append({"ip": ip, "regla": regla, "paquetes": item["paquetes"],
                               "bytes_ip": item["bytes_ip"], "vlan": sorted(item["vlan"]),
                               "primero_utc": utc(item["primero"]), "ultimo_utc": utc(item["ultimo"]),
                               "interlocutores_principales": item["interlocutores"].most_common(5)})
    (salida / "inventario_ips.json").write_text(json.dumps(inventario_out, indent=2, ensure_ascii=False), encoding="utf-8")
    resumen = dict(cuentas)
    resumen.update({"ejecucion": archivo.name, "poblacion": sorted(poblacion), "fronteras_utc": [utc(f) for f in fronteras],
                    "pcap_ficheros": len(rutas), "paso_s": 10, "historia_maxima_s": 60})
    (salida / "resumen.json").write_text(json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8")
    return resumen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archivo", type=Path, help="capturas/<ID>")
    ap.add_argument("--salida", type=Path, required=True)
    ap.add_argument("--poblacion", type=Path)
    ap.add_argument("--fronteras", type=Path)
    args = ap.parse_args()
    print(json.dumps(procesar(args.archivo, args.salida, poblacion_desde(args.poblacion),
                              fronteras_desde(args.fronteras)), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
