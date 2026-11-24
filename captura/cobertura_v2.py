#!/usr/bin/env python3
"""Cruza el registro de transacciones del generador V2 con el PCAP y el EVE archivados.

Comprueba, para una ejecución:
* cobertura de peticiones: cada transacción TCP tiene su SYN (origen_ip, origen_puerto, destino),
  cada DNS su consulta UDP (origen_ip, origen_puerto) y cada ping un eco en ±2 s;
* captura de respuestas: SYN-ACK del servidor, respuestas DNS y respuestas ICMP;
* desfase aparente reloj Clientes → reloj Sensor1: SYN.ts − inicio_utc (incluye latencia de pila);
* EVE: eventos por tipo para las IP de la ejecución, rcode DNS y códigos HTTP frente al registro.

Solo lee. Usa ``tcpdump -r`` (no necesita privilegios para leer ficheros).

    python3 cobertura_v2.py --capturas DIR --transacciones T1.jsonl [T2.jsonl ...] --salida informe.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

RE_TCP = re.compile(r"^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[(\S+)\]")
RE_UDP = re.compile(r"^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): ")
RE_ICMP = re.compile(r"^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP echo (request|reply)")


def epoch(utc: str) -> float:
    return datetime.datetime.fromisoformat(utc.replace("Z", "+00:00")).timestamp()


def cercano(lista: list[float] | None, t0: float, tolerancia: float = 5.0) -> float | None:
    """Marca de la copia más próxima a t0 dentro de la tolerancia (s)."""
    if not lista:
        return None
    ts = min(lista, key=lambda x: abs(x - t0))
    return ts if abs(ts - t0) <= tolerancia else None


def leer_pcap(ficheros: list[Path], red: str) -> dict:
    filtro = ("(src net {r} and ((tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn or udp dst port 53 or icmp[icmptype] == icmp-echo))"
              " or (dst net {r} and ((tcp[tcpflags] & (tcp-syn|tcp-ack)) == (tcp-syn|tcp-ack) or (tcp[tcpflags] & tcp-rst) != 0"
              " or udp src port 53 or icmp[icmptype] == icmp-echoreply))").format(r=red)
    # El espejo llega con etiquetas 802.1Q (comprobado 24-nov): sin 'vlan' el filtro BPF no ve nada.
    filtro = "vlan and (%s)" % filtro
    syn, synack, rst, dnsq, dnsr, eco, ecor = {}, set(), set(), {}, set(), [], []
    copias_syn = Counter()
    for f in ficheros:
        out = subprocess.run(["tcpdump", "-nn", "-tt", "-r", str(f), filtro], capture_output=True, text=True).stdout
        for l in out.splitlines():
            m = RE_TCP.match(l)
            if m:
                ts, s, sp, d, dp, fl = m.groups()
                if fl == "S":
                    # Lista: el mismo puerto efímero puede reutilizarse en la ejecución.
                    syn.setdefault((s, int(sp), d, int(dp)), []).append(float(ts))
                    copias_syn[(s, int(sp), d, int(dp))] += 1
                elif "S" in fl:
                    synack.add((d, int(dp), s, int(sp)))
                elif "R" in fl:
                    rst.add((d, int(dp), s, int(sp)))
                continue
            m = RE_ICMP.match(l)
            if m:
                ts, s, d, k = m.groups()
                (eco if k == "request" else ecor).append((s if k == "request" else d, float(ts)))
                continue
            m = RE_UDP.match(l)
            if m:
                ts, s, sp, d, dp = m.groups()
                if dp == "53":
                    dnsq.setdefault((s, int(sp)), []).append(float(ts))
                elif sp == "53":
                    dnsr.add((d, int(dp)))
    return {"syn": syn, "synack": synack, "rst": rst, "dnsq": dnsq, "dnsr": dnsr, "eco": eco, "ecor": ecor,
            "copias_syn": Counter(copias_syn.values())}


RE_SEQ = re.compile(r"^\S+ IP (\S+) > (\S+): Flags \[[^\]]*\], seq (\d+):(\d+),.* length (\d+)")


def carga_servidor(ficheros: list[Path], red: str, servidor: str) -> int:
    """Bytes de carga TCP servidor→clientes en el PCAP, sin las copias del espejo (C7)."""
    vistos = set()
    total = 0
    for f in ficheros:
        out = subprocess.run(["tcpdump", "-nn", "-tt", "-S", "-r", str(f),
                              "vlan and src host %s and dst net %s and tcp" % (servidor, red)],
                             capture_output=True, text=True).stdout
        for l in out.splitlines():
            m = RE_SEQ.match(l)
            if m:
                k = m.groups()[:4]
                if k not in vistos:
                    vistos.add(k)
                    total += int(m.group(5))
    return total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capturas", required=True)
    ap.add_argument("--transacciones", nargs="+", required=True)
    ap.add_argument("--red", default="10.10.20.16/28", help="red de los alias de los perfiles")
    ap.add_argument("--salida", required=True)
    a = ap.parse_args()
    cap = Path(a.capturas)
    txs = [json.loads(l) for f in a.transacciones for l in open(f, encoding="utf-8") if l.strip()]
    pc = leer_pcap(sorted((cap / "pcap").glob("live-*.pcap")), a.red)
    res = defaultdict(Counter)
    desfases = []
    faltan = []
    for t in txs:
        proto, acc = t.get("protocolo"), t["accion"]
        k = res[acc]
        k["transacciones"] += 1
        if t.get("origen_puerto") is None and proto != "icmp":
            k["sin_puerto_registrado"] += 1
            continue
        if proto in ("http", "https", "tcp"):
            clave = (t["origen_ip"], t["origen_puerto"], t["destino_ip"], t["destino_puerto"])
            ts = cercano(pc["syn"].get(clave), epoch(t["inicio_utc"]))
            if ts is None:
                k["peticion_no_vista"] += 1
                faltan.append(t["transaccion_id"])
                continue
            k["peticion_vista"] += 1
            desfases.append(ts - epoch(t["inicio_utc"]))
            if clave in pc["synack"]:
                k["respuesta_synack"] += 1
            if clave in pc["rst"]:
                k["respuesta_rst"] += 1
        elif proto == "dns":
            clave = (t["origen_ip"], t["origen_puerto"])
            ts = cercano(pc["dnsq"].get(clave), epoch(t["inicio_utc"]))
            if ts is None:
                k["peticion_no_vista"] += 1
                faltan.append(t["transaccion_id"])
                continue
            k["peticion_vista"] += 1
            desfases.append(ts - epoch(t["inicio_utc"]))
            if clave in pc["dnsr"]:
                k["respuesta_dns"] += 1
        elif proto == "icmp":
            t0 = epoch(t["inicio_utc"])
            if any(ip == t["origen_ip"] and abs(ts - t0) < 2 for ip, ts in pc["eco"]):
                k["peticion_vista"] += 1
            else:
                k["peticion_no_vista"] += 1
                faltan.append(t["transaccion_id"])
            if any(ip == t["origen_ip"] and abs(ts - t0) < 4 for ip, ts in pc["ecor"]):
                k["respuesta_icmp"] += 1
    # EVE
    ips = {t["origen_ip"] for t in txs}
    tipos, rcodes, http_cmp, tls_ver = Counter(), Counter(), Counter(), Counter()
    por_puerto = {(t["origen_ip"], t.get("origen_puerto")): t for t in txs}
    for f in (cap / "eve").glob("eve-*.json"):
        for l in open(f, encoding="utf-8", errors="replace"):
            try:
                e = json.loads(l)
            except ValueError:
                tipos["linea_invalida"] += 1
                continue
            if e.get("src_ip") not in ips and e.get("dest_ip") not in ips:
                continue
            tipos[e.get("event_type")] += 1
            if e.get("event_type") == "dns" and e["dns"].get("type") == "answer":
                rcodes[e["dns"].get("rcode")] += 1
            if e.get("event_type") == "tls":
                tls_ver[e["tls"].get("version")] += 1
            if e.get("event_type") == "http":
                t = por_puerto.get((e.get("src_ip"), e.get("src_port")))
                st = e["http"].get("status")
                if t is None:
                    http_cmp["sin_transaccion"] += 1
                elif st == t.get("http_codigo"):
                    http_cmp["coincide"] += 1
                else:
                    http_cmp["difiere"] += 1
    servidor = next((t["destino_ip"] for t in txs if t.get("protocolo") in ("http", "https")), None)
    rx_registro = sum(t.get("bytes_recibidos") or 0 for t in txs if t.get("protocolo") in ("http", "https"))
    rx_pcap = carga_servidor(sorted((cap / "pcap").glob("live-*.pcap")), a.red, servidor) if servidor else 0
    total = sum(c["transacciones"] for c in res.values())
    vistas = sum(c["peticion_vista"] for c in res.values())
    informe = {
        "capturas": str(cap), "transacciones": total, "peticiones_vistas": vistas,
        "cobertura_peticiones": round(vistas / total, 6) if total else None,
        "por_accion": {k: dict(v) for k, v in sorted(res.items())},
        "transacciones_no_vistas": faltan[:50],
        "carga_servidor_a_clientes": {"registro_bytes_recibidos_aplicacion": rx_registro, "pcap_bytes_tcp_sin_copias": rx_pcap,
                                      "fraccion": round(rx_pcap / rx_registro, 6) if rx_registro else None,
                                      "nota": "HTTPS añade cabeceras TLS: la fracción puede superar 1 ligeramente"},
        "copias_por_syn_en_espejo": {str(k): v for k, v in sorted(pc["copias_syn"].items())},
        "desfase_aparente_s": {"n": len(desfases), "mediana": statistics.median(desfases) if desfases else None,
                               "min": min(desfases) if desfases else None, "max": max(desfases) if desfases else None,
                               "nota": "SYN visto en Sensor1 menos inicio_utc en Clientes: desfase de relojes + latencia de pila/red"},
        "eve_eventos_por_tipo": dict(tipos), "eve_dns_rcode_respuestas": dict(rcodes),
        "eve_tls_version": dict(tls_ver), "eve_http_vs_registro": dict(http_cmp),
    }
    Path(a.salida).write_text(json.dumps(informe, indent=1, sort_keys=True, ensure_ascii=False))
    print(json.dumps({k: informe[k] for k in ("transacciones", "peticiones_vistas", "cobertura_peticiones", "desfase_aparente_s",
                                              "carga_servidor_a_clientes",
                                              "copias_por_syn_en_espejo", "transacciones_no_vistas", "por_accion",
                                              "eve_eventos_por_tipo", "eve_dns_rcode_respuestas", "eve_tls_version",
                                              "eve_http_vs_registro")}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
