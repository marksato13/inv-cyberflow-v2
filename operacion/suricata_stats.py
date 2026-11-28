#!/usr/bin/env python3
"""Contadores de captura de Suricata (capture.kernel_packets / kernel_drops) desde los eventos `stats`
de la EVE dedicada de V2 (/var/log/suricata/v2/eve.json, copiada por el archivador en
capturas/<ID>/eve/).

Por qué de la EVE y no de stats.log: stats.log tiene `null-values` en su valor por omisión (no) y
OMITE los contadores que valen 0; la EVE sí los escribe. «No aparece en stats.log» significaba «vale
0», no «no se mide» (Bloque 1, revisión 5).

Estados (nunca se sustituye un dato ausente por cero; ver evaluar() para la precedencia):
  perdida                aumento de kernel_drops dentro del periodo (fallo)
  reinicio               uptime discontinuo o contadores que retroceden (fallo)
  perdida_no_localizada  aumento solo en intervalos que cruzan un borde (sin decidir)
  ausente                alguna muestra sin capture.kernel_drops (sin decidir)
  insuficiente           sin acotar, huecos > 16 s, una sola muestra o sin uptime (sin decidir)
  sin_eventos            ningún evento stats
  presente               acotado, continuo y Δ 0 (aprobado)
La lectura fallida (no se pudo leer la EVE) la registra quien lee: vigia_v2 (eve_error) o
revisar_criterios (fichero ausente => sin_eventos con falta de evidencia).

    python3 suricata_stats.py extraer EVE... --salida suricata-stats-<ID>.jsonl
    python3 suricata_stats.py ventana /var/log/suricata/v2/eve.json --desde E --hasta E --salida F
    python3 suricata_stats.py evaluar FICHERO... [--desde E --hasta E]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import heapq
import json
import sys
import time
from pathlib import Path

INTERVALO_STATS_S = 8           # stats.interval de /etc/suricata/suricata.yaml en Sensor1
# Suficiencia temporal (revisión 6). kernel_drops es acumulado: el Δ entre dos muestras cuenta todo lo
# descartado entre ellas, pero NADA de lo que ocurra antes de la primera o después de la última. Por
# eso un periodo [inicio, fin] solo queda certificado si:
#  - hay una muestra en o antes de `inicio` y otra en o después de `fin` (lo acotan; una sola muestra,
#    o solo muestras interiores, dejan los bordes sin observar => «insuficiente», nunca 0);
#  - entre muestras consecutivas no hay más de HUECO_MAXIMO_S. Suricata escribe cada 8 s; en las 41 h
#    de la EVE dedicada (19 742 muestras, 25–26 nov) el intervalo máximo fue 8,0 s. Se tolera una
#    escritura retrasada (2 intervalos); más indica que la salida de stats se detuvo y no se puede
#    afirmar continuidad;
#  - el uptime avanza como el reloj (|Δuptime − Δt| ≤ TOLERANCIA_UPTIME_S; uptime va en segundos
#    enteros): si no, el proceso se reinició aunque el uptime nuevo no sea menor que el anterior.
# El Δ se mide entre las muestras que acotan el periodo: puede incluir hasta un intervalo fuera de él
# en cada extremo, lo que solo puede atribuir de más, nunca ocultar.
HUECO_MAXIMO_S = 2 * INTERVALO_STATS_S
TOLERANCIA_UPTIME_S = 2.0
# Antigüedad admisible de la lectura del vigía: dos intervalos más la latencia de ssh + tail (≤ 4 s).
ANTIGUEDAD_MAXIMA_S = 2 * INTERVALO_STATS_S + 4

def epoch(ts: str) -> float:
    ts = ts.replace("Z", "+00:00")
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return dt.datetime.fromisoformat(ts).timestamp()


def eventos_stats(rutas, desde: float | None = None, hasta: float | None = None) -> list[dict]:
    """Eventos stats de uno o varios EVE/JSONL, en orden de timestamp. Líneas ilegibles se ignoran
    (la EVE puede cortarse a mitad de línea en la copia del archivador).

    Con desde/hasta solo se GUARDAN los de [desde, hasta] (rev. 8): la EVE dedicada no rota y
    guardarlos todos para filtrar después llevaba el proceso a 1,04 GB con 449 MB de EVE."""
    ev = []
    for r in rutas:
        with open(r, encoding="utf-8", errors="replace") as f:
            for linea in f:
                if '"stats"' not in linea:
                    continue
                try:
                    e = json.loads(linea)
                except ValueError:
                    continue
                if e.get("event_type") == "stats" and isinstance(e.get("stats"), dict):
                    if desde is not None or hasta is not None:
                        t = epoch(e["timestamp"])
                        if (desde is not None and t < desde) or (hasta is not None and t > hasta):
                            continue
                    ev.append(e)
    ev.sort(key=lambda e: epoch(e["timestamp"]))
    return ev


class _Desordenados(Exception):
    """Un EVE no está en orden temporal; ventana() vuelve al ordenamiento anterior."""


def _eventos_ordenados(ruta, desde, hasta):
    anterior = None
    with open(ruta, encoding="utf-8", errors="replace") as f:
        for linea in f:
            if '"stats"' not in linea:
                continue
            try:
                e = json.loads(linea)
            except ValueError:
                continue
            if e.get("event_type") != "stats" or not isinstance(e.get("stats"), dict):
                continue
            t = epoch(e["timestamp"])
            if anterior is not None and t < anterior:
                raise _Desordenados(ruta)
            anterior = t
            if desde <= t <= hasta:
                yield t, e


def lectura(e: dict) -> dict:
    """Un evento stats -> los campos que importan, con None cuando faltan (no 0)."""
    s = e.get("stats") or {}
    cap = s.get("capture")
    cap = cap if isinstance(cap, dict) else {}
    return {"timestamp": e.get("timestamp"), "uptime": s.get("uptime"),
            "kernel_packets": cap.get("kernel_packets"), "kernel_drops": cap.get("kernel_drops"),
            "errors": cap.get("errors")}


def evaluar(eventos: list[dict], desde: float | None = None, hasta: float | None = None) -> dict:
    """Estado de kernel_drops en [desde, hasta], por intervalos entre muestras consecutivas (rev. 7).

    Cada intervalo [t_i, t_i+1] de las muestras usadas (de la última en o antes de `desde` a la primera
    en o después de `hasta`) se clasifica:
      - atribuible: está entero dentro de [desde, hasta]; lo que aumente kernel_drops ocurrió en el
        periodo;
      - ampliado: cruza un borde; un aumento solo se localiza en el intervalo exterior ampliado, no
        necesariamente en el periodo.
    Un aumento de kernel_drops entre dos muestras es pérdida DEMOSTRADA en ese intervalo aunque falte
    continuidad u otra evidencia: si el proceso se hubiera reiniciado, el contador nuevo también cuenta
    descartes de dentro del intervalo.

    Precedencia (el fallo manda sobre la falta de evidencia):
      perdida               aumento en un intervalo atribuible                       -> fallo
      reinicio              uptime discontinuo o contadores que retroceden          -> fallo
      perdida_no_localizada solo aumentos en intervalos ampliados                    -> sin decidir
      ausente               alguna muestra sin kernel_drops/kernel_packets           -> sin decidir
      insuficiente          sin acotar, huecos > HUECO_MAXIMO_S, una sola muestra o
                            sin uptime (continuidad no verificable)                  -> sin decidir
      presente              acotado, continuo, sin huecos y Δ 0                       -> aprobado
    """
    L = sorted((lectura(e) for e in eventos), key=lambda x: epoch(x["timestamp"]))
    r = {"eventos": len(L), "intervalo_stats_s": INTERVALO_STATS_S, "hueco_maximo_admitido_s": HUECO_MAXIMO_S,
         "periodo": [desde, hasta]}
    if not L:
        r.update(estado="sin_eventos", delta_kernel_drops=None)
        return r
    acotado = False
    if desde is not None and hasta is not None:
        antes = [i for i, x in enumerate(L) if epoch(x["timestamp"]) <= desde]
        despues = [i for i, x in enumerate(L) if epoch(x["timestamp"]) >= hasta]
        a = antes[-1] if antes else 0
        b = despues[0] if despues else len(L) - 1
        r["muestra_antes_s"] = round(desde - epoch(L[antes[-1]]["timestamp"]), 3) if antes else None
        r["muestra_despues_s"] = round(epoch(L[despues[0]]["timestamp"]) - hasta, 3) if despues else None
        L = L[a:b + 1]
        r["eventos_usados"] = len(L)
        acotado = bool(antes) and bool(despues)
    r["primero"], r["ultimo"] = L[0]["timestamp"], L[-1]["timestamp"]
    t = [epoch(x["timestamp"]) for x in L]
    r["hueco_maximo_s"] = round(max((y - x for x, y in zip(t, t[1:])), default=0), 3)
    huecos, reinicios, sin_uptime, ausentes, con_perdida = [], [], [], [], []
    atrib = ampl = 0
    for x in L:
        if x["kernel_drops"] is None or x["kernel_packets"] is None:
            ausentes.append(x["timestamp"])
        if not isinstance(x["uptime"], (int, float)):
            sin_uptime.append(x["timestamp"])
    for i in range(len(L) - 1):
        x, y, dt_ = L[i], L[i + 1], t[i + 1] - t[i]
        if dt_ > HUECO_MAXIMO_S:
            huecos.append([x["timestamp"], round(dt_, 3)])
        kd0, kd1, kp0, kp1 = x["kernel_drops"], y["kernel_drops"], x["kernel_packets"], y["kernel_packets"]
        retrocede = (kd0 is not None and kd1 is not None and kd1 < kd0) or \
                    (kp0 is not None and kp1 is not None and kp1 < kp0)
        salto = (isinstance(x["uptime"], (int, float)) and isinstance(y["uptime"], (int, float))
                 and abs((y["uptime"] - x["uptime"]) - dt_) > TOLERANCIA_UPTIME_S)
        if retrocede or salto:
            reinicios.append(y["timestamp"])
        if kd0 is None or kd1 is None:
            continue
        # tras un reinicio el contador nuevo empezó dentro del intervalo: lo que muestra es pérdida
        # del intervalo (cota inferior); sin reinicio, la diferencia
        inc = kd1 if (retrocede or salto) else kd1 - kd0
        if inc > 0:
            clase = "atribuible" if desde is not None and hasta is not None and desde <= t[i] and t[i + 1] <= hasta else "ampliado"
            con_perdida.append({"desde": x["timestamp"], "hasta": y["timestamp"], "kernel_drops": inc, "clase": clase})
            if clase == "atribuible":
                atrib += inc
            else:
                ampl += inc
    r.update(delta_kernel_drops_atribuible=atrib, delta_kernel_drops_ampliado=ampl,
             intervalos_con_perdida=con_perdida[:20],
             kernel_drops=[L[0]["kernel_drops"], L[-1]["kernel_drops"]],
             kernel_packets=[L[0]["kernel_packets"], L[-1]["kernel_packets"]],
             uptime=[L[0]["uptime"], L[-1]["uptime"]], errors=[L[0]["errors"], L[-1]["errors"]])
    if not ausentes and not reinicios:
        r["delta_kernel_packets"] = L[-1]["kernel_packets"] - L[0]["kernel_packets"]
    falta = []
    if desde is None or hasta is None:
        falta.append("sin periodo")
    elif r.get("muestra_antes_s") is None:
        falta.append("sin muestra en o antes del inicio")
    elif r.get("muestra_despues_s") is None:
        falta.append("sin muestra en o después del fin")
    if huecos:
        falta.append("huecos mayores de %d s" % HUECO_MAXIMO_S)
    if len(L) < 2:
        falta.append("una sola muestra")
    if sin_uptime:
        falta.append("sin uptime en %d muestras: continuidad no verificable" % len(sin_uptime))
    if ausentes:
        falta.append("sin kernel_drops/kernel_packets en %d muestras" % len(ausentes))
    r["falta_evidencia"] = falta
    if huecos:
        r["huecos"] = huecos[:10]
    if atrib:
        r.update(estado="perdida", delta_kernel_drops=atrib)
    elif reinicios:
        r.update(estado="reinicio", reinicios=reinicios, delta_kernel_drops=None)
    elif ampl:
        r.update(estado="perdida_no_localizada", delta_kernel_drops=None,
                 motivo="aumento solo en intervalos que cruzan un borde del periodo")
    elif ausentes:
        r.update(estado="ausente", sin_kernel_drops=len(ausentes), primer_ausente=ausentes[0], delta_kernel_drops=None)
    elif falta:
        r.update(estado="insuficiente", motivo=falta[0], delta_kernel_drops=None)
    else:
        r.update(estado="presente", delta_kernel_drops=0)
    return r

def _rss_kb():
    """RSS actual y máximo del proceso en Linux, solo para la medición opcional."""
    try:
        campos = dict(linea.split(":", 1) for linea in Path("/proc/self/status").read_text().splitlines()
                      if linea.startswith(("VmRSS:", "VmHWM:")))
        return {k: int(v.split()[0]) for k, v in campos.items()}
    except OSError:
        return {}


def ventana(rutas, desde: float, hasta: float, margen: float, salida: Path, perfil: dict | None = None) -> dict:
    """Eventos stats de la EVE dedicada COMPLETA en [desde − margen, hasta + margen]: aportan las
    muestras que acotan el periodo y que el recorte del archivador (interior) no lleva."""
    rutas = tuple(rutas)
    temporal = salida.with_name(salida.name + ".parcial")
    def escribir(eventos):
        compactos, sha = [], hashlib.sha256()
        escritura_s, inicio = 0.0, time.perf_counter()
        with temporal.open("wb") as f:
            for e in eventos:
                # Se conserva solo lo que evaluar() lee; un evento stats completo ocupa ~11 KB.
                x = lectura(e)
                compactos.append({"timestamp": x["timestamp"], "stats": {"uptime": x["uptime"],
                                  "capture": {"kernel_packets": x["kernel_packets"],
                                              "kernel_drops": x["kernel_drops"], "errors": x["errors"]}}})
                b = (json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
                t = time.perf_counter()
                f.write(b)
                sha.update(b)
                escritura_s += time.perf_counter() - t
        total = time.perf_counter() - inicio
        return compactos, sha.hexdigest(), total - escritura_s, escritura_s

    try:
        ordenados = heapq.merge(*(_eventos_ordenados(r, desde - margen, hasta + margen) for r in rutas),
                                key=lambda x: x[0])
        compactos, sha, lectura_s, escritura_s = escribir(e for _, e in ordenados)
        retroceso = False
    except _Desordenados:
        # Conserva la semántica previa para un fichero anómalo con timestamps fuera de orden.
        compactos, sha, lectura_s, escritura_s = escribir(eventos_stats(rutas, desde - margen, hasta + margen))
        retroceso = True
    temporal.replace(salida)                       # nunca queda un fichero a medias con el nombre final
    if perfil is not None:
        perfil.update(lectura_s=round(lectura_s, 3), escritura_s=round(escritura_s, 3),
                      rss_tras_lectura_escritura_kb=_rss_kb(), retroceso_por_desorden=retroceso)
    t = time.perf_counter()
    evaluacion = evaluar(compactos, desde, hasta)
    if perfil is not None:
        perfil.update(evaluacion_s=round(time.perf_counter() - t, 3), rss_tras_evaluacion_kb=_rss_kb())
    return {"salida": salida.name, "eventos": len(compactos), "desde": desde, "hasta": hasta, "margen_s": margen,
            "sha256": sha, "evaluacion": evaluacion}


def ventana_cierre(rutas, desde, hasta, margen, salida: Path, reintentos=3, espera=10.0, dormir=time.sleep,
                   perfiles: list | None = None) -> tuple[int, dict]:
    """El paso de cerrar_v2.sh. Suricata escribe stats cada 8 s, así que la muestra posterior al fin
    puede no existir todavía al cerrar: se repite la lectura mientras falte SOLO esa muestra.
    rc 0 = decidido (presente, perdida, reinicio), 3 = sin decidir al agotar los intentos,
    4 = EVE ausente o ilegible (no se escribe salida, y se borra una anterior, para que C9 no use datos
    viejos). C9 trata 3 y 4 como falta de evidencia."""
    intentos = []
    for n in range(1, max(1, reintentos) + 1):
        perfil = {} if perfiles is not None else None
        try:
            r = ventana(rutas, desde, hasta, margen, salida, perfil)
        except (OSError, UnicodeError) as e:
            if salida.exists():
                salida.unlink()
            intentos.append({"intento": n, "error": "%s: %s" % (type(e).__name__, e)})
            if perfiles is not None:
                perfiles.append({"intento": n, "error": str(e), **perfil})
            return 4, {"estado": "eve_ilegible", "intentos": intentos}
        if perfiles is not None:
            perfiles.append({"intento": n, **perfil})
        ev = r["evaluacion"]
        intentos.append({"intento": n, "estado": ev["estado"], "eventos": r["eventos"],
                         "muestra_despues_s": ev.get("muestra_despues_s")})
        falta_posterior = ev["estado"] == "insuficiente" and ev.get("motivo") == "sin muestra en o después del fin"
        if not falta_posterior or n == max(1, reintentos):
            break
        dormir(espera)
    r["intentos"] = intentos
    return (0 if ev["estado"] in ("presente", "perdida", "reinicio") else 3), r

def extraer(rutas, salida: Path, desde=None, hasta=None) -> dict:
    ev = eventos_stats(rutas)
    datos = "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in ev).encode("utf-8")
    salida.write_bytes(datos)
    return {"entradas": [str(r) for r in rutas], "salida": salida.name, "eventos": len(ev),
            "sha256": hashlib.sha256(datos).hexdigest(), "evaluacion": evaluar(ev, desde, hasta)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    x = sub.add_parser("extraer"); x.add_argument("eve", nargs="+", type=Path); x.add_argument("--salida", type=Path, required=True)
    v = sub.add_parser("evaluar"); v.add_argument("ficheros", nargs="+", type=Path)
    v.add_argument("--desde", type=float); v.add_argument("--hasta", type=float)
    w = sub.add_parser("ventana"); w.add_argument("eve", nargs="+", type=Path)
    w.add_argument("--desde", type=float); w.add_argument("--hasta", type=float)
    w.add_argument("--manifiesto", type=Path, help="capturas/<ID>/manifiesto.json: toma inicio y fin del archivador")
    w.add_argument("--margen", type=float, default=30.0); w.add_argument("--salida", type=Path, required=True)
    w.add_argument("--reintentos", type=int, default=1); w.add_argument("--espera", type=float, default=10.0)
    a = ap.parse_args(argv)
    if a.orden == "extraer":
        print(json.dumps(extraer(a.eve, a.salida), ensure_ascii=False))
    elif a.orden == "ventana":
        if a.manifiesto is not None:
            try:
                m = json.loads(a.manifiesto.read_text(encoding="utf-8"))
                a.desde, a.hasta = epoch(m["inicio"]), epoch(m["fin"])
            except (OSError, ValueError, KeyError, TypeError) as e:
                print(json.dumps({"estado": "manifiesto_ilegible", "error": str(e)}, ensure_ascii=False))
                return 5
        if a.desde is None or a.hasta is None:
            ap.error("ventana necesita --manifiesto o --desde y --hasta")
        rc, r = ventana_cierre(a.eve, a.desde, a.hasta, a.margen, a.salida, a.reintentos, a.espera)
        print(json.dumps(r, ensure_ascii=False))
        return rc
    else:
        print(json.dumps(evaluar(eventos_stats(a.ficheros), a.desde, a.hasta), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
