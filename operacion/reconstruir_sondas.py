#!/usr/bin/env python3
"""Registro de sondas RECONSTRUIDO para ejecuciones anteriores a preflight.jsonl (T1, T2, E1–E3).

    python3 reconstruir_sondas.py --ejecucion ID --lanzamiento registros/lanzamiento.json \
        --supervisor generador/ID/supervisor.jsonl --programa generador/ID/programa.json \
        --salida sondas-reconstruidas-ID.jsonl

Hasta el 26-nov, `v2ctl.py iniciar` lanzaba las sondas del preflight sin registrarlas, justo antes
del supervisor. Lo que sí consta de cada ejecución es:
  - que `iniciar` se llamó en el instante planificado del generador (lanzar_v2.sh espera hasta INI:
    `planificado.generador_inicio_epoch` de lanzamiento.json, más `retraso_prueba_s`);
  - que el supervisor lanzó el primer perfil después de las sondas (`perfil_lanzado`);
  - el origen (primer perfil), el nombre (portal.<zona>) y el id (semilla fija, random.Random(1)).
El puerto de origen NO consta: queda a null. contraste_dns.py solo usa un registro reconstruido si
su intervalo [INI, primer perfil] contiene el evento y una única clave con la firma cae en él; lo
cuenta aparte («reconstruido») y el dictamen no lo trata como explicación plena.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import random
from pathlib import Path

ACCIONES = (("dns", "dns"), ("obtener HTTP", "obtener"), ("obtener HTTPS", "obtener"),
            ("consulta", "consulta"), ("envio", "envio"))


def ep(s: str) -> float:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def reconstruir(ejecucion: str, lanzamiento: dict, supervisor: list[dict], programa: dict) -> list[dict]:
    plan = lanzamiento.get("planificado") or {}
    if "generador_inicio_epoch" not in plan:
        raise SystemExit("lanzamiento.json sin planificado.generador_inicio_epoch")
    desde = float(plan["generador_inicio_epoch"]) + float(lanzamiento.get("retraso_prueba_s") or 0)
    lanzados = [ep(x["utc"]) for x in supervisor if x.get("tipo") == "perfil_lanzado"]
    if not lanzados:
        raise SystemExit("supervisor.jsonl sin perfil_lanzado")
    hasta = min(lanzados)
    if hasta < desde:
        raise SystemExit("primer perfil anterior al instante planificado: no se reconstruye")
    perfil0 = next(iter(programa["perfiles"]))
    origen = programa["perfiles"][perfil0]["origen"]
    nombre = "portal." + programa["destinos"]["dns_zona"]
    ident = random.Random(1).randint(0, 65535)
    out = []
    for sonda, accion in ACCIONES:
        r = {"tipo": "sonda", "fuente": "reconstruido", "ejecucion_id": ejecucion, "contexto": "iniciar",
             "sonda": sonda, "accion": accion, "origen_ip": origen, "origen_puerto": None,
             "inicio_utc": iso(desde), "fin_utc": iso(hasta),
             "evidencia": {"desde": "lanzamiento.json planificado.generador_inicio_epoch + retraso_prueba_s",
                           "hasta": "supervisor.jsonl primer perfil_lanzado",
                           "id": "random.Random(1).randint(0, 65535) en v2ctl.py",
                           "puerto": "no consta"}}
        if accion == "dns":
            r.update(protocolo="dns", destino_puerto=53, dns_id=ident, dns_nombre=nombre)
        else:
            r.update(protocolo="https" if "HTTPS" in sonda else "http",
                     destino_puerto=programa["destinos"]["puerto_https" if "HTTPS" in sonda else "puerto_http"])
        out.append(r)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ejecucion", required=True)
    ap.add_argument("--lanzamiento", required=True, type=Path)
    ap.add_argument("--supervisor", required=True, type=Path)
    ap.add_argument("--programa", required=True, type=Path)
    ap.add_argument("--salida", required=True, type=Path)
    a = ap.parse_args(argv)
    sup = [json.loads(x) for x in a.supervisor.read_text(encoding="utf-8").splitlines() if x.strip()]
    lineas = reconstruir(a.ejecucion, json.loads(a.lanzamiento.read_text(encoding="utf-8")), sup,
                         json.loads(a.programa.read_text(encoding="utf-8")))
    a.salida.write_text("".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in lineas),
                        encoding="utf-8")
    print(json.dumps({"ejecucion": a.ejecucion, "desde": lineas[0]["inicio_utc"], "hasta": lineas[0]["fin_utc"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
