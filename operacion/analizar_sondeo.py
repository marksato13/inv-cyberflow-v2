#!/usr/bin/env python3
"""Convierte muestras SPAN en intervalos de calidad.

Si el contador cambia entre muestras i e i+1, el cambio pudo ocurrir en
cualquier instante de [envio_i, recepcion_i+1]. Esos límites incluyen el tiempo
que tardó cada respuesta. Los intervalos consecutivos pueden solaparse durante
una consulta; los totales de segundos cuentan la unión sin duplicar tiempo.
La precedencia en un solape es indeterminado, con_descartes, sin_descartes.
"""

import argparse
from bisect import bisect_left, bisect_right
import json
import os
import sys

CLASES = ("sin_descartes", "con_descartes", "indeterminado")


def percentil(valores, porcentaje):
    if not valores:
        return None
    ordenados = sorted(valores)
    posicion = (len(ordenados) - 1) * porcentaje
    inferior = int(posicion)
    fraccion = posicion - inferior
    return ordenados[inferior] + fraccion * (ordenados[min(inferior + 1, len(ordenados) - 1)] - ordenados[inferior])


def resumen(valores):
    return {"p50": percentil(valores, 0.50), "p95": percentil(valores, 0.95),
            "max": max(valores) if valores else None}


def analizar(eventos, desde=None, hasta=None, max_intervalo_s=15):
    muestras = sorted((e for e in eventos if e.get("tipo") == "muestra"), key=lambda e: e["envio"])
    comienzo = desde if desde is not None else (muestras[0]["envio"] if muestras else eventos[0]["t"])
    termino = hasta if hasta is not None else (muestras[-1]["recepcion"] if muestras else eventos[-1]["t"])
    if termino < comienzo:
        raise ValueError("--hasta debe ser mayor o igual a --desde")
    intervalos = []
    fallos_ordenados = sorted(
        (e for e in eventos if e.get("tipo") in
         ("respuesta_invalida", "error_supervisor", "contador_disminuye")),
        key=lambda e: e["t"],
    )
    tiempos_fallo = [e["t"] for e in fallos_ordenados]
    huecos = sorted((e for e in eventos if e.get("tipo") == "hueco"),
                    key=lambda e: e["hasta"])
    finales_hueco = [e["hasta"] for e in huecos]

    def agregar(a, b, clase, delta=None, causa=None):
        a, b = max(a, comienzo), min(b, termino)
        if b > a:
            dato = {"desde": a, "hasta": b, "delta_drops": delta, "clase": clase}
            if causa:
                dato["causa"] = causa
            intervalos.append(dato)

    if not muestras:
        agregar(comienzo, termino, "indeterminado", causa="sin_muestras")
    else:
        agregar(comienzo, muestras[0]["envio"], "indeterminado", causa="antes_primera_muestra")
        if len(muestras) == 1:
            agregar(muestras[0]["envio"], muestras[0]["recepcion"],
                    "indeterminado", causa="muestra_unica")
        for anterior, actual in zip(muestras, muestras[1:]):
            a, b = anterior["envio"], actual["recepcion"]
            delta = actual["drops"] - anterior["drops"]
            fallos = fallos_ordenados[bisect_left(tiempos_fallo, a):
                                      bisect_right(tiempos_fallo, b)]
            indice_hueco = bisect_right(finales_hueco, a)
            if indice_hueco < len(huecos) and huecos[indice_hueco]["desde"] < b:
                fallos.append(huecos[indice_hueco])
            causas = []
            if fallos:
                causas.append("hueco_o_fallo")
            if b - a > max_intervalo_s:
                causas.append("intervalo_excesivo")
            if delta < 0:
                causas.append("contador_disminuye")
            clase = ("indeterminado" if causas else
                     "con_descartes" if delta > 0 else "sin_descartes")
            agregar(a, b, clase, delta if delta >= 0 else None,
                    ",".join(causas) if causas else None)
        agregar(muestras[-1]["recepcion"], termino, "indeterminado",
                causa="despues_ultima_muestra")

    # Barrido de la unión: los solapes entre consultas se cuentan una sola vez.
    cambios = {comienzo: [], termino: []}
    for item in intervalos:
        cambios.setdefault(item["desde"], []).append((item["clase"], 1))
        cambios.setdefault(item["hasta"], []).append((item["clase"], -1))
    puntos = sorted(cambios)
    activos = {clase: 0 for clase in CLASES}
    segundos = {clase: 0.0 for clase in CLASES}
    for a, b in zip(puntos, puntos[1:]):
        for clase, cambio in cambios[a]:
            activos[clase] += cambio
        clase = next((clase for clase in reversed(CLASES) if activos[clase]),
                     "indeterminado")
        segundos[clase] += b - a
    seleccion = [m for m in muestras if m["envio"] <= termino and m["recepcion"] >= comienzo]
    latencias = [m["latencia_s"] for m in seleccion]
    reales = [m["intervalo_desde_anterior_s"] for m in seleccion
              if m.get("intervalo_desde_anterior_s") is not None]
    return {"desde": comienzo, "hasta": termino, "intervalos": intervalos,
            "segundos_por_clase": segundos, "numero_muestras": len(seleccion),
            "latencias_s": resumen(latencias), "intervalos_reales_s": resumen(reales)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registro")
    parser.add_argument("--desde", type=float)
    parser.add_argument("--hasta", type=float)
    parser.add_argument("--max-intervalo-s", type=float, default=15)
    args = parser.parse_args(argv)
    if args.max_intervalo_s <= 0:
        parser.error("--max-intervalo-s debe ser positivo")
    if not os.path.isfile(args.registro) or os.path.getsize(args.registro) == 0:
        print(json.dumps({"error": "registro ausente o vacío"}, ensure_ascii=False))
        return 3
    try:
        with open(args.registro, encoding="utf-8") as archivo:
            eventos = [json.loads(linea) for linea in archivo if linea.strip()]
        if not eventos:
            print(json.dumps({"error": "registro ausente o vacío"}, ensure_ascii=False))
            return 3
        resultado = analizar(eventos, args.desde, args.hasta, args.max_intervalo_s)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(resultado, ensure_ascii=False))
    clases = [item["clase"] for item in resultado["intervalos"]]
    if "con_descartes" in clases:
        return 1
    if "indeterminado" in clases or not clases:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
