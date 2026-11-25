#!/usr/bin/env python3
"""Switch interactivo guionizado para las pruebas de sondeo_span.py."""

import argparse
import json
import os
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guion", required=True)
    args = parser.parse_args()
    ruta = Path(args.guion)
    pasos = json.loads(ruta.read_text(encoding="utf-8"))["pasos"]
    estado = Path(str(ruta) + ".estado")
    indice = int(estado.read_text(encoding="ascii")) if estado.exists() else 0
    actual = None
    print("SW-CORE-STACK#", flush=True)
    for linea in sys.stdin:
        orden = linea.rstrip("\r\n")
        if orden == "exit":
            return
        if orden.startswith("show interfaces "):
            actual = pasos[min(indice, len(pasos) - 1)]
            indice += 1
            estado.write_text(str(indice), encoding="ascii")
            if actual.get("accion") == "corte":
                os._exit(0)
            if actual.get("accion") == "timeout":
                time.sleep(60)
            time.sleep(actual.get("demora_s", 0))
            print(orden, flush=True)
            if actual.get("accion") == "basura":
                print("respuesta ilegible", flush=True)
            else:
                print("  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: "
                      + str(actual["drops"]), flush=True)
                print("     " + str(actual.get("paquetes", 123456)) + " packets output, "
                      + str(actual.get("bytes", 98765432)) + " bytes, 0 underruns", flush=True)
        elif orden.startswith("show platform hardware fed "):
            time.sleep(actual.get("demora_s", 0))
            print(orden, flush=True)
            if actual.get("accion") == "basura":
                print("sin datos", flush=True)
            else:
                print(" 1 100 200 300", flush=True)
        else:
            print(orden, flush=True)
        print("SW-CORE-STACK#", flush=True)


if __name__ == "__main__":
    main()
