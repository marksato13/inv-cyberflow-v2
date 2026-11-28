#!/usr/bin/env python3
"""Contraste de solo lectura del Excel original con el programa v3 publicado.

Requiere openpyxl solo para esta auditoría. El libro original no se modifica ni se publica.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import openpyxl

REPO = Path(__file__).resolve().parents[1]
PROGRAMA = REPO / "programas" / "captura-49h.json"


def auditar(excel: Path):
    wb = openpyxl.load_workbook(excel, read_only=True, data_only=True)
    assert {"1 Fuentes", "2 Perfiles", "3 Jornadas"} <= set(wb.sheetnames)
    pf, j = wb["2 Perfiles"], wb["3 Jornadas"]
    p = json.loads(PROGRAMA.read_text(encoding="utf-8"))
    comprobaciones = {}

    def verificar(clave, condicion, celdas):
        comprobaciones[clave] = {"excel": celdas, "resultado": "coincide" if condicion else "DIFIERE"}
        if not condicion:
            raise AssertionError("%s: %s" % (clave, celdas))

    perfiles = p["perfiles"]
    esperados = (("P1", 30, "Consulta web y DNS"), ("P2", 30, "Navegación multirrecurso"),
                 ("P3", 180, "Transferencia de archivos"), ("P4", 10, "Aplicación transaccional"),
                 ("P5", 90, "Actividad ligera"), ("P6", 10, "Actividad intermitente"))
    for fila, (perfil, media, nombre) in enumerate(esperados, 6):
        verificar(perfil, nombre == pf[f"B{fila}"].value and pf[f"A{fila}"].value.startswith(perfil + " / ")
                 and perfiles[perfil]["media_espera_s"] == media
                 and perfiles[perfil]["origen"] == pf[f"A{fila}"].value.split(" / ")[1],
                 f"2 Perfiles!A{fila}:D{fila}")
    verificar("P2 parsing y alternancia", perfiles["P2"]["parsing_media_s"] == 0.13 and
             perfiles["P2"]["alternancia"] == ["http", "https"] and "0,13" in pf["D7"].value,
             "2 Perfiles!C7:F7, contrato §5")
    verificar("P6 ON/OFF", (perfiles["P6"]["on_s"], perfiles["P6"]["off_s"]) == (60, 120)
             and "ON 60 s / OFF 120 s" in pf["D11"].value, "2 Perfiles!C11:F11")
    dist = p["distribuciones"]
    verificar("H1", (dist["H1"]["media"], dist["H1"]["desviacion"],
             dist["H1"]["minimo"], dist["H1"]["maximo_exclusivo"]) ==
             (pf["C18"].value, pf["D18"].value, 100, 2_000_000), "2 Perfiles!A18:G18")
    verificar("H2", (dist["H2"]["media"], dist["H2"]["desviacion"],
             dist["H2"]["minimo"], dist["H2"]["maximo_exclusivo"]) ==
             (pf["C19"].value, pf["D19"].value, 50, 2_000_000), "2 Perfiles!A19:G19")
    verificar("H3", (dist["H3"]["escala"], dist["H3"]["forma"],
             dist["H3"]["maximo_exclusivo"], dist["H3"]["restar"]) ==
             (pf["C20"].value, pf["D20"].value, 55, 2), "2 Perfiles!A20:G20")
    verificar("F1", (dist["F1"]["mu"], dist["F1"]["sigma"],
             dist["F1"]["maximo_exclusivo"]) ==
             (pf["C21"].value, pf["D21"].value, 5_000_000), "2 Perfiles!A21:G21")
    verificar("siete jornadas de siete horas", p["duracion_s"] == 176400 and
             len(p["jornadas"]) == 7 and all(j[f"B{fila}"].value == 7 and
             p["jornadas"][fila - 6]["id"] == j[f"A{fila}"].value and
             p["jornadas"][fila - 6]["fin_s"] - p["jornadas"][fila - 6]["inicio_s"] == 25200
             for fila in range(6, 13)), "3 Jornadas!A6:G14")
    verificar("niveles", all(abs(p["factores"][nombre] - j[f"B{fila}"].value) < 1e-12
             for fila, nombre in ((20, "reducido"), (21, "base"), (22, "aumentado"))),
             "3 Jornadas!A20:G22")
    verificar("particiones", p["horas_por_particion"] == {
             "entrenamiento": j["B29"].value, "calibracion": j["B30"].value,
             "desarrollo": j["B31"].value} and len(p["bloques"]) == 14 and
             all(b["fin_s"] - b["inicio_s"] == 12600 for b in p["bloques"]),
             "3 Jornadas!A29:G31; contrato §7")
    return {"tipo": "contraste de configuración; no valida ejecución de 49 h",
            "excel_sha256": hashlib.sha256(excel.read_bytes()).hexdigest(),
            "programa_sha256": hashlib.sha256(PROGRAMA.read_bytes()).hexdigest(),
            "comprobaciones": comprobaciones}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("excel", nargs="?", type=Path,
                    default=REPO / "evidencias" / "bloque2" / "CyberFlow_V2_Perfiles_y_Jornadas_49h.xlsx")
    ap.add_argument("--salida", type=Path, required=True)
    a = ap.parse_args()
    informe = auditar(a.excel)
    a.salida.parent.mkdir(parents=True, exist_ok=True)
    a.salida.write_text(json.dumps(informe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("coincide:", len(informe["comprobaciones"]), "comprobaciones; excel", informe["excel_sha256"])
