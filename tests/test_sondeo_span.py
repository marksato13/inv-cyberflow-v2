"""Pruebas de extremo a extremo del sondeo y del análisis SPAN."""

import json
from pathlib import Path
import subprocess
import sys
import time


RAIZ = Path(__file__).resolve().parents[1]
SONDEO = RAIZ / "operacion" / "sondeo_span.py"
ANALIZAR = RAIZ / "operacion" / "analizar_sondeo.py"
FALSO = RAIZ / "tests" / "falso_switch.py"


def ejecutar(tmp_path, pasos, duracion=1.2, cada=0.08, tiempo_max=1):
    guion = tmp_path / "guion.json"
    guion.write_text(json.dumps({"pasos": pasos}), encoding="utf-8")
    registro = tmp_path / "sondeo.jsonl"
    pid = tmp_path / "sondeo.pid"
    comando = f'"{sys.executable}" "{FALSO}" --guion "{guion}"'
    proceso = subprocess.run([
        sys.executable, str(SONDEO), "--salida", str(registro),
        "--hasta-epoch", str(time.time() + duracion), "--cada-s", str(cada),
        "--tiempo-max-respuesta-s", str(tiempo_max), "--comando-ssh", comando,
        "--pid", str(pid),
    ], cwd=RAIZ, capture_output=True, text=True, timeout=duracion + 8)
    assert proceso.returncode == 0, proceso.stderr
    assert not pid.exists()
    eventos = [json.loads(linea) for linea in registro.read_text(encoding="utf-8").splitlines()]
    assert eventos[0]["tipo"] == "arranque"
    assert eventos[-1]["tipo"] == "fin"
    assert eventos[-1]["motivo"] == "hasta_epoch"
    return registro, eventos


def analizar(registro, *opciones):
    proceso = subprocess.run([sys.executable, str(ANALIZAR), str(registro), *map(str, opciones)],
                             cwd=RAIZ, capture_output=True, text=True, timeout=5)
    return proceso.returncode, json.loads(proceso.stdout)


def muestras(eventos):
    return [e for e in eventos if e["tipo"] == "muestra"]


def test_normal_mide_intervalo_real(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10, "demora_s": 0.06}])
    datos = muestras(eventos)
    assert len(datos) >= 2
    assert datos[0]["latencia_s"] >= 0.10
    assert datos[1]["intervalo_desde_anterior_s"] >= datos[0]["latencia_s"]
    assert datos[0]["cola1_filas"] == " 1 100 200 300"
    codigo, resultado = analizar(registro)
    assert codigo == 0
    assert resultado["segundos_por_clase"]["sin_descartes"] > 0
    assert resultado["latencias_s"]["p95"] is not None
    assert resultado["intervalos_reales_s"]["p50"] is not None


def test_descartes_usan_intervalo_de_incertidumbre(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10}, {"drops": 15}])
    datos = muestras(eventos)
    codigo, resultado = analizar(registro)
    assert codigo == 1
    intervalo = next(i for i in resultado["intervalos"] if i["delta_drops"] == 5)
    assert intervalo["clase"] == "con_descartes"
    assert intervalo["desde"] == datos[0]["envio"]
    assert intervalo["hasta"] == datos[1]["recepcion"]


def test_corte_reconecta_y_registra_hueco(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10}, {"accion": "corte"}, {"drops": 10}],
                                  duracion=4.6)
    assert len(muestras(eventos)) >= 2
    assert len([e for e in eventos if e["tipo"] == "conexion" and e["ok"]]) >= 2
    assert any(e["tipo"] == "hueco" and e["causa"] == "desconexion" for e in eventos)
    codigo, resultado = analizar(registro)
    assert codigo == 2
    assert any(i["clase"] == "indeterminado" for i in resultado["intervalos"])


def test_timeout_reconecta_y_registra_hueco(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10}, {"accion": "timeout"}, {"drops": 10}],
                                  duracion=4.6, tiempo_max=0.35)
    assert len(muestras(eventos)) >= 2
    assert any(e["tipo"] == "hueco" and e["causa"] == "timeout" for e in eventos)
    assert len([e for e in eventos if e["tipo"] == "conexion" and e["ok"]]) >= 2
    assert analizar(registro)[0] == 2


def test_respuesta_invalida_no_cuenta_como_sin_descartes(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10}, {"accion": "basura"}, {"drops": 10}],
                                  duracion=1.2)
    assert any(e["tipo"] == "respuesta_invalida" for e in eventos)
    assert any(e["tipo"] == "hueco" and e["causa"] == "respuesta_invalida" for e in eventos)
    assert analizar(registro)[0] == 2


def test_contador_disminuye_es_indeterminado(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 100}, {"drops": 80}])
    assert any(e["tipo"] == "contador_disminuye" and e["antes"] == 100
               and e["despues"] == 80 for e in eventos)
    codigo, resultado = analizar(registro)
    assert codigo == 2
    assert any(i.get("causa") and "contador_disminuye" in i["causa"]
               for i in resultado["intervalos"])


def test_registro_interrumpido_tiene_margen_final_indeterminado(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10}])
    registro.write_text("\n".join(json.dumps(e) for e in eventos if e["tipo"] != "fin") + "\n",
                        encoding="utf-8")
    ultimo = muestras(eventos)[-1]
    codigo, resultado = analizar(registro, "--hasta", ultimo["recepcion"] + 3)
    assert codigo == 2
    assert any(i["causa"] == "despues_ultima_muestra" for i in resultado["intervalos"]
               if "causa" in i)
    assert resultado["segundos_por_clase"]["indeterminado"] >= 3


def test_margen_inicial_es_indeterminado(tmp_path):
    registro, eventos = ejecutar(tmp_path, [{"drops": 10}])
    primero = muestras(eventos)[0]
    codigo, resultado = analizar(registro, "--desde", primero["envio"] - 3)
    assert codigo == 2
    assert any(i.get("causa") == "antes_primera_muestra" for i in resultado["intervalos"])
    assert resultado["segundos_por_clase"]["indeterminado"] >= 3


def test_registro_vacio_da_codigo_3(tmp_path):
    registro = tmp_path / "vacio.jsonl"
    registro.touch()
    assert analizar(registro)[0] == 3


def test_una_muestra_no_acredita_ausencia_de_descartes(tmp_path):
    registro = tmp_path / "una.jsonl"
    registro.write_text(json.dumps({"tipo": "muestra", "t": 2.0, "envio": 1.0,
                                    "recepcion": 2.0, "drops": 0, "latencia_s": 1.0,
                                    "intervalo_desde_anterior_s": None}) + "\n",
                        encoding="utf-8")
    codigo, resultado = analizar(registro)
    assert codigo == 2
    assert resultado["intervalos"][0]["clase"] == "indeterminado"
    assert resultado["segundos_por_clase"]["indeterminado"] == 1.0


def test_intervalo_excesivo_es_indeterminado(tmp_path):
    registro = tmp_path / "largo.jsonl"
    eventos = [{"tipo": "muestra", "t": 1.0, "envio": 0.0, "recepcion": 1.0,
                "drops": 4, "latencia_s": 1.0, "intervalo_desde_anterior_s": None},
               {"tipo": "muestra", "t": 21.0, "envio": 20.0, "recepcion": 21.0,
                "drops": 4, "latencia_s": 1.0, "intervalo_desde_anterior_s": 20.0}]
    registro.write_text("\n".join(json.dumps(e) for e in eventos) + "\n", encoding="utf-8")
    codigo, resultado = analizar(registro)
    assert codigo == 2
    assert resultado["intervalos"][0]["clase"] == "indeterminado"
    assert resultado["intervalos"][0]["causa"] == "intervalo_excesivo"
