"""Pruebas de extremo a extremo del sondeo y del análisis SPAN."""

import json
from pathlib import Path
import subprocess
import sys
import time

import pytest


RAIZ = Path(__file__).resolve().parents[1]
SONDEO = RAIZ / "operacion" / "sondeo_span.py"
ANALIZAR = RAIZ / "operacion" / "analizar_sondeo.py"
FALSO = RAIZ / "tests" / "falso_switch.py"


# Ventanas sucesivas (factor sobre la duración pedida). Cada prueba exige que el guion del switch falso
# se haya recorrido ENTERO dentro de la ventana; si no, la pasada no ejercita el escenario y se repite
# con una ventana mayor. Las aserciones de cada prueba no cambian y se aplican a esa pasada completa.
# Si ni la mayor alcanza, la prueba falla con el motivo y los intentos (nunca pasa sin escenario).
# Antes (r7) la ventana era fija y, con la máquina cargada, las pasadas incompletas fallaban en una
# aserción que no tenía nada que ver con lo que se probaba (BLOQUE1-REVISION-8, §1).
FACTORES_VENTANA = (1, 3, 9)


def peticiones_servidas(guion):
    estado = Path(str(guion) + ".estado")
    return int(estado.read_text(encoding="ascii")) if estado.exists() else 0


def ejecutar(tmp_path, pasos, duracion=3.0, cada=0.08, tiempo_max=1, tiempo_conexion=10):
    # tiempo_conexion: plazo del prompt inicial de cada switch falso NUEVO. Con tiempo_max 0,35 s
    # (prueba de timeout) y la máquina cargada, el arranque de otro Python superaba ese plazo y la
    # reconexión fallaba por el entorno, no por el sondeo (antes-06 y antes-x3-03 de suite-r8).
    intentos = []
    eventos = []
    for n, factor in enumerate(FACTORES_VENTANA, 1):
        ventana = duracion * factor
        d = tmp_path / ("intento-%d" % n)
        d.mkdir()
        guion = d / "guion.json"
        guion.write_text(json.dumps({"pasos": pasos}), encoding="utf-8")
        registro = d / "sondeo.jsonl"
        pid = d / "sondeo.pid"
        comando = f'"{sys.executable}" "{FALSO}" --guion "{guion}"'
        t0 = time.time()
        proceso = subprocess.run([
            sys.executable, str(SONDEO), "--salida", str(registro),
            "--hasta-epoch", str(t0 + ventana), "--cada-s", str(cada),
            "--tiempo-max-respuesta-s", str(tiempo_max),
            "--tiempo-max-conexion-s", str(tiempo_conexion), "--comando-ssh", comando,
            "--pid", str(pid),
        ], cwd=RAIZ, capture_output=True, text=True, timeout=2 * ventana + tiempo_conexion + 20,
            stdin=subprocess.DEVNULL)
        assert proceso.returncode == 0, proceso.stderr
        assert not pid.exists()
        eventos = [json.loads(linea) for linea in registro.read_text(encoding="utf-8").splitlines()]
        assert eventos[0]["tipo"] == "arranque"
        assert eventos[-1]["tipo"] == "fin"
        assert eventos[-1]["motivo"] == "hasta_epoch"
        servidas = peticiones_servidas(guion)
        intentos.append({"intento": n, "ventana_s": round(ventana, 1), "duracion_real_s": round(time.time() - t0, 3),
                         "peticiones_servidas": servidas, "pasos": len(pasos),
                         "muestras": len(muestras(eventos))})
        # Se pidió la muestra siguiente al último paso: todos los pasos se sirvieron y el sondeo
        # recibió la respuesta del último (solo pide otra tras recibirla).
        if servidas >= len(pasos) + 1:
            print("intentos del escenario:", json.dumps(intentos))
            return registro, eventos
    pytest.fail("el guion del switch falso no se completó en ninguna ventana %s: %s\nultimos eventos: %s"
                % ([round(duracion * f, 1) for f in FACTORES_VENTANA], json.dumps(intentos), json.dumps(eventos[-8:])))


def analizar(registro, *opciones):
    proceso = subprocess.run([sys.executable, str(ANALIZAR), str(registro), *map(str, opciones)],
                             cwd=RAIZ, capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
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
                                  duracion=3.0)
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
