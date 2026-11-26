"""Sondas del preflight antes del periodo útil (revisión del 26-nov, puntos 3 y 4).

- El margen de v2ctl se deriva de las constantes del extractor (Bloque 3), no de los datos.
- Con ventanas construidas con las reglas de metadatos_v2 (E1 desde el inicio de la captura, E5
  fuera del programa) y la historia de extraer_v2, una sonda que termina MARGEN_SONDA_S antes de
  t0 no toca ninguna ventana útil; la sonda al arrancar (como hasta el 25-nov) toca 23.
- `iniciar --sondas-previas` rechaza un registro de otra ejecución, con fallos o sin margen.
"""
import csv
import datetime as dt
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
for sub in ("operacion", "extraccion", "generador"):
    sys.path.insert(0, str(RAIZ / sub))
import extraer_v2 as ex  # noqa: E402
import metadatos_v2 as md  # noqa: E402
import v2ctl  # noqa: E402
import ventanas_sonda as vs  # noqa: E402

IP = "10.10.20.21"


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def test_margen_derivado_del_extractor():
    assert v2ctl.HORIZONTE_S == ex.HORIZONTE_MOTOR_S
    assert v2ctl.PASO_S == md.PASO_S
    assert v2ctl.MARGEN_SONDA_S == ex.HORIZONTE_MOTOR_S + md.PASO_S
    # lanzar_v2.sh usa el mismo número
    assert "MARGEN_SONDA_S=%d" % v2ctl.MARGEN_SONDA_S in (RAIZ / "operacion/lanzar_v2.sh").read_text(encoding="utf-8")


def ventanas(inicio_captura, t0, duracion, ip=IP):
    """Ventanas de 10 s de una entidad con las reglas de extraer_v2.marcar y metadatos_v2 (E1/E5)."""
    filas = []
    anchor = (int(inicio_captura // 10) + 1) * 10
    while anchor <= t0 + duracion:
        _, marca, _ = ex.marcar(anchor, inicio_captura, [])
        motivos = ["E1:" + m for m in marca.split(",") if m]
        trel = anchor - t0
        if not (0 <= trel - md.PASO_S and trel <= duracion):
            motivos.append("E5:fuera_del_programa")
        filas.append({"ventana_id": "%s|%s" % (ip, anchor), "entidad_ip": ip, "regla_poblacion": "poblacion",
                      "ventana_cierre_utc": iso(anchor), "t_programa_s": str(trel),
                      "antecedentes_desde_utc": iso(max(inicio_captura, anchor - ex.HORIZONTE_MOTOR_S)),
                      "motivos_exclusion": ";".join(motivos)})
        anchor += 10
    return filas


def sonda(ini, fin, fuente=None):
    x = {"tipo": "sonda", "origen_ip": IP, "contexto": "sondear", "sonda": "dns",
         "inicio_utc": iso(ini), "fin_utc": iso(fin)}
    if fuente:
        x["fuente"] = fuente
    return x


def test_sonda_con_margen_no_toca_ventanas_utiles():
    captura = 1_000_000.0
    t0 = captura + 250.0                       # captura previa >= 150 s y margen de sonda cumplido
    fin_sonda = t0 - v2ctl.MARGEN_SONDA_S
    filas, utiles, guardadas = vs.evaluar(ventanas(captura, t0, 1440), vs.intervalos([sonda(fin_sonda - 1.2, fin_sonda)]))
    assert utiles == 0
    assert guardadas > 0                       # la sonda cae en ventanas que ya excluye una guarda
    assert filas[0]["margen_hasta_t0_s"] >= v2ctl.MARGEN_SONDA_S - 1.0   # menos la cola de 1 s


def test_sonda_al_arrancar_contamina_23_ventanas_como_en_t1_e3():
    captura = 1_000_000.0
    t0 = captura + 243.0                       # como T1: generador 243 s después de la captura
    filas, utiles, guardadas = vs.evaluar(ventanas(captura, t0, 1440), vs.intervalos([sonda(t0 - 0.2, t0 - 0.15)]))
    # 23 ventanas tocadas (las del laboratorio); según la fase de t0 en la rejilla de 10 s, la
    # primera puede caer en E5 (fuera del programa): 22 o 23 útiles, nunca 0.
    assert utiles + guardadas == 23 and utiles in (22, 23)


def test_varias_sondas_del_mismo_origen_cuentan_ventanas_distintas():
    captura = 1_000_000.0
    t0 = captura + 243.0
    v = ventanas(captura, t0, 1440)
    _, una, g1 = vs.evaluar(v, vs.intervalos([sonda(t0 - 0.2, t0 - 0.15)]))
    cinco = [sonda(t0 - 0.2 + i * 0.01, t0 - 0.15 + i * 0.01) for i in range(5)]
    for i, x in enumerate(cinco):
        x["sonda"] = "s%d" % i
    filas, utiles, guardadas = vs.evaluar(v, vs.intervalos(cinco))
    assert len(filas) == 5 and utiles == una and guardadas == g1


def test_justo_por_debajo_del_margen_contamina():
    captura = 1_000_000.0
    t0 = captura + 250.0
    fin = t0 - (ex.HORIZONTE_MOTOR_S - md.PASO_S) + 5     # 5 s dentro de la historia de la 1.ª útil
    _, utiles, _ = vs.evaluar(ventanas(captura, t0, 1440), vs.intervalos([sonda(fin - 1, fin)], cola_s=0))
    assert utiles >= 1


def escribir_meta(ruta, filas):
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)


def test_cli_estados(tmp_path):
    captura, t0 = 1_000_000.0, 1_000_250.0
    meta = tmp_path / "meta.csv"
    escribir_meta(meta, ventanas(captura, t0, 600))
    pre = tmp_path / "pre.jsonl"
    sal = tmp_path / "s.json"
    pre.write_text(json.dumps(sonda(t0 - 245, t0 - 241)) + "\n")
    assert vs.main(["--ventanas", str(meta), "--preflight", str(pre), "--salida", str(sal)]) == 0
    assert json.loads(sal.read_text())["estado"] == "sin_contaminacion"
    pre.write_text(json.dumps(sonda(t0 + 30, t0 + 31)) + "\n")
    assert vs.main(["--ventanas", str(meta), "--preflight", str(pre), "--salida", str(sal)]) == 1
    assert vs.main(["--ventanas", str(meta), "--salida", str(sal)]) == 2
    assert json.loads(sal.read_text())["estado"] == "sin_registro"


def test_salida_real_de_ventanas_sonda_la_entiende_el_dictamen(tmp_path):
    """La versión que escribe ventanas_sonda.py es la que acepta estado_global (VD2, 26-nov)."""
    sys.path.insert(0, str(RAIZ / "operacion"))
    import estado_global as eg
    captura, t0 = 1_000_000.0, 1_000_250.0
    meta = tmp_path / "meta.csv"
    escribir_meta(meta, ventanas(captura, t0, 600))
    pre, sal = tmp_path / "pre.jsonl", tmp_path / "s.json"
    pre.write_text(json.dumps(sonda(t0 - 245, t0 - 241)) + "\n")
    vs.main(["--ventanas", str(meta), "--preflight", str(pre), "--salida", str(sal)])
    assert eg.calidad_sonda(json.loads(sal.read_text())) == "completo"
    pre.write_text(json.dumps(sonda(t0 - 245, t0 - 241, fuente="reconstruido")) + "\n")
    vs.main(["--ventanas", str(meta), "--preflight", str(pre), "--salida", str(sal)])
    assert eg.calidad_sonda(json.loads(sal.read_text())) == "indeterminado"
    pre.write_text(json.dumps(sonda(t0 + 30, t0 + 31)) + "\n")
    vs.main(["--ventanas", str(meta), "--preflight", str(pre), "--salida", str(sal)])
    assert eg.calidad_sonda(json.loads(sal.read_text())) == "contaminacion"


# -- iniciar --sondas-previas --------------------------------------------------------------------
def registro(tmp_path, ejecucion="V2-X-20261126T000000Z", fin=1000.0, clase="ok", ok=True):
    lineas = [{"tipo": "comprobacion", "ejecucion_id": ejecucion, "comprobacion": "reloj", "ok": ok},
              {"tipo": "sonda", "ejecucion_id": ejecucion, "sonda": "dns", "clase": clase,
               "inicio_utc": iso(fin - 1), "fin_utc": iso(fin)}]
    r = tmp_path / "pre.jsonl"
    v2ctl.escribir_jsonl(r, lineas)
    return r


def test_validar_sondas_previas(tmp_path):
    e = "V2-X-20261126T000000Z"
    ok, res = v2ctl.validar_sondas_previas(registro(tmp_path), e, 1000.0 + 240)
    assert ok == [] and res["margen_real_s"] == 240
    assert any("margen" in f for f in v2ctl.validar_sondas_previas(registro(tmp_path), e, 1000.0 + 100)[0])
    assert any("otra ejecución" in f for f in v2ctl.validar_sondas_previas(registro(tmp_path, "V2-Y-20261126T000000Z"), e, 2000)[0])
    assert any("sonda falla" in f for f in v2ctl.validar_sondas_previas(registro(tmp_path, clase="fallo_inesperado"), e, 2000)[0])
    assert any("comprobación" in f for f in v2ctl.validar_sondas_previas(registro(tmp_path, ok=False), e, 2000)[0])
    (tmp_path / "roto.jsonl").write_text("{no json")
    assert v2ctl.validar_sondas_previas(tmp_path / "roto.jsonl", e, 2000)[0]


def test_registro_de_sonda_lleva_la_clave_completa():
    reg = {"origen_ip": IP, "origen_puerto": 40000, "dns_id": 17611, "dns_nombre": "portal.cf-v2.lab",
           "protocolo": "dns", "destino_ip": "10.10.10.20", "destino_puerto": 53, "clase": "ok"}
    x = v2ctl._registro_sonda("V2-X-20261126T000000Z", "sondear", "dns", "dns", reg, "a", "b", 1.0, 2.0)
    for k in ("ejecucion_id", "origen_ip", "origen_puerto", "dns_id", "dns_nombre", "inicio_utc", "fin_utc",
              "inicio_monotonic", "fin_monotonic", "destino_ip", "destino_puerto"):
        assert x[k] is not None, k
