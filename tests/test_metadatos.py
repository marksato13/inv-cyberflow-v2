"""Trazabilidad de ventanas: metadatos separados de las 28 entradas y reglas de exclusión E1–E5."""
import csv
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "extraccion"))
import extraer_v2 as ex  # noqa: E402
import metadatos_v2 as md  # noqa: E402

T0 = 1795560000.0  # t=0 del programa


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


class TestMetadatos(unittest.TestCase):
    def preparar(self, d):
        d = Path(d)
        cap, x, gen = d / "capturas" / "V2-X-1", d / "x", d / "gen"
        for p in (cap / "eve", x, gen):
            p.mkdir(parents=True)
        prog = {"duracion_s": 60, "bloques": [{"id": "B1", "inicio_s": 0, "fin_s": 30, "particion": "entrenamiento"},
                                               {"id": "B2", "inicio_s": 30, "fin_s": 60, "particion": "calibracion"}],
                "fases": [{"id": "F1", "inicio_s": 0, "fin_s": 60, "factor": 1}],
                "pulsos": [], "perfiles": {"ofimatica": {"origen": "10.10.20.21"}}}
        (gen / "programa.json").write_text(json.dumps(prog))
        (gen / "eventos-ofimatica.jsonl").write_text(json.dumps({"tipo": "inicio", "perfil": "ofimatica",
                                                                 "utc": iso(T0), "t_s": 0}) + "\n")
        txs = [("t1", 12, 13), ("t2", 41, 42)]
        (gen / "transacciones-ofimatica.jsonl").write_text("".join(json.dumps(
            {"transaccion_id": i, "perfil": "ofimatica", "inicio_utc": iso(T0 + a), "fin_utc": iso(T0 + b)}) + "\n" for i, a, b in txs))
        with open(d / "cob.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["transaccion_id", "estado", "transferencia"])
            w.writeheader(); w.writerow({"transaccion_id": "t1", "estado": "verificable", "transferencia": "completa"})
            w.writerow({"transaccion_id": "t2", "estado": "no verificable", "transferencia": "no verificable"})
        (d / "conc.jsonl").write_text("".join(json.dumps({"transaccion_id": i, "clase": "correcto"}) + "\n" for i in ("t1", "t2")))
        (cap / "inventario.jsonl").write_text(json.dumps({"fichero": "live-a.pcap", "fichero_archivado": "live-a.pcap.gz",
                                                          "primer_paquete_epoch": T0 - 5, "ultimo_paquete_epoch": T0 + 70}) + "\n")
        (cap / "manifiesto.json").write_text(json.dumps({"eve_sha256": "ab" * 32}))
        (x / "inventario_ips.json").write_text(json.dumps([{"ip": "10.10.20.21", "regla": "poblacion"}]))
        with open(x / "filas.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(ex.FIELDS))
            w.writeheader()
            for k, fin in enumerate((20, 40, 50, 80)):
                fila = {c: 0 for c in ex.v2.FEATURE_NAMES}
                fila.update(ejecucion="V2-X-1", ip="10.10.20.21", ventana_inicio=iso(T0 + fin - 10), ventana_fin=iso(T0 + fin),
                            bloque=0 if fin <= 30 else 1, motivo_marca="frontera" if fin == 40 else "",
                            n_paquetes_ventana=1, n_eventos_l7_ventana=0)
                w.writerow(fila)
        return cap, x, gen, d

    def test_trazabilidad_y_exclusiones(self):
        with tempfile.TemporaryDirectory() as d:
            cap, x, gen, d = self.preparar(d)
            rc = md.cmd_metadatos(SimpleNamespace(capturas=str(cap), extraccion=str(x), generador=str(gen),
                                                  cobertura=str(d / "cob.csv"), conciliacion=str(d / "conc.jsonl")))
            inf = json.loads((x / "trazabilidad.json").read_text())
            self.assertEqual(rc, 0)
            self.assertTrue(inf["trazabilidad_ok"])
            self.assertEqual(inf["n_entradas"], 28)
            with open(x / "entradas_if.csv", newline="") as f:
                cab = next(csv.reader(f))
            self.assertEqual(cab, ["ventana_id"] + list(ex.v2.FEATURE_NAMES))   # ningún metadato entre las 28
            meta = list(csv.DictReader(open(x / "ventanas_meta.csv", newline="")))
            por_cierre = {round(float(m["t_programa_s"])): m for m in meta}
            self.assertEqual(por_cierre[20]["particion"], "entrenamiento")
            self.assertEqual(por_cierre[20]["excluir_entrenamiento"], "False")
            self.assertEqual(por_cierre[20]["pcap_ventana"], "live-a.pcap.gz")
            self.assertIn("E1:frontera", por_cierre[40]["motivos_exclusion"])
            self.assertEqual(por_cierre[40]["particion"], "calibracion")
            self.assertIn("E3:cobertura_no verificable", por_cierre[50]["motivos_exclusion"])
            self.assertIn("E5:fuera_del_programa", por_cierre[80]["motivos_exclusion"])

    def test_fronteras_desde_programa_y_arranque(self):
        with tempfile.TemporaryDirectory() as d:
            cap, x, gen, d = self.preparar(d)
            md.cmd_fronteras(SimpleNamespace(generador=str(gen), salida=str(d / "fr.json")))
            self.assertEqual(ex.fronteras_desde(d / "fr.json"), [T0 + 30])


if __name__ == "__main__":
    unittest.main()
