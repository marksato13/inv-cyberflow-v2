"""Pruebas locales del archivador, sin servicios ni red."""
from __future__ import annotations

import datetime
import gzip
import json
import os
import shutil
import struct
import sys
import uuid
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "captura"))
import archivar_v2 as ar  # noqa: E402


def pcap(ruta, marcas):
    with open(ruta, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for t in marcas:
            f.write(struct.pack("<IIII", int(t), 0, 1, 1) + b"x")


def nombre(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("live-%Y%m%d%H%M%S.pcap")


class TestArchivado(unittest.TestCase):
    def setUp(self):
        self.base = RAIZ / "tests" / ("temporal-" + uuid.uuid4().hex)
        self.base.mkdir(mode=0o777)
        self.addCleanup(self.limpiar)
        self.anillo = self.base / "anillo"
        self.anillo.mkdir()
        self.eve = self.base / "eve.json"
        self.eve.write_bytes(b"")
        self.a = SimpleNamespace(raiz=str(self.base / "salida"), ejecucion="PRUEBA", anillo=str(self.anillo),
                                 eve=[str(self.eve)], eve_rotada_patron="{ruta}.1", interfaz="nada",
                                 margen_previo=30, hasta_epoch=0, margen_final_s=60,
                                 libre_minimo_gb=0, cada=0.01)
        self.arch = ar.Archivador(self.a)
        self.arch.desde = 0

    def limpiar(self):
        for f in (self.arch.inv, self.arch.ev, self.arch.eve_out):
            if not f.closed:
                f.close()
        for s in self.arch.seguidores:
            if s.fd and not s.fd.closed:
                s.fd.close()
            for r in s.retirados:
                r[0].close()
        shutil.rmtree(self.base)

    def seguidores(self):
        self.arch.seguidores = [ar.SeguidorEve(self.eve, self.arch)]
        return self.arch.seguidores[0]

    def salida(self):
        return (self.arch.dir / "eve" / "eve-PRUEBA.json").read_bytes()

    def huecos(self):
        p = self.arch.dir / "eve" / "huecos.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def test_copytruncate_recupera_copia_y_gzip(self):
        for comprimir in (False, True):
            with self.subTest(gzip=comprimir):
                self.eve.write_bytes(b'{"n":1}\n')
                s = self.seguidores()
                s.pasada()
                original = self.eve.read_bytes() + b'{"n":2}\n'
                rotada = Path(str(self.eve) + ".1" + (".gz" if comprimir else ""))
                if comprimir:
                    with gzip.open(rotada, "wb") as f:
                        f.write(original)
                else:
                    rotada.write_bytes(original)
                self.eve.write_bytes(b"")
                s.pasada()
                self.assertIn(b'{"n":2}\n', self.salida())
                self.assertEqual(self.huecos()[-1]["tipo"], "copytruncate_recuperado")
                self.assertEqual(self.huecos()[-1]["lineas_recuperadas"], 1)
                rotada.unlink()
                s.fd.close()
                self.arch.seguidores.clear()
                self.arch.eve_out.seek(0)
                self.arch.eve_out.truncate()
                self.arch.eve_out.flush()
                self.eve.write_bytes(b"")

    def test_rename_create_vacia_descriptor_anterior(self):
        s = self.seguidores()
        self.eve.write_bytes(b'{"n":1}\n')
        s.pasada()
        s.fd.close()  # Windows no permite renombrar un fichero abierto
        self.eve.rename(self.base / "eve.json.1")
        with open(self.base / "eve.json.1", "ab") as f:
            f.write(b'{"n":2}\n')
        s.fd = open(self.base / "eve.json.1", "rb")
        s.ino = os.fstat(s.fd.fileno()).st_ino
        self.eve.write_bytes(b'{"n":3}\n')
        s.pasada()
        self.assertEqual(self.salida().count(b"\n"), 3)
        self.assertEqual(self.arch.eve_huecos, 0)
        self.assertEqual(self.huecos()[-1]["lineas_recuperadas"], 1)

    def test_sustitucion_y_linea_incompleta(self):
        s = self.seguidores()
        self.eve.write_bytes(b'{"n":1')
        s.pasada()
        self.assertEqual(self.salida(), b"")
        s.fd.close()
        self.eve.rename(self.base / "anterior")
        nuevo = self.base / "nuevo"
        nuevo.write_bytes(b'{"n":2}\n')
        nuevo.replace(self.eve)
        s.fd = open(self.base / "anterior", "rb")
        s.ino = os.fstat(s.fd.fileno()).st_ino
        s.pasada()
        self.assertEqual(self.salida(), b'{"n":2}\n')
        # La línea sin terminar del inodo viejo se declara al retirarlo, no antes.
        self.assertNotIn("linea_incompleta", [r["tipo"] for r in self.huecos()])
        s.vaciar_retirados(cerrar_todo=True)
        self.assertIn("linea_incompleta", [r["tipo"] for r in self.huecos()])

    def test_gzip_a_medio_escribir_se_reintenta(self):
        """logrotate comprime eve.json.1 sin delaycompress: el .gz puede estar incompleto."""
        s = self.seguidores()
        self.eve.write_bytes(b'{"n":1}\n')
        s.pasada()
        completo = self.eve.read_bytes() + b'{"n":2}\n'
        gz = Path(str(self.eve) + ".1.gz")
        gz.write_bytes(gzip.compress(completo)[:12])          # a medio escribir
        self.eve.write_bytes(b'{"n":3}\n')                   # truncado y nuevo contenido
        s.pasada()
        self.assertEqual(sorted(self.salida().splitlines()), [b'{"n":1}', b'{"n":3}'])
        self.assertEqual(len(s.rotacion_pendiente), 1)
        gz.write_bytes(gzip.compress(completo))              # logrotate termina
        s.pasada()
        self.assertEqual(sorted(self.salida().splitlines()), [b'{"n":1}', b'{"n":2}', b'{"n":3}'])
        self.assertEqual(s.rotacion_pendiente, [])
        self.assertEqual(self.arch.eve_huecos, 0)

    def test_inodo_retirado_sigue_vaciandose(self):
        """Prueba de rotación en Sensor1: el escritor siguió 1,5 s en el inodo viejo (388 líneas)."""
        s = self.seguidores()
        self.eve.write_bytes(b'{"n":1}\n')
        s.pasada()
        s.fd.close()
        self.eve.rename(self.base / "viejo")
        s.fd = open(self.base / "viejo", "rb")
        s.ino = os.fstat(s.fd.fileno()).st_ino
        self.eve.write_bytes(b'{"n":3}\n')
        s.pasada()
        with open(self.base / "viejo", "ab") as f:   # escritor aún sin SIGHUP
            f.write(b'{"n":2}\n')
        s.pasada()
        self.assertEqual(sorted(self.salida().splitlines()), [b'{"n":1}', b'{"n":2}', b'{"n":3}'])
        self.assertEqual(self.arch.eve_huecos, 0)

    def test_linea_corrupta_aparte(self):
        s = self.seguidores()
        self.eve.write_bytes(b'basura\n{"n":1}\n')
        s.pasada()
        self.assertEqual(self.salida(), b'{"n":1}\n')
        self.assertEqual(self.arch.eve_corruptas, 1)
        self.assertTrue((self.arch.dir / "eve" / "corruptas.jsonl").exists())

    def test_hueco_copytruncate_irrecuperable(self):
        s = self.seguidores()
        self.eve.write_bytes(b'{"n":1}\n')
        s.pasada()
        self.eve.write_bytes(b"")
        s.pasada()
        self.assertEqual(self.huecos(), [])            # se reintenta mientras logrotate trabaja
        with patch.object(ar, "REINTENTO_ROTADA_S", -1):
            s.pasada()
        self.assertEqual(self.huecos()[-1]["tipo"], "copytruncate_irrecuperable")
        self.assertEqual(self.arch.eve_huecos, 1)

    def test_pcap_salto_nombres_y_borrado(self):
        t = 1_800_000_000
        pcap(self.anillo / nombre(t), [t])
        pcap(self.anillo / nombre(t + 5), [t + 5])
        self.arch.pasada_pcap()
        pcap(self.anillo / nombre(t + 20), [t + 20])
        pcap(self.anillo / nombre(t + 25), [t + 25])
        real = shutil.copy2
        def desaparecer(src, dst):
            if Path(src).name == nombre(t + 5):
                Path(src).unlink()
                raise FileNotFoundError(src)
            return real(src, dst)
        with patch.object(ar.shutil, "copy2", side_effect=desaparecer):
            self.arch.pasada_pcap()
        self.assertEqual(self.arch.pcap_huecos, 3)  # borrado y saltos de nombre y paquetes

    def test_cierre_espera_fichero_posterior(self):
        t = 1_800_000_000
        self.a.hasta_epoch = t + 2
        pcap(self.anillo / nombre(t), [t + 2])
        self.arch.pasada_pcap()
        self.assertFalse(self.arch.fin_copiado())
        pcap(self.anillo / nombre(t + 5), [t + 5])
        self.arch.pasada_pcap()
        self.assertTrue(self.arch.fin_copiado())
        self.assertEqual(len(self.arch.copiados), 1)

    def test_espacio_bajo_falla_y_cierra_manifiesto(self):
        with patch.object(ar, "contadores", return_value={"utc": "inicio", "nic_rx_dropped": 0}), \
             patch.object(ar, "relojes", return_value={}), \
             patch.object(self.arch, "libre_gb", return_value=0.1):
            self.a.libre_minimo_gb = 1
            self.assertEqual(self.arch.correr(), 1)
        estado = json.loads((self.arch.dir / "estado.json").read_text())
        man = json.loads((self.arch.dir / "manifiesto.json").read_text())
        self.assertEqual((estado["estado"], estado["motivo"]), ("fallo", "espacio"))
        self.assertEqual(man["estado"], "incompleta")

    def test_hasta_releido_solo_crece(self):
        ruta = self.arch.dir / "HASTA_EPOCH"
        ruta.write_text("2000")
        self.arch.actualizar_hasta()
        ruta.write_text("1990")
        self.arch.actualizar_hasta()
        self.assertEqual(self.a.hasta_epoch, 2000)
        eventos = [json.loads(l) for l in (self.arch.dir / "eventos.jsonl").read_text().splitlines()]
        cambios = [x for x in eventos if x["tipo"] == "hasta_actualizado"]
        self.assertEqual([(x["anterior"], x["nuevo"]) for x in cambios], [(0, 2000)])

    def test_tope_se_ajusta_tras_confirmacion(self):
        self.a.hasta_max_epoch = 3000
        (self.arch.dir / "HASTA_MAX_EPOCH").write_text("2500")
        self.arch.actualizar_tope()
        self.assertEqual(self.a.hasta_max_epoch, 2500)
        (self.arch.dir / "HASTA_EPOCH").write_text("2600")
        self.arch.actualizar_hasta()
        self.assertEqual(self.a.hasta_epoch, 0)

    def test_tope_sin_fin_generador_cierra_incompleta(self):
        self.a.hasta_max_epoch = 1
        with patch.object(ar, "contadores", return_value={"utc": "inicio", "nic_rx_dropped": 0}), \
             patch.object(ar, "relojes", return_value={}), \
             patch.object(self.arch, "libre_gb", return_value=10):
            self.assertEqual(self.arch.correr(), 1)
        man = json.loads((self.arch.dir / "manifiesto.json").read_text())
        self.assertEqual((man["estado"], man["motivo"]), ("incompleta", "tope_sin_fin_generador"))
        self.assertIsNone(man["hasta_efectivo_epoch"])


if __name__ == "__main__":
    unittest.main()
