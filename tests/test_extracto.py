"""El extracto publicable conserva lo que hace falta para repetir la comprobación de copias."""
import shutil
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

from captura import copias_espejo as ce
from tests.test_copias_espejo import pcap, trama

RAIZ = Path(__file__).resolve().parents[1]


class ExtractoTest(unittest.TestCase):
    def setUp(self):
        self.raiz = Path(__file__).resolve().parent / (".extracto-" + uuid.uuid4().hex)
        (self.raiz / "a" / "pcap").mkdir(parents=True)
        (self.raiz / "b" / "pcap").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.raiz)

    def test_completas_cabeceras_y_descartes(self):
        t = [trama(100, vlan=20), trama(100.0002, vlan=30, ttl=63),                       # experimental
             trama(101, "10.10.10.30", "10.10.60.11", ipid=7, vlan=10, payload=b"x" * 1000),  # gestión
             trama(101.0002, "10.10.10.30", "10.10.60.11", ipid=7, vlan=60, ttl=63, payload=b"x" * 1000),
             trama(102, "10.10.50.52", "10.10.10.20", ipid=9, vlan=50),                     # ajeno
             trama(103, "10.10.10.30", "10.10.60.10", ipid=11, vlan=10)]                    # bastión → equipo ajeno
        pcap(self.raiz / "a" / "pcap" / "live-20250101000000.pcap", t)
        salida = self.raiz / "b" / "pcap" / "live-20250101000000.pcap.gz"
        r = subprocess.run([sys.executable, str(RAIZ / "captura" / "extracto_pcap.py"), str(self.raiz / "a" / "pcap"),
                            "--salida", str(salida), "--completas", "10.10.20.21",
                            "--cabeceras", "10.10.10.30,10.10.60.11"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"completa": 2', r.stdout)
        self.assertIn('"cabeceras": 2', r.stdout)
        self.assertIn('"descartada_fuera_de_poblacion": 2', r.stdout)
        exp = ce.analizar(self.raiz / "b" / "pcap", ips={"10.10.20.21"})
        ges = ce.analizar(self.raiz / "b" / "pcap", ips={"10.10.10.30", "10.10.60.11"})
        self.assertEqual(exp["denominadores"]["eventos_por_clase"], {"completo": 1})
        self.assertEqual(ges["denominadores"]["eventos_por_clase"], {"completo": 1})
        self.assertTrue(exp["entrada_completa"] and ges["entrada_completa"])
        # las cabeceras recortadas conservan la longitud original de la trama
        datos = [x for x in ce.tramas(salida)]
        self.assertEqual([len(d) for _, _, d in datos], [len(t[0][1]), len(t[1][1]), 96, 96])
        self.assertEqual(datos[2][1], len(t[2][1]))


if __name__ == "__main__":
    unittest.main()
