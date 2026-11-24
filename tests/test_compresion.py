"""Compresión verificada del archivador y lectura de .pcap.gz en la cobertura."""
import gzip
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "captura"))
import archivar_v2 as arch  # noqa: E402
import cobertura_v2 as cob  # noqa: E402


def pcap_minimo(n=3):
    cab = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    trama = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
    return cab + b"".join(struct.pack("<IIII", 1000 + i, 0, len(trama), len(trama)) + trama for i in range(n))


class TestCompresion(unittest.TestCase):
    def test_comprimir_verificado_conserva_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "live-20261124000000.pcap"
            datos = pcap_minimo(50)
            p.write_bytes(datos)
            sha = hashlib.sha256(datos).hexdigest()
            r = arch.comprimir_verificado(p, sha)
            self.assertTrue(r["comprimido"])
            self.assertFalse(p.exists())
            self.assertEqual(gzip.decompress((Path(d) / r["fichero_archivado"]).read_bytes()), datos)

    def test_sha_distinto_conserva_original(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "live-20261124000000.pcap"
            p.write_bytes(pcap_minimo(5))
            r = arch.comprimir_verificado(p, "0" * 64)
            self.assertFalse(r["comprimido"])
            self.assertTrue(p.exists())
            self.assertFalse(p.with_name(p.name + ".gz").exists())

    def test_cobertura_lee_gz_igual_que_sin_comprimir(self):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / "a.pcap"
            b = Path(d) / "b.pcap.gz"
            datos = pcap_minimo(7)
            a.write_bytes(datos)
            b.write_bytes(gzip.compress(datos))
            self.assertEqual(list(cob.paquetes(a)), list(cob.paquetes(b)))


if __name__ == "__main__":
    unittest.main()
