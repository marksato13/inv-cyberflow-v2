"""sanear_pcap_tcp.py: solo las conexiones pedidas, MAC seudonimizadas, VLAN conservada."""
from __future__ import annotations

import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "captura"))
import sanear_pcap_tcp as st  # noqa: E402


def trama(src, sp, dst, dp, vlan=60, mac_a=b"\xaa" * 6, mac_b=b"\xbb" * 6):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x02, 1000, 0, 0)
    return mac_a + mac_b + struct.pack("!HH", 0x8100, vlan) + b"\x08\x00" + ip + tcp


class Saneado(unittest.TestCase):
    def test_filtra_y_seudonimiza(self):
        with tempfile.TemporaryDirectory() as t:
            ent, sal = Path(t) / "e.pcap", Path(t) / "s.pcap"
            tramas = [trama("10.10.20.22", 40000, "10.10.30.10", 80),
                      trama("10.10.30.10", 80, "10.10.20.22", 40000),
                      trama("10.10.20.22", 40001, "10.10.30.10", 80),       # otra conexión
                      trama("10.10.60.45", 5000, "10.10.30.10", 80)]        # equipo ajeno
            with open(ent, "wb") as f:
                f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                for x in tramas:
                    f.write(struct.pack("<IIII", 1, 0, len(x), len(x)) + x)
            r = st.sanear(ent, sal, ["10.10.20.22:40000"])
            self.assertEqual(r["salida"]["tramas"], 2)
            self.assertEqual(r["descartadas_por_motivo"], {"fuera_de_las_conexiones": 2})
            datos = sal.read_bytes()
            self.assertNotIn(b"\xaa" * 6, datos)
            self.assertNotIn(socket.inet_aton("10.10.60.45"), datos)
            self.assertIn(struct.pack("!HH", 0x8100, 60), datos)


if __name__ == "__main__":
    unittest.main()
