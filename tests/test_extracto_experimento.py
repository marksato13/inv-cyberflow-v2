"""extracto_experimento.py: solo tráfico experimental; todo intacto salvo las MAC (HMAC)."""
from __future__ import annotations

import gzip
import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "captura"))
import extracto_experimento as ex  # noqa: E402

POB, SRV = ["10.10.20.22"], ["10.10.30.10", "10.10.10.20"]


def trama(src, dst, vlan=60, ttl=64, mac=b"\xaa\xbb\xcc\xdd\xee\x01"):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 7, 0, ttl, 6, 0x1234, socket.inet_aton(src), socket.inet_aton(dst))
    return b"\xff" * 6 + mac + struct.pack("!HH", 0x8100, vlan) + b"\x08\x00" + ip + b"\x00" * 20


def escribir(ruta, tramas, comprimir=False):
    datos = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)       # ns
    for i, t in enumerate(tramas):
        datos += struct.pack("<IIII", 100 + i, 123456789, len(t), len(t) + 4) + t
    (gzip.open if comprimir else open)(ruta, "wb").write(datos)


def leer(ruta):
    d = Path(ruta).read_bytes()
    i, out = 24, []
    while i < len(d):
        s, fr, incl, orig = struct.unpack("<IIII", d[i:i + 16])
        out.append((s, fr, incl, orig, d[i + 16:i + 16 + incl]))
        i += 16 + incl
    return d[:24], out


class Extracto(unittest.TestCase):
    def test_filtra_conserva_y_seudonimiza(self):
        with tempfile.TemporaryDirectory() as t:
            ent, sal, clave = Path(t) / "e.pcap.gz", Path(t) / "s.pcap", b"secreta"
            ts = [trama("10.10.20.22", "10.10.30.10"), trama("10.10.10.20", "10.10.20.22", vlan=10, ttl=63),
                  trama("10.10.60.45", "10.10.30.10"),           # ajeno
                  trama("10.10.20.22", "8.8.8.8")]               # población con un tercero
            escribir(ent, ts, comprimir=True)
            r = ex.filtrar_pcap(ent, sal, POB, SRV, clave)
            self.assertEqual(r["salida"]["tramas"], 2)
            self.assertEqual(r["descartadas_por_motivo"], {"fuera_del_experimento": 2})
            glob, fr = leer(sal)
            self.assertEqual(glob[:4], b"\x4d\x3c\xb2\xa1")                      # precisión ns conservada
            for (s, f, incl, orig, d), original in zip(fr, ts[:2]):
                self.assertEqual((f, incl, orig), (123456789, len(original), len(original) + 4))
                self.assertEqual(d[12:], original[12:])                         # VLAN, IP, TTL… intactos
                self.assertEqual(d[:6], b"\xff" * 6)                            # difusión sin tocar
                self.assertNotEqual(d[6:12], original[6:12])
                self.assertEqual(d[6], 2)
            # determinista: la misma MAC y clave dan el mismo seudónimo en otro fichero
            ex.filtrar_pcap(ent, Path(t) / "s2.pcap", POB, SRV, clave)
            self.assertEqual(Path(t, "s2.pcap").read_bytes(), sal.read_bytes())

    def test_eve(self):
        with tempfile.TemporaryDirectory() as t:
            e = Path(t) / "eve.json"
            e.write_text("\n".join(json.dumps(x) for x in [
                {"src_ip": "10.10.20.22", "dest_ip": "10.10.10.20", "ether": {"src_mac": "aa:bb"}, "dns": {}},
                {"src_ip": "10.10.60.45", "dest_ip": "10.10.10.20", "dns": {"rrname": "ajeno"}}]) + "\n")
            r = ex.filtrar_eve(e, Path(t) / "s.json", POB, SRV)
            self.assertEqual(r["salida"]["eventos"], 1)
            self.assertNotIn("ether", (Path(t) / "s.json").read_text())


if __name__ == "__main__":
    unittest.main()
