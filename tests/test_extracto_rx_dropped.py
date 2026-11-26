"""Extracto publicable de la prueba de rx_dropped: misma clase, sin datos de infraestructura."""
import json
import struct
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "captura"))
import extracto_rx_dropped as er  # noqa: E402
import rx_dropped_prueba as rx  # noqa: E402

PVST_DST = bytes.fromhex("01000ccccccd")
SRC = bytes.fromhex("aabbccddeeff")


def pvst(vlan=20):
    llc_snap = bytes([0xAA, 0xAA, 0x03]) + bytes.fromhex("00000c") + struct.pack("!H", 0x010B)
    bpdu = bytes(range(1, 40))                       # «identificadores de puente»
    return (PVST_DST + SRC + struct.pack("!HH", 0x8100, vlan) + struct.pack("!H", len(llc_snap + bpdu))
            + llc_snap + bpdu)


def ipv4():
    return bytes(6) + SRC + struct.pack("!HH", 0x8100, 20) + struct.pack("!H", 0x0800) + bytes(40)


def pcap(ruta, tramas):
    with open(ruta, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, d in tramas:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(d), len(d)) + d)


def test_extracto(tmp_path):
    (tmp_path / "pcap").mkdir()
    pcap(tmp_path / "pcap" / "live-1.pcap", [(100.2, pvst()), (100.5, ipv4()), (101.1, pvst(30)), (300.0, pvst())])
    prueba = {"desde_epoch": 100.0, "hasta_epoch": 102.0, "ficheros": ["live-1.pcap"],
              "incremento": {"rx_dropped": 2, "rx_packets": 3},
              "serie": [{"s": 0, "rx_dropped": 1}, {"s": 1, "rx_dropped": 1}]}
    (tmp_path / "p.json").write_text(json.dumps(prueba))
    out = {k: tmp_path / ("x." + k) for k in ("pcap", "csv", "json")}
    assert er.main(["--prueba", str(tmp_path / "p.json"), "--pcap-dir", str(tmp_path / "pcap"),
                    "--salida-pcap", str(out["pcap"]), "--salida-csv", str(out["csv"]),
                    "--salida-json", str(out["json"])]) == 0
    r = json.loads(out["json"].read_text())
    assert r["tramas_sin_manejador"] == 2 and r["snap_802_3_igual_a_rx_dropped"]
    assert r["clases_iguales_a_rx_dropped"] == ["vlan/802.3_llc_snap"]
    assert r["por_protocolo"] == {"pvst+": 2}
    tramas = [d for _, est, d in rx.tramas(str(out["pcap"])) if est == "ok"]
    assert [rx.clase(d) for d in tramas] == ["vlan/802.3_llc_snap"] * 2
    for d in tramas:
        assert d[:6] == PVST_DST                      # multicast de protocolo: se conserva
        assert SRC not in d and d[6:9] == bytes([2, 0, 0])
        assert d[26:] == bytes(len(d) - 26)           # BPDU a ceros (tras VLAN + long + LLC/SNAP)
        assert len(d) == len(pvst())
