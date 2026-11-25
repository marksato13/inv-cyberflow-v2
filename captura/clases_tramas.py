#!/usr/bin/env python3
"""Cuenta las tramas de una captura archivada por clase (VLAN + ethertype / 802.3-LLC) y las compara
con los contadores de la NIC que el archivador guardó en su manifiesto.

    python3 clases_tramas.py capturas/<ID> --salida c.json

Sirve para la prueba retrospectiva de rx_dropped: si las tramas 802.3/SNAP etiquetadas (PVST+ y CDP,
que Linux no tiene a quién entregar) coinciden con delta_nic_rx_dropped y el total de tramas del PCAP
coincide con delta_nic_rx_packets, el contador no indica tramas perdidas por la captura. Los deltas
del manifiesto se miden al arrancar y al parar el archivador, que no coincide exactamente con el
primer y el último paquete archivado: la diferencia en los bordes se informa, no se oculta.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rx_dropped_prueba import clase, tramas  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captura", type=Path, help="capturas/<ID> (con pcap/ y manifiesto.json)")
    ap.add_argument("--salida", type=Path, required=True)
    a = ap.parse_args()
    total, incid = collections.Counter(), []
    ficheros = sorted((a.captura / "pcap").glob("live-*.pcap*"))
    primero = ultimo = None
    for f in ficheros:
        try:
            for ts, est, d in tramas(str(f)):
                if est != "ok":
                    incid.append({"fichero": f.name, "estado": est})
                    continue
                primero = ts if primero is None else min(primero, ts)
                ultimo = ts if ultimo is None else max(ultimo, ts)
                total[clase(d)] += 1
        except (OSError, ValueError, EOFError) as e:
            incid.append({"fichero": f.name, "error": str(e)})
    try:
        man = json.loads((a.captura / "manifiesto.json").read_text())
    except (OSError, ValueError):
        man = {}
    snap = total.get("vlan/802.3_llc_snap", 0)
    n = sum(total.values())
    out = {"version": "1.0", "captura": str(a.captura), "ficheros": len(ficheros), "incidencias": incid,
           "primer_paquete": primero, "ultimo_paquete": ultimo, "tramas": n, "por_clase": dict(total.most_common()),
           "manifiesto": {k: man.get(k) for k in ("delta_nic_rx_packets", "delta_nic_rx_dropped", "inicio", "fin",
                                                   "pcap_huecos", "kernel_drops", "estado")},
           "comparacion": {
               "tramas_pcap_menos_rx_packets": n - man["delta_nic_rx_packets"] if man.get("delta_nic_rx_packets") is not None else None,
               "snap_etiquetadas_menos_rx_dropped": snap - man["delta_nic_rx_dropped"] if man.get("delta_nic_rx_dropped") is not None else None}}
    a.salida.write_text(json.dumps(out, indent=1, ensure_ascii=False))
    print(json.dumps({k: out[k] for k in ("tramas", "por_clase", "manifiesto", "comparacion")}, ensure_ascii=False))
    return 3 if incid else 0


if __name__ == "__main__":
    raise SystemExit(main())
