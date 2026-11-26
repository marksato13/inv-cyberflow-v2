"""Los procesos que los guiones dejan en segundo plano por ssh no deben retener la sesión.

`ssh host "A && B > log 2>&1 < /dev/null &"` manda a segundo plano la lista entera: la subshell
hereda la salida de ssh y la sesión no termina hasta que acaba B (VD1, 26-nov: la captura de
srv-dmz colgó lanzar_v2.sh). Solo el último comando puede ir con `&`, separado por `;`.
"""
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def test_sondeo_cubre_el_margen_previo_del_archivador():
    """El primer paquete archivado es anterior al arranque del archivador (margen previo + rotación):
    el lanzador espera a que el sondeo lleve ese tiempo antes de arrancarlo (E3 y VD2 sin sondeo al
    principio)."""
    sys_path = str(RAIZ / "captura")
    import sys
    sys.path.insert(0, sys_path)
    import archivar_v2 as av
    t = (RAIZ / "operacion" / "lanzar_v2.sh").read_text(encoding="utf-8")
    m = int(re.search(r"MARGEN_PREVIO_ARCH_S=(\d+)", t).group(1))
    assert "--margen-previo $MARGEN_PREVIO_ARCH_S" in t
    espera = re.search(r"T_SONDEO \+ MARGEN_PREVIO_ARCH_S \+ (\d+) \+ (\d+)", t)
    assert espera and int(espera.group(1)) >= av.ROTACION_S
    assert t.index("T_SONDEO=") < t.index("archivar_v2.py --ejecucion")
    assert m >= 0


def test_sin_lista_and_en_segundo_plano():
    malas = []
    for f in sorted((RAIZ / "operacion").glob("*.sh")):
        for n, l in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if "nohup" in l and re.search(r"&\s*\"?\s*(\\|\|\||$)", l) and re.search(r"&&[^\"]*nohup", l):
                malas.append("%s:%d" % (f.name, n))
    assert not malas, malas
