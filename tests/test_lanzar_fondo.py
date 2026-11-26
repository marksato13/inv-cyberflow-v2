"""Los procesos que los guiones dejan en segundo plano por ssh no deben retener la sesión.

`ssh host "A && B > log 2>&1 < /dev/null &"` manda a segundo plano la lista entera: la subshell
hereda la salida de ssh y la sesión no termina hasta que acaba B (VD1, 26-nov: la captura de
srv-dmz colgó lanzar_v2.sh). Solo el último comando puede ir con `&`, separado por `;`.
"""
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def test_sin_lista_and_en_segundo_plano():
    malas = []
    for f in sorted((RAIZ / "operacion").glob("*.sh")):
        for n, l in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if "nohup" in l and re.search(r"&\s*\"?\s*(\\|\|\||$)", l) and re.search(r"&&[^\"]*nohup", l):
                malas.append("%s:%d" % (f.name, n))
    assert not malas, malas
