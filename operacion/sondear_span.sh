#!/usr/bin/env bash
# Sondeo de solo lectura del destino SPAN (Gi2/0/19) con una sola sesión SSH al switch.
#   bash sondear_span.sh <segundos> <salida.txt> [intervalo_s]
# Cada línea lleva delante el epoch del BASTIÓN (el reloj del switch no está sincronizado:
# «show clock» sale con «*», no autoritativo). Por ciclo: contador «Total output drops»,
# «packets output», «bytes» y las filas de la cola 1 (encolado y descartes por umbral, en bytes)
# de «show platform hardware fed switch 2 qos queue stats interface Gi2/0/19».
set -u
DUR=${1:?segundos}; OUT=${2:?salida}; CADA=${3:-2}
FIN=$(( $(date +%s) + DUR ))
{
  echo "terminal length 0"
  while [ "$(date +%s)" -lt "$FIN" ]; do
    echo "show interfaces GigabitEthernet2/0/19 | include output drops|packets output"
    echo "show platform hardware fed switch 2 qos queue stats interface GigabitEthernet2/0/19 | include ^ 1 "
    sleep "$CADA"
  done
  echo "exit"
} | ssh -tt -o BatchMode=yes sw-core-stack 2>&1 | tr -d '\r' | while IFS= read -r l; do
  case "$l" in
    *"output drops"*|*"packets output"*|" 1 "*) printf '%s %s\n' "$(date +%s.%N)" "$l" ;;
  esac
done > "$OUT"
