#!/usr/bin/env bash
# Verificación dirigida del Bloque 1 (revisión 26-nov, puntos 4, 6 y 8). NO es el piloto final.
# Corre en el BASTIÓN: lanzar_v2.sh con el programa corto de 24 min (sondas antes del periodo útil,
# captura de referencia en srv-dmz, PCAP DNS de DC1), espera al fin y cierra con cerrar_v2.sh.
#   bash verificacion_dirigida.sh <TAG> [programa] [gb]
set -u
TAG=${1:?tag}; PROG=${2:-prueba-niveles-transiciones.json}; GB=${3:-3}
OP=~/cyberflow-v2/codigo/operacion; S1=/home/m4rk/cyberflow-v2
B=~/cyberflow-v2/bloque1/verificacion; mkdir -p "$B"
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"
L="$B/lanzar-$TAG.txt"
( cd "$OP" && CF_TIPO_EJECUCION=verificacion_dirigida bash lanzar_v2.sh "$PROG" "$TAG" "$GB" ) > "$L" 2>&1; RC=$?; echo "lanzar rc=$RC"
ID=$(grep -o "V2-$TAG-[0-9TZ]*" "$L" | head -1); echo "ejecucion $ID"
[ -n "$ID" ] && [ "$RC" = 0 ] || { echo "lanzamiento fallido: no se espera ni se cierra"; exit 1; }
for i in $(seq 1 240); do
  $SSH sensor1 "cat $S1/capturas/$ID/estado.json" 2>/dev/null | grep -q '"estado": *"\(terminado\|fallo\)"' && break
  sleep 30
done
$SSH sensor1 "cat $S1/capturas/$ID/estado.json"
( cd "$OP" && bash cerrar_v2.sh "$ID" ) > "$B/cerrar-$ID.txt" 2>&1; echo "cerrar rc=$?"
$SSH sensor1 "cat $S1/pruebas/$ID/resultado-global.json" > "$B/resultado-global-$ID.json"
$SSH srvdmz "pgrep -x tcpdump >/dev/null && echo 'tcpdump de srv-dmz SIGUE VIVO' || echo 'srv-dmz sin tcpdump'"
echo "fin $ID"
