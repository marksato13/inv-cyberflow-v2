#!/usr/bin/env bash
# Reanálisis de B1, T1, T2, E1 y E2 con las herramientas corregidas del cierre del bloque 1.
# Corre en SENSOR1 (m4rk), solo lectura sobre capturas/ y pruebas/: escribe en bloque1/reanalisis/.
# No toca los resultados originales (bloque1/copias-*.json, extremo-*.json, pruebas/<ID>/).
#   bash reanalisis_bloque1.sh
set -u
S1=$HOME/cyberflow-v2; C=$S1/codigo; R=$S1/bloque1/reanalisis; mkdir -p "$R"
cd "$R"
echo "codigo $(cat $C/VERSION)" > version.txt
for ID in V2-B1-20261125T182207Z V2-T1-20261125T062528Z V2-T2-20261125T070500Z V2-E1-20261125T185323Z V2-E2-20261125T194609Z; do
  CAP=$S1/capturas/$ID; P=$S1/pruebas/$ID
  # E1 se reanalizó con cerrar_v2.sh en la prueba del cierre: sus datos de pruebas/ originales están en .original-cd06fcf
  [ -d "$P.original-cd06fcf" ] && P=$P.original-cd06fcf
  nice python3 $C/captura/copias_espejo.py $CAP/pcap --salida copias-$ID.json --detalle-umbral 0.4; echo "$ID copias rc=$?"
  nice python3 $C/captura/clases_tramas.py $CAP --salida clases-$ID.json > /dev/null; echo "$ID clases rc=$?"
  if [ -f "$P/registros/dns-$ID.jsonl" ]; then
    nice python3 $C/captura/contraste_dns.py --transacciones $P/generador/$ID/transacciones-*.jsonl \
      --dc1 $P/registros/dns-$ID.jsonl --capturas $CAP --salida dns-$ID.json --csv dns-$ID.csv > /dev/null; echo "$ID dns rc=$?"
  fi
  if [ -f "$S1/bloque1/extremo/$ID.pcap" ]; then
    nice python3 $C/captura/comparar_extremo.py --extremo $S1/bloque1/extremo/$ID.pcap --sensor $CAP/pcap \
      --salida extremo-$ID.json > /dev/null; echo "$ID extremo rc=$?"
  fi
done
# B1: tráfico de gestión (bastión 10.10.10.30 <-> Sensor1 10.10.60.11), el que provocó los descartes
ID=V2-B1-20261125T182207Z
nice python3 $C/captura/copias_espejo.py $S1/capturas/$ID/pcap --ips 10.10.10.30,10.10.60.11 \
  --salida copias-$ID-gestion.json --detalle-umbral 0.4 --max-anomalias 50000; echo "$ID copias-gestion rc=$?"
sha256sum *.json *.csv > SHA256SUMS
