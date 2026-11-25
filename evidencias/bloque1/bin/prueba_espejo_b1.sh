#!/usr/bin/env bash
# Prueba B1 del bloque 1 (calidad de captura): fondo sin generadores y reproducción controlada de
# transferencias de gestión que cruzan el cortafuegos (bastión VLAN 10 <-> Sensor1 VLAN 60).
# Se ejecuta en el bastión. Sin generadores, sin vigía. Solo lectura en el switch.
#   bash prueba_espejo_b1.sh
# Fases (marcas en marcas.jsonl con epoch del bastión):
#   F0 fondo 300 s | R1 5x «tail -n 2000» de la EVE (orden actual del vigía) cada 30 s |
#   R2 5x la misma lectura filtrada en Sensor1 (solo la última línea stats) cada 30 s |
#   R3 3x subida de 20 MB sin límite | R4 3x subida de 20 MB con scp -l 160000 (160 Mb/s) | F1 fondo 240 s
set -u
ID=V2-B1-$(date -u +%Y%m%dT%H%M%SZ)
E=~/cyberflow-v2/bloque1/$ID; mkdir -p "$E"; S1=/home/m4rk/cyberflow-v2
cd "$(dirname "$0")"
marca() { printf '{"epoch": %s, "fase": "%s", "evento": "%s"}\n' "$(date +%s.%N)" "$1" "$2" >> "$E/marcas.jsonl"; }
AHORA=$(date +%s); HASTA=$(( AHORA + 30 + 300 + 150 + 150 + 240 + 240 + 240 ))
ssh -n -o BatchMode=yes sensor1 "mkdir -p $S1/capturas; cd $S1/codigo/captura; setsid nohup python3 archivar_v2.py --ejecucion $ID --hasta-epoch $HASTA --hasta-max-epoch $((HASTA+600)) --margen-final-s 15 --eve /var/log/suricata/v2/eve.json --libre-minimo-gb 4 > $S1/capturas/archivador-$ID.txt 2>&1 < /dev/null &"
for i in $(seq 1 30); do ssh -n -o BatchMode=yes sensor1 "cat $S1/capturas/$ID/estado.json 2>/dev/null" | grep -q '"estado": *"ok"' && break; sleep 2; done
marca archivador confirmado
head -c 20000000 /dev/urandom > "$E/carga-20MB.bin"
bash sondear_span.sh $(( HASTA - $(date +%s) + 20 )) "$E/sondeo.txt" 2 &
SONDEO=$!
sleep 30
marca F0 inicio; sleep 300; marca F0 fin
for i in 1 2 3 4 5; do marca R1 "tail2000-$i"; ssh -n -o BatchMode=yes sensor1 "tail -n 2000 /var/log/suricata/v2/eve.json" > /dev/null; marca R1 "fin-$i"; sleep 30; done
for i in 1 2 3 4 5; do marca R2 "filtrada-$i"; ssh -n -o BatchMode=yes sensor1 "tail -n 2000 /var/log/suricata/v2/eve.json | grep -F '\"event_type\":\"stats\"' | tail -n 1" > /dev/null; marca R2 "fin-$i"; sleep 30; done
for i in 1 2 3; do marca R3 "subida-$i"; scp -q -o BatchMode=yes "$E/carga-20MB.bin" sensor1:/tmp/cf-b1-carga.bin; marca R3 "fin-$i"; sleep 75; done
for i in 1 2 3; do marca R4 "subida-limitada-$i"; scp -q -l 160000 -o BatchMode=yes "$E/carga-20MB.bin" sensor1:/tmp/cf-b1-carga.bin; marca R4 "fin-$i"; sleep 60; done
marca F1 inicio
wait "$SONDEO"
marca F1 fin
ssh -n -o BatchMode=yes sensor1 "rm -f /tmp/cf-b1-carga.bin"
rm -f "$E/carga-20MB.bin"
echo "$ID"
