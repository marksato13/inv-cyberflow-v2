#!/usr/bin/env bash
# Prueba B2 del bloque 1: ejecución V2 normal (lanzar_v2.sh) con dos observaciones añadidas:
#  - sondeo del destino SPAN cada ~2 s (sondear_span.sh, solo lectura);
#  - captura independiente en el extremo srv-dmz (tcpdump en ens35, solo 10.10.30.10:80/443).
# Al terminar la captura cierra la ejecución (cerrar_v2.sh) y, ya sin captura en curso, copia la
# captura del extremo a Sensor1 para contrastarla con lo recibido por el espejo.
#   bash prueba_espejo_b2.sh <programa.json> <TAG> [semilla]
set -u
PROG=${1:?programa}; TAG=${2:?tag}; SEM=${3:-2}
B1=~/cyberflow-v2/bloque1; OP=~/cyberflow-v2/codigo/operacion; S1=/home/m4rk/cyberflow-v2
cd "$B1/bin"
EXT=/home/adminsrvdmz/bloque1; ETQ=$TAG-$(date -u +%Y%m%dT%H%M%SZ)
ssh -n -o BatchMode=yes srvdmz "mkdir -p $EXT; sudo -n setsid nohup tcpdump -i ens35 -n -s 0 -U -w $EXT/$ETQ.pcap 'host 10.10.30.10 and tcp and (port 80 or port 443)' > $EXT/$ETQ.log 2>&1 < /dev/null &"
sleep 3
DUR=$(python3 -c "import json;print(int(json.load(open('$OP/../programas/$PROG'))['duracion_s']))")
bash sondear_span.sh $(( DUR + 600 )) "$B1/sondeo-$ETQ.txt" 2 &
SONDEO=$!
( cd "$OP" && bash lanzar_v2.sh "$PROG" "$TAG" "$SEM" ) > "$B1/lanzar-$ETQ.txt" 2>&1
ID=$(grep -o "V2-$TAG-[0-9TZ]*" "$B1/lanzar-$ETQ.txt" | head -1)
echo "ejecucion $ID"
for i in $(seq 1 200); do
  ssh -n -o BatchMode=yes sensor1 "cat $S1/capturas/$ID/estado.json" 2>/dev/null | grep -q '"estado": *"\(terminado\|fallo\)"' && break
  sleep 30
done
ssh -n -o BatchMode=yes srvdmz "sudo -n pkill -INT -f 'tcpdump -i ens35 -n -s 0 -U -w $EXT/$ETQ.pcap'; sleep 2; cat $EXT/$ETQ.log"
kill "$SONDEO" 2>/dev/null; wait "$SONDEO" 2>/dev/null
( cd "$OP" && bash cerrar_v2.sh "$ID" ) > "$B1/cerrar-$ID.txt" 2>&1
ssh -n -o BatchMode=yes sensor1 "mkdir -p $S1/bloque1/extremo"
ssh -n -o BatchMode=yes srvdmz "cat $EXT/$ETQ.pcap" | ssh -o BatchMode=yes sensor1 "cat > $S1/bloque1/extremo/$ID.pcap"
mv "$B1/sondeo-$ETQ.txt" "$B1/sondeo-$ID.txt"
ssh -n -o BatchMode=yes sensor1 "cd $S1/bloque1 && nice python3 $S1/codigo/captura/copias_espejo.py $S1/capturas/$ID/pcap --salida copias-$ID.json --detalle-umbral 0.4 && nice python3 $S1/codigo/captura/comparar_extremo.py --extremo extremo/$ID.pcap --sensor $S1/capturas/$ID/pcap --salida extremo-$ID.json"
echo "fin $ID"
