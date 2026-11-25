#!/usr/bin/env bash
# Prueba E3 del cierre del bloque 1: ejecución V2 normal (lanzar_v2.sh con el sondeo del espejo
# integrado y el PCAP DNS de DC1) + captura de referencia en el extremo srv-dmz con los offloads
# (TSO/GSO/GRO/LRO) DESACTIVADOS en ens35, para contrastar paquete a paquete con Sensor1.
# Corre en el BASTIÓN. Conserva y restaura la configuración de offload; la registra antes y después.
#   bash prueba_espejo_b3.sh <programa.json> <TAG> [semilla]
set -u
PROG=${1:?programa}; TAG=${2:?tag}; SEM=${3:-3}
B1=~/cyberflow-v2/bloque1; OP=~/cyberflow-v2/codigo/operacion; S1=/home/m4rk/cyberflow-v2
EXT=/home/adminsrvdmz/bloque1; ETQ=$TAG-$(date -u +%Y%m%dT%H%M%SZ)
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"
mkdir -p "$B1"
# 1. Offload: registrar, desactivar, comprobar
$SSH srvdmz "ethtool -k ens35" > "$B1/offload-antes-$ETQ.txt"
$SSH srvdmz "sudo -n ethtool -K ens35 tso off gso off gro off lro off 2>&1; ethtool -k ens35 | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload):'" \
  | tee "$B1/offload-durante-$ETQ.txt"
restaurar() {
  python3 - "$B1/offload-antes-$ETQ.txt" > "$B1/offload-restaurar-$ETQ.txt" <<'PY'
import sys
m = {"tcp-segmentation-offload": "tso", "generic-segmentation-offload": "gso",
     "generic-receive-offload": "gro", "large-receive-offload": "lro"}
for l in open(sys.argv[1]):
    k, _, v = l.partition(":")
    if k.strip() in m and "fixed" not in v:
        print(m[k.strip()], v.split()[0])
PY
  $SSH srvdmz "sudo -n ethtool -K ens35 $(tr '\n' ' ' < "$B1/offload-restaurar-$ETQ.txt")"
  $SSH srvdmz "ethtool -k ens35" > "$B1/offload-despues-$ETQ.txt"
  diff <(grep -v fixed "$B1/offload-antes-$ETQ.txt") <(grep -v fixed "$B1/offload-despues-$ETQ.txt") \
    && echo "offload restaurado igual que antes" || echo "OFFLOAD DISTINTO DEL ORIGINAL"
}
trap restaurar EXIT
# 2. Captura del extremo (solo tráfico del servidor) y ejecución
$SSH srvdmz "mkdir -p $EXT; sudo -n setsid nohup tcpdump -i ens35 -n -s 0 -U -w $EXT/$ETQ.pcap 'host 10.10.30.10 and tcp and (port 80 or port 443)' > $EXT/$ETQ.log 2>&1 < /dev/null &"
sleep 3
( cd "$OP" && bash lanzar_v2.sh "$PROG" "$TAG" "$SEM" ) > "$B1/lanzar-$ETQ.txt" 2>&1
ID=$(grep -o "V2-$TAG-[0-9TZ]*" "$B1/lanzar-$ETQ.txt" | head -1)
echo "ejecucion $ID"
for i in $(seq 1 200); do
  $SSH sensor1 "cat $S1/capturas/$ID/estado.json" 2>/dev/null | grep -q '"estado": *"\(terminado\|fallo\)"' && break
  sleep 30
done
# tcpdump se para por PID (pkill -f con el texto del comando también casaría con esta sesión ssh)
$SSH srvdmz "for p in \$(pgrep -x tcpdump); do grep -qa $ETQ /proc/\$p/cmdline && sudo -n kill -INT \$p; done; sleep 2; cat $EXT/$ETQ.log"
restaurar; trap - EXIT
# 3. Cierre y contraste (ya sin captura en curso)
( cd "$OP" && bash cerrar_v2.sh "$ID" ) > "$B1/cerrar-$ID.txt" 2>&1; echo "cerrar rc=$?"
$SSH sensor1 "mkdir -p $S1/bloque1/extremo"
$SSH srvdmz "cat $EXT/$ETQ.pcap" | ssh -o BatchMode=yes sensor1 "cat > $S1/bloque1/extremo/$ID.pcap"
$SSH sensor1 "cd $S1/bloque1 && mkdir -p reanalisis && nice python3 $S1/codigo/captura/comparar_extremo.py --extremo extremo/$ID.pcap --sensor $S1/capturas/$ID/pcap --salida reanalisis/extremo-$ID.json; echo extremo rc=\$?"
echo "fin $ID"
