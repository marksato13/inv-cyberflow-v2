#!/usr/bin/env bash
# Prueba dirigida (Bloque 1, revisión 26-nov, punto 9): ¿dónde se pierden las copias de gestión?
# Corre en el BASTIÓN (gadmin). SOLO LECTURA de contadores; no cambia SPAN, búferes, vSwitch ni VM.
# Necesita que NO haya ninguna ejecución V2 en curso (genera tráfico por el cortafuegos).
#   bash prueba_gestion_esxi.sh <ETIQUETA>
# Fases (como B1): F0 fondo 60 s | R3 1x scp 20 MB sin límite | R4 3x scp -l 160000 | F1 fondo 60 s.
# En cada marca lee la cadena completa del espejo:
#   switch CORE-STACK: Gi2/0/19 (destino) y Gi1/0/23, Gi2/0/23 (orígenes): paquetes y descartes;
#   ESXi esxi-hv-siem: vmnic2 (NIC física) y puertos de vSwitch2: enlace 2281701388, Sensor1
#     134217746, VM-SURICATA 134217750 (pktsRx/droppedRx) + vmxnet3 rxSummary de Sensor1;
#   Sensor1: ens37 (rx_packets/rx_dropped) y ethtool -S.
# Al final archiva en Sensor1 los PCAP del anillo del periodo (privados) y cuenta copias de gestión
# por fase con copias_espejo.py.
set -u
TAG=${1:?etiqueta}
B=$HOME/cyberflow-v2/bloque1/$TAG; mkdir -p "$B"; S1=/home/m4rk/cyberflow-v2
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"
if $SSH sensor1 "pgrep -f '[a]rchivar_v2.py' >/dev/null" || $SSH clientes "pgrep -f '[c]lientes_lab_v2.py' >/dev/null"; then
  echo "hay una ejecución en curso: no se hace la prueba"; exit 1; fi
sw() { timeout 30 ssh -n -o BatchMode=yes -o ConnectTimeout=8 sw-core-stack "$1" 2>&1 | tr -d '\r'; }
contadores() {  # $1 = marca
  local f="$B/contadores-$1.txt"
  { echo "## utc $(date -u +%FT%T.%NZ) epoch $(date +%s.%N)"
    for i in Gi2/0/19 Gi1/0/23 Gi2/0/23; do echo "## switch $i"; sw "show interfaces $i" | grep -E "packets input|packets output|output drops|input errors|output errors"; done
    echo "## esxi"
    $SSH esxi-hv-siem 'esxcli network nic stats get -n vmnic2 | grep -E "Packets received|Receive packets dropped|Total receive errors|Receive missed errors|Receive FIFO errors";
      for p in 2281701388 134217746 134217750; do echo "port $p"; vsish -e get /net/portsets/vSwitch2/ports/$p/stats | grep -E "pktsRx:|droppedRx:"; done;
      echo "vmxnet3 134217746"; vsish -e get /net/portsets/vSwitch2/ports/134217746/vmxnet3/rxSummary | grep -E "pkts rx ok:|running out of buffers|ring is full|dropped"'
    echo "## sensor1"
    $SSH sensor1 'for k in rx_packets rx_dropped rx_nohandler rx_missed_errors; do echo "$k $(cat /sys/class/net/ens37/statistics/$k)"; done; ethtool -S ens37 | grep -iE "drop|err|fail|full" | grep -v ": 0$"'
  } > "$f" 2>&1
  printf '{"utc":"%s","epoch":%s,"marca":"%s"}\n' "$(date -u +%FT%T.%3NZ)" "$(date +%s.%N)" "$1" >> "$B/marcas.jsonl"
}
head -c 20000000 /dev/urandom > "$B/carga-20MB.bin"
contadores C0-inicio
sleep 60
contadores C1-fin-F0
scp -q -o BatchMode=yes "$B/carga-20MB.bin" sensor1:/tmp/cf-esxi-carga.bin
sleep 5; contadores C2-fin-R3
sleep 30; contadores C3-inicio-R4
for i in 1 2 3; do scp -q -l 160000 -o BatchMode=yes "$B/carga-20MB.bin" sensor1:/tmp/cf-esxi-carga.bin; sleep 20; done
contadores C4-fin-R4
sleep 60
contadores C5-fin-F1
rm -f "$B/carga-20MB.bin"; $SSH sensor1 "rm -f /tmp/cf-esxi-carga.bin"
sleep 12   # cierra el fichero del anillo en curso (-G 5)
# Archivo de los PCAP del anillo del periodo y copias por fase (en Sensor1, privado)
T0=$(head -1 "$B/marcas.jsonl" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['epoch'])")
T1=$(tail -1 "$B/marcas.jsonl" | python3 -c "import json,sys;print(json.loads(sys.stdin.read())['epoch'])")
scp -q -o BatchMode=yes "$B/marcas.jsonl" sensor1:/tmp/cf-esxi-marcas.jsonl
$SSH sensor1 "set -u; A=$S1/bloque1/$TAG; mkdir -p \$A/pcap; cp /tmp/cf-esxi-marcas.jsonl \$A/marcas.jsonl
  for f in /var/lib/ppi-motor-capture/live-*.pcap*; do m=\$(stat -c %Y \$f); awk -v m=\$m -v a=$T0 -v b=$T1 'BEGIN{exit !(m>=a-10 && m<=b+20)}' && cp -p \$f \$A/pcap/; done
  cd \$A && sha256sum pcap/* > SHA256SUMS && ls pcap | wc -l
  python3 $S1/codigo/captura/copias_espejo.py \$A/pcap --ips 10.10.10.30,10.10.60.11 --salida copias-gestion.json --detalle-umbral 0.4 --max-anomalias 50000 > /dev/null; echo copias rc=\$?"
echo "fin $TAG"
