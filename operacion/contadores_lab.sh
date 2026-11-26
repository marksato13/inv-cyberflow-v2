#!/usr/bin/env bash
# Instantánea de contadores para una ejecución V2. Corre en el BASTIÓN (gadmin), solo lectura.
#   bash contadores_lab.sh <fichero_salida.json>
# Switch: destino del SPAN (Gi2/0/19) y orígenes (Gi1/0/23, Gi2/0/23): paquetes de salida y
# output drops. Sensor1: ens37, softnet, estadísticas de tcpdump y Suricata (EVE dedicada). Aislamiento V1:
# sets de srv-dmz, reglas de DC1 y modo del agente. Cero descartes en tcpdump o Suricata no
# prueba que no haya pérdida antes del sensor: por eso se toman también los del switch.
set -u
OUT=${1:?salida}
sw() { timeout 30 ssh -n -o BatchMode=yes -o ConnectTimeout=8 sw-core-stack "$1" 2>&1 | tr -d '\r' | sed -E 's/Connection to [0-9.]+ closed by remote host\.//' | grep -v -E '^\*|^ *$'; }
{
  echo "=== utc $(date -u +%FT%T.%NZ)"
  for i in GigabitEthernet2/0/19 GigabitEthernet1/0/23 GigabitEthernet2/0/23; do
    echo "=== switch $i"; sw "show interfaces $i" | grep -E "line protocol|input rate|output rate|packets input|packets output|output drops|output errors|MTU"
  done
  echo "=== sensor1"
  ssh -n -o BatchMode=yes sensor1 'for k in rx_packets rx_bytes rx_dropped rx_missed_errors rx_errors; do echo "ens37_$k $(cat /sys/class/net/ens37/statistics/$k)"; done
    echo "softnet_dropped $(awk "{s+=strtonum(\"0x\"\$2)} END{print s}" /proc/net/softnet_stat)"
    journalctl -u ppi-motor-capture -n 200 --no-pager 2>/dev/null | grep -E "packets (captured|received|dropped)" | tail -3
    # stats.log omite los contadores a 0 (null-values: no): se lee el último stats de la EVE dedicada.
    # Una clave que no aparece = ausente, no 0.
    echo "suricata_stats $(tail -n 2000 /var/log/suricata/v2/eve.json 2>/dev/null | grep -F "\"event_type\":\"stats\"" | tail -n 1 | grep -oE "\"(uptime|kernel_packets|kernel_drops)\":[0-9]+" | tr "\n" " ")"'
  echo "=== aislamiento_v1"
  ssh -n -o BatchMode=yes srvdmz 'for s in limitados bloqueados; do echo "srvdmz_$s $(sudo -n nft list set inet cyberflow_dmz $s | grep -c elements)"; done
    echo "agente_aplicar $(systemctl cat ppi-enforce-agent-v2-dmz | grep "^ExecStart=/" | grep -c -- --aplicar)"'
  echo "dc1_nft_lineas $(ssh -n -o BatchMode=yes dcadmin@10.10.10.20 'sudo -n nft list ruleset | wc -l')"
} > "$OUT" 2>&1
echo "$OUT"
