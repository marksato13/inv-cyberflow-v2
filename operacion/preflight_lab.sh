#!/usr/bin/env bash
# Comprobación previa del laboratorio para una ejecución V2. Corre en el BASTIÓN (gadmin), solo lectura.
# Sale con código 0 si todo cumple; con 1 si algo falla. Escribe una línea JSON por comprobación.
# Uso: bash preflight_lab.sh <inicio_epoch> <fin_epoch> <gb_necesarios>
set -u
INI=${1:?inicio_epoch}; FIN=${2:?fin_epoch}; GB=${3:?gb_necesarios}
fallos=0
ok() { printf '{"comprobacion":"%s","resultado":"%s","detalle":"%s"}\n' "$1" "$2" "$(echo "$3" | tr -d '"\r' | tr '\n' ' ' | cut -c1-300)"; [ "$2" = ok ] || fallos=$((fallos+1)); }
sw() { timeout 30 ssh -n -o BatchMode=yes -o ConnectTimeout=8 sw-core-stack "$1" 2>&1 | tr -d '\r' | sed -E 's/Connection to [0-9.]+ closed by remote host\.//' | grep -v -E '^\*|^ *$'; }
# (el aviso de cierre del switch llega pegado a la última línea, sin salto: se recorta, no se descarta la línea)

# 1. Espejo: sesión, destino a 1000, MTU del destino
m=$(sw "show monitor session 1")
echo "$m" | grep -q "Both *: Gi1/0/23,Gi2/0/23" && echo "$m" | grep -q "Destination Ports *: Gi2/0/19" \
  && ok span_sesion ok "Gi1/0/23,Gi2/0/23 both -> Gi2/0/19" || ok span_sesion fallo "$m"
st=$(sw "show interfaces GigabitEthernet2/0/19 status" | grep Gi2/0/19)
echo "$st" | grep -q "a-1000" && ok span_destino_velocidad ok "$st" || ok span_destino_velocidad fallo "$st"
mt=$(sw "show interfaces Gi2/0/19" | grep -o "MTU [0-9]*")
[ "$mt" = "MTU 9198" ] && ok span_destino_mtu ok "$mt" || ok span_destino_mtu fallo "$mt"
v=$(ssh -n esxi-hv-siem 'esxcli network nic list' 2>&1 | awk '$1=="vmnic2"{print $6}')
[ "$v" = 1000 ] && ok vmnic2_velocidad ok "$v" || ok vmnic2_velocidad fallo "$v"

# 2. Sensor1: NIC de captura, servicios de captura, espacio real donde escribe el archivador
s=$(ssh -n sensor1 'ip -o link show ens37; systemctl is-active ppi-motor-capture suricata cyberflow-limpieza.timer; df -B1 --output=avail ~/cyberflow-v2 | tail -1; timedatectl show -p NTPSynchronized --value')
echo "$s" | head -1 | grep -q "PROMISC" && echo "$s" | head -1 | grep -q "UP" && ok ens37 ok "UP PROMISC" || ok ens37 fallo "$s"
[ "$(echo "$s" | sed -n 2,4p | sort -u)" = active ] && ok sensor1_servicios ok "captura, suricata, limpieza" || ok sensor1_servicios fallo "$(echo "$s" | sed -n 2,4p)"
libre=$(echo "$s" | sed -n 5p); need=$(awk -v g="$GB" 'BEGIN{printf "%d", (g+4)*1e9}')
[ "$libre" -ge "$need" ] && ok sensor1_espacio ok "libre $((libre/1000000000)) GB >= necesario ${GB} + 4 GB" || ok sensor1_espacio fallo "libre $((libre/1000000000)) GB < ${GB}+4"
[ "$(echo "$s" | sed -n 6p)" = yes ] && ok ntp_sensor1 ok yes || ok ntp_sensor1 fallo "$(echo "$s" | sed -n 6p)"

# 3. Exclusión V1: una regla *@a/b del toml debe cubrir [inicio, fin]
cub=$(ssh -o BatchMode=yes sensor1 "python3 - $INI $FIN" <<'PY'
import sys, tomllib, datetime as d
a, b = float(sys.argv[1]), float(sys.argv[2])
t = tomllib.load(open("/home/m4rk/cyberflow/configs/cyberflow.local.toml", "rb"))
ok = []
for r in t["reentrenamiento"]["excluir_ventanas"]:
    ent, rng = r.split("@", 1); x, y = rng.split("/")
    if ent == "*" and d.datetime.fromisoformat(x).timestamp() <= a and d.datetime.fromisoformat(y).timestamp() >= b:
        ok.append(r)
print("ok " + ok[0] if ok else "fallo sin regla *@ que cubra la ejecucion")
PY
)
ok exclusion_v1 "${cub%% *}" "${cub#* }"

# 4. srv-dmz: servidor V2 con registro y límite; sets de restricción vacíos; agente sin --aplicar
d=$(ssh -n srvdmz 'ps -o args= -C python3 | grep servidor_lab_v2 | grep -c -- "--limite-bps 5000000"; sudo -n nft list set inet cyberflow_dmz limitados | grep -c elements; sudo -n nft list set inet cyberflow_dmz bloqueados | grep -c elements; systemctl cat ppi-enforce-agent-v2-dmz | grep "^ExecStart=/" | grep -c -- --aplicar; timedatectl show -p NTPSynchronized --value')
[ "$(echo "$d" | sed -n 1p)" = 2 ] && ok servidor_v2 ok "http y https con registro y limite 5 MB/s" || ok servidor_v2 fallo "procesos=$(echo "$d" | sed -n 1p)"
[ "$(echo "$d" | sed -n 2p)$(echo "$d" | sed -n 3p)" = 00 ] && ok srvdmz_sets_vacios ok "limitados y bloqueados vacios" || ok srvdmz_sets_vacios fallo "$d"
[ "$(echo "$d" | sed -n 4p)" = 0 ] && ok agente_v1_sombra ok "sin --aplicar" || ok agente_v1_sombra fallo "agente con --aplicar"
[ "$(echo "$d" | sed -n 5p)" = yes ] && ok ntp_srvdmz ok yes || ok ntp_srvdmz fallo "$(echo "$d" | sed -n 5p)"

# 5. DC1: sin reglas nft, zona controlada y NTP
c=$(ssh -n dcadmin@10.10.10.20 'sudo -n nft list ruleset | wc -l; timedatectl show -p NTPSynchronized --value')
[ "$(echo "$c" | sed -n 1p)" = 0 ] && ok dc1_sin_restricciones ok "nft vacio" || ok dc1_sin_restricciones fallo "$c"
[ "$(echo "$c" | sed -n 2p)" = yes ] && ok ntp_dc1 ok yes || ok ntp_dc1 fallo "$c"

# 6. Clientes: NTP y ninguna ejecución V2 viva
k=$(ssh -n clientes 'timedatectl show -p NTPSynchronized --value; pgrep -fc "[c]lientes_lab_v2|[v]2ctl.py _supervisar"')
[ "$(echo "$k" | sed -n 1p)" = yes ] && ok ntp_clientes ok yes || ok ntp_clientes fallo "$k"
[ "$(echo "$k" | sed -n 2p)" = 0 ] && ok clientes_libre ok "sin generadores vivos" || ok clientes_libre fallo "$k"

printf '{"preflight":"%s","fallos":%d}\n' "$([ $fallos = 0 ] && echo ok || echo fallo)" "$fallos"
[ $fallos = 0 ]
