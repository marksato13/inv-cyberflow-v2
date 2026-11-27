#!/usr/bin/env bash
# ¿Está el laboratorio parado para V2? Corre en el BASTIÓN (gadmin), solo lectura. Una línea JSON por
# comprobación; sale con 0 si V2 está parado y la infraestructura permanente de V1 sigue en pie.
#
# Sustituye la comprobación improvisada de la 7.ª revisión, que preguntaba por `tcpdump-ring`: esa unidad
# NO existe en Sensor1 (LoadState not-found) y `systemctl is-active` responde «inactive» para una unidad
# inexistente, así que «tcpdump-ring inactivo» no decía nada (BLOQUE1-REVISION-8, §4). El anillo que copia
# el archivador V2 es /var/lib/ppi-motor-capture, de la unidad ppi-motor-capture.service (V1, permanente).
set -u
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"
fallos=0
ok() { printf '{"comprobacion":"%s","resultado":"%s","detalle":"%s"}\n' "$1" "$2" "$(echo "$3" | tr -d '"\r' | tr '\n' ' ' | cut -c1-300)"; [ "$2" = ok ] || fallos=$((fallos+1)); }

# Bastión: candado y procesos de una ejecución
[ -e "$HOME/cyberflow-v2/CAPTURA_EN_CURSO" ] && ok bastion_candado fallo "existe CAPTURA_EN_CURSO" || ok bastion_candado ok "sin candado"
p=$(pgrep -af '[l]anzar_v2|[c]errar_v2|[s]ondeo_span|[v]igia_v2|[v]igilar_referencias|[v]erificacion_dirigida' || true)
[ -z "$p" ] && ok bastion_procesos ok "ninguno" || ok bastion_procesos fallo "$p"

# Sensor1: nada de V2; V1 permanente en pie (anillo escribiéndose, Suricata, limpieza)
s=$($SSH sensor1 'pgrep -af "[a]rchivar_v2|[v]2ctl|[s]uricata_stats" || echo NINGUNO
echo "--"; systemctl is-active ppi-motor-capture suricata cyberflow-limpieza.timer | tr "\n" " "
echo; systemctl show tcpdump-ring -p LoadState --value
f=$(ls -t /var/lib/ppi-motor-capture/live-*.pcap* 2>/dev/null | head -1); [ -n "$f" ] && echo $(( $(date +%s) - $(stat -c %Y "$f") )) || echo sin_ficheros
cat ~/cyberflow-v2/codigo/VERSION 2>/dev/null || echo sin_version')
v2=$(echo "$s" | sed -n '1,/^--$/p' | sed '$d')
[ "$v2" = NINGUNO ] && ok sensor1_procesos_v2 ok "ninguno" || ok sensor1_procesos_v2 fallo "$v2"
r=$(echo "$s" | sed -n '/^--$/,$p' | sed 1d)
[ "$(echo "$r" | sed -n 1p)" = "active active active " ] && ok sensor1_v1_servicios ok "ppi-motor-capture, suricata, limpieza activos" || ok sensor1_v1_servicios fallo "$(echo "$r" | sed -n 1p)"
a=$(echo "$r" | sed -n 3p)
case "$a" in ''|*[!0-9]*) ok sensor1_anillo fallo "anillo: $a" ;; *) [ "$a" -lt 15 ] && ok sensor1_anillo ok "ultimo PCAP hace ${a} s" || ok sensor1_anillo fallo "ultimo PCAP hace ${a} s" ;; esac
ok sensor1_unidad_tcpdump_ring ok "LoadState $(echo "$r" | sed -n 2p) (no es el anillo; solo informativo)"
ok sensor1_codigo ok "$(echo "$r" | sed -n 4p)"

# Clientes: sin generadores
c=$($SSH clientes 'pgrep -af "[c]lientes_lab_v2|[v]2ctl" || echo NINGUNO')
[ "$c" = NINGUNO ] && ok clientes_procesos ok "ninguno" || ok clientes_procesos fallo "$c"

# srv-dmz: sin tcpdump de referencia de V2
d=$($SSH srvdmz 'pgrep -af "[t]cpdump .*V2-" || echo NINGUNO')
[ "$d" = NINGUNO ] && ok srvdmz_tcpdump_v2 ok "ninguno" || ok srvdmz_tcpdump_v2 fallo "$d"

# DC1: sin registrador DNS de V2 en marcha (unidades transitorias cf-v2-dns-*)
u=$($SSH dcadmin@10.10.10.20 'systemctl list-units --no-legend --state=active "cf-v2-dns-*" | wc -l')
[ "$u" = 0 ] && ok dc1_registro_dns ok "ninguna unidad cf-v2-dns-* activa" || ok dc1_registro_dns fallo "unidades activas: $u"

printf '{"parado":"%s","fallos":%d}\n' "$([ $fallos = 0 ] && echo si || echo no)" "$fallos"
[ $fallos = 0 ]
