#!/usr/bin/env bash
# Lanza una ejecución V2 completa. Corre en el BASTIÓN como gadmin.
#   bash lanzar_v2.sh <programa.json> <ETIQUETA> <gb_necesarios>
# Ejemplos:
#   bash lanzar_v2.sh piloto-30min.json PILOTO 2
#   bash lanzar_v2.sh captura-42h.json C42 12
# Orden: identificador -> exclusión V1 -> preflight -> relojes -> registro DNS (DC1) ->
#        archivador (Sensor1) -> espera >= 2 min de captura previa -> generador (Clientes) -> vigía.
# Si algo falla antes del generador, no se lanza nada más y se deshace lo arrancado.
set -euo pipefail
PROG=${1:?programa}; TAG=${2:?etiqueta}; GB=${3:?gb_necesarios}
B=$HOME/cyberflow-v2/codigo                      # copia en el bastión
CL=/home/adminclientes/cyberflow-v2              # Clientes
S1=/home/m4rk/cyberflow-v2                       # Sensor1
DC=/home/dcadmin/cyberflow-v2                    # DC1
POBL=10.10.20.21,10.10.20.22,10.10.20.23,10.10.20.24,10.10.20.25,10.10.20.26
PREVIO_S=150; MARGEN_FIN_S=120
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"

ID="V2-${TAG}-$(date -u +%Y%m%dT%H%M%SZ)"
E=$HOME/cyberflow-v2/ejecuciones/$ID; mkdir -p "$E"
log() { printf '{"utc":"%s","paso":"%s","detalle":"%s"}\n' "$(date -u +%FT%T.%3NZ)" "$1" "$(echo "${2:-}" | tr -d '"\r' | tr '\n' ' ' | cut -c1-400)" | tee -a "$E/lanzamiento.jsonl"; }
DUR=$(python3 -c "import json,sys;print(int(json.load(open(sys.argv[1]))['duracion_s']))" "$B/programas/$PROG")
SHA=$(sha256sum "$B/programas/$PROG" | cut -c1-64)
T_ARCH=$(date +%s); INI=$((T_ARCH + PREVIO_S)); FIN=$((INI + DUR + MARGEN_FIN_S))
log identificador "$ID programa=$PROG sha256=$SHA duracion=$DUR inicio_previsto=$INI fin_captura=$FIN"

deshacer() { log deshacer "$1"
  $SSH dcadmin@10.10.10.20 "sudo -n systemctl stop cf-v2-dns-${ID,,}" 2>/dev/null || true
  $SSH sensor1 "pkill -TERM -f '[a]rchivar_v2.py --ejecucion $ID'" 2>/dev/null || true
  exit 1; }

# 1. V1 no aprende de esta ventana (respaldo del toml si hay que añadir la regla)
r=$($SSH sensor1 "python3 $S1/codigo/operacion/exclusion_v1.py --desde $((T_ARCH - 600)) --hasta $((FIN + 600))") || deshacer "exclusion_v1: $r"
log exclusion_v1 "$r"

# 2. Preflight del laboratorio (solo lectura)
if ! bash "$B/operacion/preflight_lab.sh" "$T_ARCH" "$FIN" "$GB" > "$E/preflight-lab.jsonl"; then
  log preflight fallo; cat "$E/preflight-lab.jsonl"; deshacer "preflight con fallos"; fi
log preflight ok

# 3. Relojes de los servidores (Clientes y Sensor1 los registran sus propios programas)
for h in srvdmz dcadmin@10.10.10.20; do
  $SSH "$h" 'date -u +%FT%T.%NZ; timedatectl show; (chronyc tracking 2>/dev/null || timedatectl timesync-status)' > "$E/relojes-inicio-${h#*@}.txt" 2>&1 || true
done
log relojes "srvdmz y dc1"

# 4. Registro DNS independiente en DC1 (unidad transitoria con tope de vida)
$SSH dcadmin@10.10.10.20 "sudo -n mkdir -p /var/log/cyberflow-v2 && sudo -n systemd-run --unit=cf-v2-dns-${ID,,} --property=RuntimeMaxSec=$((DUR + 3600)) /usr/bin/python3 $DC/servidor/registro_dns_v2.py --interfaz ens224 --salida /var/log/cyberflow-v2/dns-$ID.jsonl --poblacion $POBL" \
  || deshacer "no arrancó el registro DNS"
log registro_dns "cf-v2-dns-${ID,,}"

# 5. Archivador en Sensor1 (EVE + PCAP comprimido, parada por espacio)
# (el & solo debe afectar al archivador: con «a && b && c &» ssh espera a la subcapa y no regresa)
$SSH sensor1 "mkdir -p $S1/capturas; cd $S1/codigo/captura; setsid nohup python3 archivar_v2.py --ejecucion $ID --hasta-epoch $FIN --eve /var/log/suricata/eve.json --libre-minimo-gb 4 > $S1/capturas/archivador-$ID.txt 2>&1 < /dev/null &" \
  || deshacer "no arrancó el archivador"
for i in $(seq 1 30); do
  st=$($SSH sensor1 "cat $S1/capturas/$ID/estado.json 2>/dev/null" || true)
  echo "$st" | grep -q '"estado": *"ok"' && break; sleep 2
done
echo "$st" | grep -q '"estado": *"ok"' || deshacer "archivador sin estado ok: $st"
log archivador ok

# 6. Captura previa sin tráfico V2 (>= 2 min) y generador
while [ "$(date +%s)" -lt "$INI" ]; do sleep 5; done
r=$($SSH clientes "python3 $CL/codigo/operacion/v2ctl.py iniciar --programa $CL/codigo/programas/$PROG --ejecucion $ID --requiere-permiso") \
  || deshacer "v2ctl iniciar: $r"
log generador "$r"

# 7. Vigía (renueva el permiso mientras el archivador esté sano; si no, para el generador)
setsid nohup python3 "$B/operacion/vigia_v2.py" --ejecucion "$ID" \
  --estado-remoto "$S1/capturas/$ID/estado.json" \
  --permiso-remoto "$CL/ejecuciones/$ID/PERMISO_CAPTURA" \
  --v2ctl-remoto "$CL/codigo/operacion/v2ctl.py" \
  --registro "$E/vigia.jsonl" > "$E/vigia-salida.txt" 2>&1 < /dev/null &
log vigia "pid $!"
python3 - "$E" "$ID" "$PROG" "$SHA" "$T_ARCH" "$INI" "$FIN" "$DUR" <<'PY'
import json, sys
e, i, p, s, ta, ini, fin, dur = sys.argv[1:]
json.dump({"ejecucion": i, "programa": p, "programa_sha256": s, "archivador_desde_epoch": int(ta),
           "generador_previsto_epoch": int(ini), "captura_hasta_epoch": int(fin), "duracion_s": int(dur),
           "dns_unidad": "cf-v2-dns-" + i.lower()}, open(e + "/lanzamiento.json", "w"), indent=1)
PY
echo "$ID"
