#!/usr/bin/env bash
# Lanza una ejecución V2 completa. Corre en el BASTIÓN como gadmin.
#   bash lanzar_v2.sh <programa.json> <ETIQUETA> <gb_necesarios>
# Ejemplos:
#   bash lanzar_v2.sh piloto-30min.json PILOTO 2
#   bash lanzar_v2.sh captura-42h.json C42 12
# Orden: identificador -> exclusión V1 -> preflight -> relojes -> registro DNS + PCAP (DC1) ->
#        referencia del extremo (tcpdump en srv-dmz) -> sondeo del espejo (bastión) -> archivador (Sensor1) ->
#        sondas del preflight (Clientes, registradas) -> espera: captura previa >= 2 min Y margen de sonda
#        (HORIZONTE 230 s + PASO 10 s, v2ctl.MARGEN_SONDA_S) -> generador (Clientes) -> vigía.
# Si algo falla antes del generador, no se lanza nada más y se deshace lo arrancado.
set -euo pipefail
PROG=${1:?programa}; TAG=${2:?etiqueta}; GB=${3:?gb_necesarios}
B=$HOME/cyberflow-v2/codigo                      # copia en el bastión
CL=/home/adminclientes/cyberflow-v2              # Clientes
S1=/home/m4rk/cyberflow-v2                       # Sensor1
DC=/home/dcadmin/cyberflow-v2                    # DC1
POBL=10.10.20.21,10.10.20.22,10.10.20.23,10.10.20.24,10.10.20.25,10.10.20.26
PREVIO_S=150; MARGEN_FIN_S=120; HOLGURA_S=3600; MARGEN_SONDA_S=240
EXT=/home/adminsrvdmz/cyberflow-v2/extremo        # srv-dmz: referencia independiente HTTP/HTTPS
# Solo la población con srv-dmz (privacidad y volumen): nada de terceros entra en el fichero.
FILTRO_EXT="host 10.10.30.10 and tcp and (port 80 or port 443) and (host 10.10.20.21 or host 10.10.20.22 or host 10.10.20.23 or host 10.10.20.24 or host 10.10.20.25 or host 10.10.20.26)"
# Tipo de ejecución (obligatorio): fija los requisitos del dictamen (estado_global.REQUISITOS).
TIPO=${CF_TIPO_EJECUCION:-}
case "$TIPO" in verificacion_dirigida|piloto_final|captura_definitiva) ;;
  *) echo "CF_TIPO_EJECUCION debe ser verificacion_dirigida, piloto_final o captura_definitiva" >&2; exit 2;; esac
RETRASO_PRUEBA_S=${RETRASO_PRUEBA_S:-0}
[[ $RETRASO_PRUEBA_S =~ ^[0-9]+$ ]] || { echo "RETRASO_PRUEBA_S debe ser entero no negativo" >&2; exit 2; }
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"

ID="V2-${TAG}-$(date -u +%Y%m%dT%H%M%SZ)"
E=$HOME/cyberflow-v2/ejecuciones/$ID; mkdir -p "$E"
log() { printf '{"utc":"%s","paso":"%s","detalle":"%s"}\n' "$(date -u +%FT%T.%3NZ)" "$1" "$(echo "${2:-}" | tr -d '"\r' | tr '\n' ' ' | cut -c1-400)" | tee -a "$E/lanzamiento.jsonl"; }
DUR=$(python3 -c "import json,sys;print(int(json.load(open(sys.argv[1]))['duracion_s']))" "$B/programas/$PROG")
SHA=$(sha256sum "$B/programas/$PROG" | cut -c1-64)
T_ARCH=$(date +%s); TOPE_INICIAL=$((T_ARCH + 3600 + PREVIO_S + DUR + MARGEN_FIN_S + HOLGURA_S))
log identificador "$ID programa=$PROG sha256=$SHA duracion=$DUR tope_inicial=$TOPE_INICIAL retraso_prueba=$RETRASO_PRUEBA_S"

# 0. Coordinación de copias (VD3): candado de captura en el bastión. Ninguna copia de evidencia
# (transferir.py) puede empezar mientras exista; y la captura no empieza hasta HOLGURA_S tras el
# fin de la última copia registrada (el archivador recoge el anillo de los 30-35 s anteriores).
# Lo quita cerrar_v2.sh cuando el archivador y las dos referencias están parados.
python3 "$B/operacion/transferir.py" candado crear "$ID" \
  || { log candado "no creado: captura en curso o copia sin terminar"; exit 1; }
log candado "creado ($HOME/cyberflow-v2/CAPTURA_EN_CURSO)"

deshacer() { log deshacer "$1"
  [ -f "$E/sondeo-span.pid" ] && kill -TERM "$(cat "$E/sondeo-span.pid")" 2>/dev/null || true
  [ -f "$E/referencias.pid" ] && kill -TERM "$(cat "$E/referencias.pid")" 2>/dev/null || true
  $SSH dcadmin@10.10.10.20 "sudo -n systemctl stop cf-v2-dns-${ID,,}" 2>/dev/null || true
  $SSH srvdmz "sudo -n pkill -INT -f '[t]cpdump .* -w $EXT/$ID.pcap'" 2>/dev/null || true
  $SSH sensor1 "pkill -TERM -f '[a]rchivar_v2.py --ejecucion $ID'" 2>/dev/null || true
  python3 "$B/operacion/transferir.py" candado quitar "$ID" >/dev/null 2>&1 || true
  exit 1; }

# 1. V1 no aprende de esta ventana (respaldo del toml si hay que añadir la regla)
r=$($SSH sensor1 "python3 $S1/codigo/operacion/exclusion_v1.py --desde $((T_ARCH - 600)) --hasta $((TOPE_INICIAL + 600))") || deshacer "exclusion_v1: $r"
log exclusion_v1 "$r"

# 2. Preflight del laboratorio (solo lectura)
if ! bash "$B/operacion/preflight_lab.sh" "$T_ARCH" "$TOPE_INICIAL" "$GB" > "$E/preflight-lab.jsonl"; then
  log preflight fallo; cat "$E/preflight-lab.jsonl"; deshacer "preflight con fallos"; fi
log preflight ok

# 3. Relojes de los servidores (Clientes y Sensor1 los registran sus propios programas)
for h in srvdmz dcadmin@10.10.10.20 sensor1 clientes; do
  # relojes + carga y espacio de las referencias (srv-dmz y DC1) y de Sensor1/Clientes (C10), al principio y al final
  $SSH "$h" 'date -u +%FT%T.%NZ; timedatectl show; (chronyc tracking 2>/dev/null || timedatectl timesync-status); echo "== carga"; cat /proc/loadavg; nproc; echo "== espacio"; df -B1 --output=target,avail / /var/log $HOME 2>/dev/null' > "$E/relojes-inicio-${h#*@}.txt" 2>&1 || true
done
log relojes "srvdmz y dc1"
bash "$B/operacion/contadores_lab.sh" "$E/contadores-lab-inicio.txt" >/dev/null; log contadores inicio

# 4. Registro DNS independiente en DC1 (unidad transitoria con tope de vida)
$SSH dcadmin@10.10.10.20 "sudo -n mkdir -p /var/log/cyberflow-v2 && sudo -n systemd-run --unit=cf-v2-dns-${ID,,} --property=RuntimeMaxSec=$((DUR + 3600)) /usr/bin/python3 $DC/servidor/registro_dns_v2.py --interfaz ens224 --salida /var/log/cyberflow-v2/dns-$ID.jsonl --pcap /var/log/cyberflow-v2/dns-$ID.pcap --poblacion $POBL" \
  || deshacer "no arrancó el registro DNS"
log registro_dns "cf-v2-dns-${ID,,}"

# 4a. Referencia independiente en el extremo: tcpdump en srv-dmz (ens35), solo población <-> srv-dmz
# HTTP/HTTPS, sin recorte (-s 0), escritura sin búfer (-U). Se para en cerrar_v2.sh (SIGINT: escribe
# sus estadísticas de descartes del núcleo en el .log); cerrar_v2 calcula el sha256 y lo contrasta.
$SSH srvdmz "mkdir -p $EXT; sudo -n setsid nohup tcpdump -i ens35 -n -s 0 -U -w $EXT/$ID.pcap '$FILTRO_EXT' > $EXT/$ID.log 2>&1 < /dev/null &" \
  || deshacer "no arrancó la captura del extremo"
sleep 2
$SSH srvdmz "pgrep -f '[t]cpdump .* -w $EXT/$ID.pcap' >/dev/null" || deshacer "la captura del extremo no sigue viva: $($SSH srvdmz "cat $EXT/$ID.log" 2>&1)"
log extremo "srvdmz $EXT/$ID.pcap filtro=poblacion<->10.10.30.10:80/443"

# 4b. Supervisión continua del destino SPAN (Gi2/0/19), antes del archivador: así cubre la captura
# previa, la generación y el margen final. Se para en cerrar_v2.sh; el tope es una red de seguridad.
setsid nohup python3 "$B/operacion/sondeo_span.py" --salida "$E/sondeo-span.jsonl" \
  --hasta-epoch $((TOPE_INICIAL + 900)) --cada-s 2 --pid "$E/sondeo-span.pid" \
  > "$E/sondeo-span-salida.txt" 2>&1 < /dev/null &
for i in $(seq 1 15); do grep -q '"tipo": "muestra"' "$E/sondeo-span.jsonl" 2>/dev/null && break; sleep 2; done
grep -q '"tipo": "muestra"' "$E/sondeo-span.jsonl" 2>/dev/null || deshacer "el sondeo del espejo no dio ninguna muestra"
T_SONDEO=$(date +%s)
log sondeo_span "pid $(cat "$E/sondeo-span.pid" 2>/dev/null)"
# El archivador recoge también los PCAP del anillo de los MARGEN_PREVIO_ARCH_S anteriores a su
# arranque (+ ROTACION_S = 5 s de archivar_v2): el sondeo tiene que llevar ese tiempo dando muestras
# o el principio de la captura queda sin sondeo (`espejo: indeterminado`, como en E3 y VD2).
MARGEN_PREVIO_ARCH_S=30
while [ "$(date +%s)" -lt $((T_SONDEO + MARGEN_PREVIO_ARCH_S + 5 + 3)) ]; do sleep 1; done

# 5. Archivador en Sensor1 (EVE + PCAP comprimido, parada por espacio)
# (el & solo debe afectar al archivador: con «a && b && c &» ssh espera a la subcapa y no regresa)
$SSH sensor1 "mkdir -p $S1/capturas; cd $S1/codigo/captura; setsid nohup python3 archivar_v2.py --ejecucion $ID --hasta-epoch 0 --hasta-max-epoch $TOPE_INICIAL --margen-final-s 15 --margen-previo $MARGEN_PREVIO_ARCH_S --eve /var/log/suricata/v2/eve.json --libre-minimo-gb 4 > $S1/capturas/archivador-$ID.txt 2>&1 < /dev/null &" \
  || deshacer "no arrancó el archivador"
for i in $(seq 1 30); do
  st=$($SSH sensor1 "cat $S1/capturas/$ID/estado.json 2>/dev/null" || true)
  echo "$st" | grep -q '"estado": *"ok"' && break; sleep 2
done
echo "$st" | grep -q '"estado": *"ok"' || deshacer "archivador sin estado ok: $st"
T_CONF=$(date +%s)

# 5b. Sondas del preflight ANTES del periodo útil, con la captura ya en marcha (quedan grabadas) y
# registradas con ejecución, origen, puerto, id, nombre e instantes. El generador no arranca hasta
# fin_última_sonda + MARGEN_SONDA_S: así ninguna ventana útil las tiene en su historia de 230 s.
SONDAS=$CL/sondas/$ID-preflight.jsonl
r=$($SSH clientes "python3 $CL/codigo/operacion/v2ctl.py sondear --programa $CL/codigo/programas/$PROG --ejecucion $ID --registro $SONDAS") \
  || deshacer "sondas del preflight con fallos: $r"
$SSH clientes "cat $SONDAS" > "$E/preflight-clientes.jsonl" || deshacer "no se pudo copiar el registro de sondas"
NO_ANTES=$(python3 -c "import json,math,sys;print(math.ceil(json.loads(sys.argv[1])['ultima_sonda_fin_epoch']+$MARGEN_SONDA_S))" "$r") \
  || deshacer "registro de sondas sin fin: $r"
log sondas "$r"
INI=$((T_CONF + PREVIO_S)); if [ "$NO_ANTES" -gt "$INI" ]; then INI=$NO_ANTES; fi
FIN_GEN=$((INI + DUR)); FIN=$((FIN_GEN + MARGEN_FIN_S)); TOPE=$((FIN + HOLGURA_S))
$SSH sensor1 "printf '%s\n' $TOPE > $S1/capturas/$ID/HASTA_MAX_EPOCH.tmp; mv $S1/capturas/$ID/HASTA_MAX_EPOCH.tmp $S1/capturas/$ID/HASTA_MAX_EPOCH" \
  || deshacer "no se pudo fijar el tope real del archivador"
r=$($SSH sensor1 "python3 $S1/codigo/operacion/exclusion_v1.py --desde $((T_ARCH - 600)) --hasta $((TOPE + 600))") \
  || deshacer "exclusion_v1 tras confirmacion: $r"
log exclusion_v1_confirmada "$r"
log archivador "ok confirmado=$T_CONF inicio=$INI tope=$TOPE"

# 5c. Vigilancia de las referencias (srv-dmz y DC1): proceso vivo, progreso del fichero durante la
# generación y espacio libre, cada 20 s. Con poco espacio para la captura de esa referencia
# (SIGINT) y la declara incompleta; cerrar_v2.sh la para antes de parar las referencias.
setsid nohup python3 "$B/operacion/vigilar_referencias.py" vigilar --ejecucion "$ID" \
  --salida "$E/referencias.jsonl" --pid "$E/referencias.pid" \
  --generador-desde "$INI" --generador-hasta "$FIN_GEN" --hasta-epoch $((TOPE + 900)) \
  > "$E/referencias-salida.txt" 2>&1 < /dev/null &
for i in $(seq 1 20); do
  grep -q '"equipo": "srvdmz"' "$E/referencias.jsonl" 2>/dev/null && grep -q '"equipo": "dc1"' "$E/referencias.jsonl" 2>/dev/null && break; sleep 2
done
grep -q '"equipo": "dc1"' "$E/referencias.jsonl" 2>/dev/null && grep -q '"equipo": "srvdmz"' "$E/referencias.jsonl" 2>/dev/null \
  || deshacer "la vigilancia de las referencias no dio muestras de srv-dmz y DC1"
log referencias "vigilancia pid $(cat "$E/referencias.pid" 2>/dev/null)"

# 6. Captura previa sin tráfico V2 (>= 2 min) y generador
while [ "$(date +%s)" -lt "$INI" ]; do sleep 5; done
[ "$RETRASO_PRUEBA_S" -eq 0 ] || sleep "$RETRASO_PRUEBA_S"
r=$($SSH clientes "python3 $CL/codigo/operacion/v2ctl.py iniciar --programa $CL/codigo/programas/$PROG --ejecucion $ID --requiere-permiso --sondas-previas $SONDAS --margen-sonda-s $MARGEN_SONDA_S") \
  || deshacer "v2ctl iniciar: $r"
log generador "$r"

# 7. Vigía (renueva el permiso mientras el archivador esté sano; si no, para el generador)
setsid nohup python3 "$B/operacion/vigia_v2.py" --ejecucion "$ID" \
  --estado-remoto "$S1/capturas/$ID/estado.json" \
  --hasta-remoto "$S1/capturas/$ID/HASTA_EPOCH" \
  --margen-fin-s "$MARGEN_FIN_S" \
  --permiso-remoto "$CL/ejecuciones/$ID/PERMISO_CAPTURA" \
  --v2ctl-remoto "$CL/codigo/operacion/v2ctl.py" \
  --registro "$E/vigia.jsonl" > "$E/vigia-salida.txt" 2>&1 < /dev/null &
log vigia "pid $!"
VER_CODIGO=$(cat "$B/VERSION" 2>/dev/null || echo no_registrada)
python3 - "$E" "$ID" "$PROG" "$SHA" "$T_ARCH" "$T_CONF" "$INI" "$FIN_GEN" "$FIN" "$TOPE" "$DUR" "$RETRASO_PRUEBA_S" "$VER_CODIGO" "$MARGEN_SONDA_S" "$NO_ANTES" "$EXT/$ID.pcap" "$TIPO" <<'PY'
import json, sys
e, i, p, sha, ta, conf, ini, fin_gen, fin, tope, dur, retraso, ver, margen, no_antes, ext, tipo = sys.argv[1:]
json.dump({"ejecucion": i, "tipo_ejecucion": tipo, "programa": p, "programa_sha256": sha, "codigo_version": ver,
           "planificado": {"archivador_desde_epoch": int(ta), "generador_inicio_epoch": int(ini),
                           "generador_fin_epoch": int(fin_gen), "captura_hasta_epoch": int(fin),
                           "tope_epoch": int(tope)},
           "real": {"archivador_confirmado_epoch": int(conf)},
           # Guardas y márgenes PLANIFICADOS (no son exclusiones por incidente): la sonda termina antes
           # de no_antes − margen; la guarda E1 y E5 las aplica metadatos_v2.
           "guardas_planificadas": {"margen_sonda_s": int(margen), "generador_no_antes_de_epoch": int(no_antes),
                                    "captura_previa_s": 150, "margen_fin_s": 120},
           "referencias": {"extremo_srvdmz_pcap": ext, "dns_dc1": "cf-v2-dns-" + i.lower()},
           # Declarados = obligatorios en el dictamen (estado_global): sin su evidencia, indeterminada.
           "vigilancia_referencias": {"registro": "referencias.jsonl", "cada_s": 20, "minimo_gb": 1.0,
                                      "sin_progreso_s": 180, "sin_lectura_s": 90},
           "coordinacion_transferencias": {"candado": "~/cyberflow-v2/CAPTURA_EN_CURSO",
                                           "registro": "~/cyberflow-v2/transferencias.jsonl",
                                           "holgura_s": 60, "margen_anillo_s": 40},
           "duracion_s": int(dur), "retraso_prueba_s": int(retraso),
           "dns_unidad": "cf-v2-dns-" + i.lower()}, open(e + "/lanzamiento.json", "w"), indent=1)
PY
echo "$ID"
