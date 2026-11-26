#!/usr/bin/env bash
# Cierra una ejecución V2. Corre en el BASTIÓN como gadmin.
#   bash cerrar_v2.sh <ID>
# 1. espera los dos manifiestos (generador y archivador)   2. para el registro DNS
# 3. relojes de fin   4. reúne en Sensor1 pruebas/<ID>: generador, servidor (recortado a la
#    ventana), DNS, vigía y lanzamiento   5. conciliación, cobertura, extracción y verificación
#    con ulimit   6. SHA256SUMS de capturas/<ID> y pruebas/<ID>.
# Se puede repetir sobre el mismo ID (rehace el análisis). No borra nada. La copia al portátil se hace después, con verificación de hashes (COMANDOS.md).
set -euo pipefail
ID=${1:?ID}
CL=/home/adminclientes/cyberflow-v2; S1=/home/m4rk/cyberflow-v2
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"
E=$HOME/cyberflow-v2/ejecuciones/$ID
P=$S1/pruebas/$ID
log() { printf '{"utc":"%s","paso":"%s","detalle":"%s"}\n' "$(date -u +%FT%T.%3NZ)" "$1" "$(echo "${2:-}" | tr -d '"\r' | tr '\n' ' ' | cut -c1-400)" | tee -a "$E/cierre.jsonl"; }

# 1. Manifiestos (máx. 30 min de espera)
for i in $(seq 1 180); do
  g=$($SSH clientes "test -f $CL/ejecuciones/$ID/manifiesto-fin.json && echo si" || true)
  a=$($SSH sensor1 "test -f $S1/capturas/$ID/manifiesto.json && echo si" || true)
  [ "$g$a" = sisi ] && break; sleep 10
done
if [ "$g$a" != sisi ]; then
  log manifiestos "faltan generador=$g archivador=$a"
  $SSH sensor1 "mkdir -p $P/registros $P/generador"
  tar -C "$E" -cf - . | ssh -o BatchMode=yes sensor1 "tar -C $P/registros -xf -"
  if [ "$g" = si ]; then
    ssh -o BatchMode=yes clientes "tar -C $CL/ejecuciones -cf - $ID" | ssh -o BatchMode=yes sensor1 "tar -C $P/generador -xf -"
  fi
  ssh -n -o BatchMode=yes sensor1 "python3 $S1/codigo/operacion/estado_global.py $ID --pruebas $P --ejecucion-dir $P/registros --captura-dir $S1/capturas/$ID" > "$E/resultado-global.json" || true
  exit 1
fi
log manifiestos ok
# Sondeo del espejo: se para ahora (la captura ya terminó) y se analiza sobre el periodo real de
# captura. La falta de sondeo NO equivale a «sin descartes»: analizar_sondeo da 3 sin registro.
if [ -f "$E/sondeo-span.pid" ]; then kill -TERM "$(cat "$E/sondeo-span.pid")" 2>/dev/null || true; sleep 3; fi
# Vigilancia de las referencias: se para ANTES de parar las referencias (esa parada es la
# prevista, no un incidente) y se analiza. Sin registro no se da por completa.
if [ -f "$E/referencias.pid" ]; then
  kill -TERM "$(cat "$E/referencias.pid")" 2>/dev/null || true
  for i in $(seq 1 20); do grep -q '"tipo": "fin"' "$E/referencias.jsonl" 2>/dev/null && break; sleep 1; done
fi
python3 "$(dirname "$0")/vigilar_referencias.py" analizar "$E/referencias.jsonl" \
  --parada-cierre-epoch "$(date +%s)" > "$E/calidad-referencias.json" || true
log referencias "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("estado"),d.get("motivos"))' "$E/calidad-referencias.json" 2>&1)"
$SSH sensor1 "cat $S1/capturas/$ID/manifiesto.json" > "$E/manifiesto-archivador.json"
$SSH clientes "cat $CL/ejecuciones/$ID/manifiesto-fin.json" > "$E/manifiesto-generador.json"
$SSH clientes "cat $CL/ejecuciones/$ID/supervisor.jsonl" > "$E/supervisor-generador.jsonl"
python3 - "$E" <<'PY'
import datetime, json, math, pathlib, sys
E = pathlib.Path(sys.argv[1])
def ep(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None
l = json.loads((E / "lanzamiento.json").read_text())
a = json.loads((E / "manifiesto-archivador.json").read_text())
g = json.loads((E / "manifiesto-generador.json").read_text())
eventos = [json.loads(x) for x in (E / "supervisor-generador.jsonl").read_text().splitlines() if x.strip()]
inicios = [ep(x.get("utc")) for x in eventos if x.get("tipo") == "perfil_lanzado"]
real = l.setdefault("real", {})
real.update(primer_paquete_epoch=a.get("primer_paquete_epoch"), ultimo_paquete_epoch=a.get("ultimo_paquete_epoch"),
            generador_inicio_epoch=min(inicios) if inicios else None,
            generador_fin_epoch=ep((g.get("entorno_fin") or {}).get("utc") or g.get("utc")))
(E / "lanzamiento.json").write_text(json.dumps(l, indent=1))
valores = list(real.get(k) for k in ("primer_paquete_epoch", "ultimo_paquete_epoch", "generador_inicio_epoch", "generador_fin_epoch"))
if all(v is not None for v in valores):
    desde, hasta = math.floor(min(valores[0], valores[2])), math.ceil(max(valores[1], valores[3]))
    (E / "intervalo-exclusion.txt").write_text(f"{desde - 600} {hasta + 600}\n")
else:
    desde, hasta = l["planificado"]["archivador_desde_epoch"], l["planificado"]["captura_hasta_epoch"]
(E / "intervalo-servidor.txt").write_text(f"{desde} {hasta}\n")
pp, up = real.get("primer_paquete_epoch"), real.get("ultimo_paquete_epoch")
(E / "intervalo-captura.txt").write_text(f"{pp} {up}\n" if pp and up else "")
PY
RC_SONDEO=0
if [ -s "$E/intervalo-captura.txt" ]; then
  read -r CAP_DESDE CAP_HASTA < "$E/intervalo-captura.txt"
  python3 "$(dirname "$0")/analizar_sondeo.py" "$E/sondeo-span.jsonl" --desde "$CAP_DESDE" --hasta "$CAP_HASTA" > "$E/calidad-espejo-sondeo.json" || RC_SONDEO=$?
else
  python3 "$(dirname "$0")/analizar_sondeo.py" "$E/sondeo-span.jsonl" > "$E/calidad-espejo-sondeo.json" || RC_SONDEO=$?
fi
log sondeo_span "analizar_sondeo rc=$RC_SONDEO (0 sin descartes, 1 con descartes, 2 indeterminado, 3 sin registro)"
read -r DESDE HASTA < "$E/intervalo-servidor.txt"
if [ -f "$E/intervalo-exclusion.txt" ]; then
  read -r EX_DESDE EX_HASTA < "$E/intervalo-exclusion.txt"
  $SSH sensor1 "python3 $S1/codigo/operacion/exclusion_v1.py --desde $EX_DESDE --hasta $EX_HASTA" > "$E/exclusion-v1.json" || true
  python3 - "$E/exclusion-v1.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
try: r = json.loads(p.read_text())
except ValueError: r = {"cubierto": False, "error": "respuesta ilegible"}
r["cubria_antes"] = bool(r.get("cubierto") and not r.get("cambio"))
p.write_text(json.dumps(r, indent=1))
PY
else
  echo '{"error":"evidencia_real_incompleta"}' > "$E/exclusion-v1.json"
fi
log exclusion_v1 "$(cat "$E/exclusion-v1.json")"

# 2. Registro DNS
$SSH dcadmin@10.10.10.20 "sudo -n systemctl stop cf-v2-dns-${ID,,} 2>/dev/null; sudo -n systemctl reset-failed cf-v2-dns-${ID,,} 2>/dev/null; sudo -n cat /var/log/cyberflow-v2/dns-$ID.jsonl" > "$E/dns-$ID.jsonl"
log registro_dns "$(wc -l < "$E/dns-$ID.jsonl") lineas"
$SSH dcadmin@10.10.10.20 "sudo -n cat /var/log/cyberflow-v2/dns-$ID.pcap 2>/dev/null" > "$E/dns-$ID.pcap" || true
log registro_dns_pcap "$(wc -c < "$E/dns-$ID.pcap") bytes"

# 2b. Referencia del extremo (srv-dmz): se para tcpdump (SIGINT: imprime capturados/recibidos/
# descartados por el núcleo), se calcula sha256 y tamaño en origen y se copia a Sensor1 verificando
# el hash. Si no hubo captura del extremo (ejecuciones antiguas), queda constancia y el dictamen lo
# trata como evidencia ausente.
EXT=/home/adminsrvdmz/cyberflow-v2/extremo
$SSH srvdmz "sudo -n pkill -INT -f '[t]cpdump .* -w $EXT/$ID.pcap'; sleep 3; pgrep -f '[t]cpdump .* -w $EXT/$ID.pcap' >/dev/null && echo SIGUE_VIVO; cat $EXT/$ID.log 2>/dev/null; echo '== sha256'; sha256sum $EXT/$ID.pcap 2>/dev/null; stat -c '%s' $EXT/$ID.pcap 2>/dev/null" > "$E/extremo-captura.txt" 2>&1 || true
python3 - "$E/extremo-captura.txt" "$E/extremo-captura.json" "$EXT/$ID.pcap" <<'PY'
import json, re, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
num = lambda pat: (int(m.group(1)) if (m := re.search(pat, t)) else None)
sha = re.search(r"^([0-9a-f]{64})\s", t, re.M)
tam = re.findall(r"^(\d+)\s*$", t, re.M)
r = {"fichero_origen": sys.argv[3], "capturados": num(r"(\d+) packets captured"),
     "recibidos_por_filtro": num(r"(\d+) packets received by filter"),
     "descartados_nucleo": num(r"(\d+) packets dropped by kernel"),
     "sha256_origen": sha.group(1) if sha else None, "bytes": int(tam[-1]) if tam else None,
     "sigue_vivo": "SIGUE_VIVO" in t}
r["estado"] = ("sin_captura" if r["sha256_origen"] is None else
               "sin_estadisticas" if r["descartados_nucleo"] is None or r["sigue_vivo"] else "ok")
json.dump(r, open(sys.argv[2], "w"), indent=1)
PY
log extremo "$(cat "$E/extremo-captura.json" | tr -d '\n ')"
if grep -q '"sha256_origen": "[0-9a-f]' "$E/extremo-captura.json"; then
  $SSH sensor1 "mkdir -p $P/registros"
  ssh -n -o BatchMode=yes srvdmz "cat $EXT/$ID.pcap" | ssh -o BatchMode=yes sensor1 "cat > $P/registros/extremo-$ID.pcap"
  SHA_DEST=$($SSH sensor1 "sha256sum $P/registros/extremo-$ID.pcap | cut -c1-64")
  grep -q "\"sha256_origen\": \"$SHA_DEST\"" "$E/extremo-captura.json" && log extremo_copia "sha256 coincide $SHA_DEST" \
    || { log extremo_copia "sha256 NO coincide ($SHA_DEST)"; $SSH sensor1 "mv $P/registros/extremo-$ID.pcap $P/registros/extremo-$ID.pcap.danado"; }
fi

# 2c. Coordinación de copias: con el archivador y las dos referencias ya parados termina el
# intervalo de captura. Se comprueba en el registro de transferir.py que ninguna copia lo tocó
# (desde el arranque del archivador menos el anillo previo) y se quita el candado.
if python3 -c 'import json,sys;sys.exit(0 if "coordinacion_transferencias" in json.load(open(sys.argv[1])) else 1)' "$E/lanzamiento.json"; then
  T_DESDE=$(python3 -c 'import json,sys;l=json.load(open(sys.argv[1]));print(int(l["planificado"]["archivador_desde_epoch"]) - int(l["coordinacion_transferencias"].get("margen_anillo_s", 40)))' "$E/lanzamiento.json")
  python3 "$(dirname "$0")/transferir.py" solapes --desde "$T_DESDE" --hasta "$(date +%s)" --salida "$E/transferencias.json" > /dev/null || true
  log transferencias "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["estado"],len(d["copias_en_captura"]),"rechazadas",d["rechazadas_en_captura"])' "$E/transferencias.json" 2>&1)"
  python3 "$(dirname "$0")/transferir.py" candado quitar "$ID" && log candado "quitado"
fi

# 3. Contadores (switch, sensor, aislamiento V1) y relojes de fin
[ -f "$E/contadores-lab-fin.txt" ] || bash "$(dirname "$0")/contadores_lab.sh" "$E/contadores-lab-fin.txt" >/dev/null
for h in srvdmz dcadmin@10.10.10.20 sensor1 clientes; do
  $SSH "$h" 'date -u +%FT%T.%NZ; timedatectl show; (chronyc tracking 2>/dev/null || timedatectl timesync-status); echo "== carga"; cat /proc/loadavg; nproc; echo "== espacio"; df -B1 --output=target,avail / /var/log $HOME 2>/dev/null' > "$E/relojes-fin-${h#*@}.txt" 2>&1 || true
done

# 4. Servidor: solo las líneas de la ventana [DESDE-300, HASTA+300] (el registro es acumulativo)
for f in http-80 https-443; do
  ssh -o BatchMode=yes -o ConnectTimeout=8 srvdmz "python3 - $((DESDE - 300)) $((HASTA + 300)) /home/adminsrvdmz/laboratorio/v2/registro/$f.jsonl" > "$E/servidor-$f.jsonl" <<'PY'
import sys, json, datetime as d
a, b, ruta = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
for l in open(ruta, encoding="utf-8"):
    try:
        r = json.loads(l); t = d.datetime.fromisoformat((r.get("inicio_utc") or r["utc"]).replace("Z", "+00:00")).timestamp()
    except Exception:
        sys.stdout.write(l); continue          # se conserva: la conciliación lo cuenta como error de lectura
    if a <= t <= b:
        sys.stdout.write(l)
PY
done
log servidor "$(cat "$E"/servidor-*.jsonl | wc -l) lineas en ventana"

# Generador: tar desde Clientes, a Sensor1 por el bastión
$SSH sensor1 "mkdir -p $P/generador $P/registros"
ssh -o BatchMode=yes clientes "tar -C $CL/ejecuciones -cf - $ID" | ssh -o BatchMode=yes sensor1 "tar -C $P/generador -xf -"
tar -C "$E" -cf - . | ssh -o BatchMode=yes sensor1 "tar -C $P/registros -xf -"
log reunido "$P"

# 5. Análisis en Sensor1, con memoria acotada y sin cargar ficheros enteros
ssh -o BatchMode=yes sensor1 "CF_FALLO_PASO='${CF_FALLO_PASO:-}' bash -s" <<EOF > "$E/analisis-salida.txt" 2>&1 || true
set -u; ulimit -v 4000000
# stderr (time -v) por el mismo flujo que stdout: si van separados por ssh se entremezclan y una
# línea «verificar rc=0» llegó partida («Si…verificar rc=0»), y estado_global dio analisis incompleto (E2, 25-nov).
exec 2>&1
C=$S1/codigo; cd $P; mkdir -p cobertura registros
# Registro estructurado de pasos (una línea JSON por paso, con rc e instantes): es lo que lee
# estado_global.py; el texto «paso rc=N» queda solo para leerlo una persona. Un análisis repetido
# aparta el registro anterior en vez de mezclarlo.
[ -f registros/pasos-analisis.jsonl ] && mv registros/pasos-analisis.jsonl registros/pasos-analisis.\$(date -u +%Y%m%dT%H%M%SZ).jsonl
paso() { local n=\$1; shift; local t0=\$(date +%s.%N) rc
  if [ "\$CF_FALLO_PASO" = "\$n" ]; then echo "FALLO DELIBERADO de \$n (CF_FALLO_PASO)"; rc=97; else "\$@"; rc=\$?; fi
  printf '{"paso":"%s","rc":%d,"inicio_epoch":%s,"fin_epoch":%s,"obligatorio":%s,"fallo_deliberado":%s}\n' \
    "\$n" "\$rc" "\$t0" "\$(date +%s.%N)" "\$(case \$n in calidad_*) echo false;; *) echo true;; esac)" "\$([ "\$CF_FALLO_PASO" = "\$n" ] && echo true || echo false)" >> registros/pasos-analisis.jsonl
  echo "\$n rc=\$rc"; }
/usr/bin/time -v true >/dev/null 2>&1 && T="/usr/bin/time -v" || T=""
paso conciliar \$T python3 \$C/operacion/conciliar_v2.py --transacciones generador/$ID/transacciones-*.jsonl \
  --servidor registros/servidor-http-80.jsonl registros/servidor-https-443.jsonl \
  --dns registros/dns-$ID.jsonl --salida conciliacion
paso cobertura \$T python3 \$C/captura/cobertura_v2.py --capturas $S1/capturas/$ID --transacciones generador/$ID/transacciones-*.jsonl \
  --salida cobertura/cobertura.json --csv cobertura/cobertura.csv
paso fronteras python3 \$C/extraccion/metadatos_v2.py fronteras --generador generador/$ID --salida fronteras.json
paso extraer \$T python3 \$C/extraccion/extraer_v2.py $S1/capturas/$ID --salida extraccion --fronteras fronteras.json
paso verificar \$T python3 \$C/extraccion/verificar_v2.py $S1/capturas/$ID --salida extraccion --fronteras fronteras.json --max-filas 40 --historia-s 230
# Calidad de captura (bloque 1): no son pasos obligatorios (su rc no decide), pero desde la revisión
# del 26-nov estado_global.py LEE su resultado y lo integra en el dictamen
# (docs/BLOQUE1-POLITICA-CALIDAD.md): pérdida o entrada dañada = fallo; ausencia = indeterminado.
paso calidad_copias nice python3 \$C/captura/copias_espejo.py $S1/capturas/$ID/pcap --salida calidad-copias-espejo.json --detalle-umbral 0.4
DNSP=""; [ -s registros/dns-$ID.pcap ] && DNSP="--pcap registros/dns-$ID.pcap"
# Registro de sondas: el de v2ctl (generador/ID/preflight.jsonl); sin él, ninguna sonda se explica.
SONDASP=""; [ -s generador/$ID/preflight.jsonl ] && SONDASP="--sondas generador/$ID/preflight.jsonl"
paso calidad_dns nice python3 \$C/captura/contraste_dns.py --transacciones generador/$ID/transacciones-*.jsonl --dc1 registros/dns-$ID.jsonl \
  --capturas $S1/capturas/$ID \$DNSP \$SONDASP --salida calidad-contraste-dns.json --csv calidad-contraste-dns.csv
if [ -s registros/extremo-$ID.pcap ]; then
  paso calidad_extremo nice python3 \$C/captura/comparar_extremo.py --extremo registros/extremo-$ID.pcap --sensor $S1/capturas/$ID/pcap \
    --salida calidad-extremo.json
fi
paso metadatos python3 \$C/extraccion/metadatos_v2.py metadatos --capturas $S1/capturas/$ID --extraccion extraccion --generador generador/$ID \
  --cobertura cobertura/cobertura.csv --conciliacion conciliacion/conciliacion.jsonl
PREF=""; [ -s generador/$ID/preflight.jsonl ] && PREF="--preflight generador/$ID/preflight.jsonl"
paso calidad_sonda python3 \$C/operacion/ventanas_sonda.py --ventanas extraccion/ventanas_meta.csv \$PREF \
  --dns calidad-contraste-dns.json --salida calidad-sonda.json
EOF
log analisis "$(grep -o '^[a-z]* rc=[0-9]*' "$E/analisis-salida.txt" | tr '\n' ' ')"
$SSH sensor1 "cat $P/registros/pasos-analisis.jsonl" > "$E/pasos-analisis.jsonl" || true
scp -q -o BatchMode=yes "$E/analisis-salida.txt" "$E/cierre.jsonl" sensor1:"$P/registros/" || true

# Dictamen de criterios y resultado global, también para ejecuciones incompletas.
ssh -n -o BatchMode=yes sensor1 "python3 $S1/codigo/operacion/evaluar_piloto.py --pruebas $P --capturas $S1/capturas/$ID" > "$E/criterios-salida.txt" 2>&1 || true
# C7 y C9–C13 (que evaluar_piloto deja en revisión manual), revisados con evidencia; lo que requiere
# duración prolongada queda aparte (criterios-revisados.json).
ssh -n -o BatchMode=yes sensor1 "python3 $S1/codigo/operacion/revisar_criterios.py --pruebas $P --capturas $S1/capturas/$ID" >> "$E/criterios-salida.txt" 2>&1 || true
RC_GLOBAL=0
ssh -n -o BatchMode=yes sensor1 "python3 $S1/codigo/operacion/estado_global.py $ID --pruebas $P --ejecucion-dir $P/registros --captura-dir $S1/capturas/$ID --codigo-salida" > "$E/resultado-global.json" || RC_GLOBAL=$?
log estado_global "$(cat "$E/resultado-global.json")"

# 6. Hashes de todo lo que se va a copiar
ssh -n -o BatchMode=yes sensor1 "cd $S1 && find capturas/$ID pruebas/$ID -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > pruebas/$ID/SHA256SUMS && wc -l < pruebas/$ID/SHA256SUMS && du -sh capturas/$ID pruebas/$ID"
log hashes "pruebas/$ID/SHA256SUMS"

# Código de salida = dictamen escrito: 0 aprobado, 1 fallido, 2 indeterminado; otro valor (p. ej.
# 255 de ssh) = el dictamen no se pudo obtener, que tampoco es un aprobado.
case "$RC_GLOBAL" in 0|1|2) ;; *) log estado_global_error "rc=$RC_GLOBAL"; RC_GLOBAL=3 ;; esac
log fin "codigo_salida=$RC_GLOBAL"
exit "$RC_GLOBAL"
