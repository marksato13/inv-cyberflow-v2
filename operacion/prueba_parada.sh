#!/usr/bin/env bash
# Prueba controlada de la parada coordinada. Corre en el BASTIÓN (gadmin).
#   bash prueba_parada.sh espacio|archivador|vigia
# Lanza la prueba corta con lanzar_v2.sh y, 60 s después de arrancar el generador, provoca:
#   espacio    -> SIMULAR_LIBRE_GB=2 en el directorio de la ejecución (sin llenar el disco)
#   archivador -> kill -9 del archivador (deja de latir estado.json)
#   vigia      -> kill -9 del vigía (deja de renovarse el permiso en Clientes)
# Esperado: el generador para solo y su manifiesto queda «incompleta» con el motivo de la causa;
# el archivador cierra con su manifiesto (salvo kill -9, que no deja cerrar: eso también se registra).
set -u
CASO=${1:?espacio|archivador|vigia}
cd "$HOME/cyberflow-v2/codigo/operacion"
bash lanzar_v2.sh prueba-corta.json PARADA-${CASO^^} 2 > /tmp/lanzar-parada-$CASO.txt 2>&1 &
LP=$!
ID=""
for i in $(seq 1 60); do
  ID=$(grep -o "V2-PARADA-${CASO^^}-[0-9TZ]*" /tmp/lanzar-parada-$CASO.txt | head -1); [ -n "$ID" ] && break; sleep 2
done
until grep -q '"paso":"vigia"' /tmp/lanzar-parada-$CASO.txt 2>/dev/null; do
  grep -q '"paso":"deshacer"' /tmp/lanzar-parada-$CASO.txt && { echo "lanzamiento deshecho"; exit 1; }; sleep 3; done
sleep 60
T=$(date -u +%FT%T.%3NZ)
case $CASO in
  espacio)    ssh -n sensor1 "echo 2 > /home/m4rk/cyberflow-v2/capturas/$ID/SIMULAR_LIBRE_GB" ;;
  archivador) ssh -n sensor1 "pkill -9 -f '[a]rchivar_v2.py --ejecucion $ID'" ;;
  vigia)      pkill -9 -f "[v]igia_v2.py --ejecucion $ID" ;;
esac
echo "{\"provocado\":\"$CASO\",\"utc\":\"$T\",\"ejecucion\":\"$ID\"}" | tee -a "$HOME/cyberflow-v2/ejecuciones/$ID/prueba-parada.jsonl"
for i in $(seq 1 40); do
  f=$(ssh -n clientes "cat /home/adminclientes/cyberflow-v2/ejecuciones/$ID/manifiesto-fin.json 2>/dev/null")
  [ -n "$f" ] && break; sleep 5
done
echo "GENERADOR: $(echo "$f" | grep -E '"estado"|"motivo"' | tr -d ' \n')"
echo "VIGIA: $(tail -2 "$HOME/cyberflow-v2/ejecuciones/$ID/vigia.jsonl" 2>/dev/null | tr '\n' ' ')"
echo "ARCHIVADOR: $(ssh -n sensor1 "cat /home/m4rk/cyberflow-v2/capturas/$ID/estado.json; grep -E '\"estado\"|\"motivo\"' /home/m4rk/cyberflow-v2/capturas/$ID/manifiesto.json 2>/dev/null | tr -d ' \n'")"
wait $LP 2>/dev/null
echo "$ID"
