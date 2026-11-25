#!/usr/bin/env bash
# Despliega un tgz de `git archive` en bastión, Sensor1, Clientes (~/cyberflow-v2/codigo) y el
# registrador DNS en DC1 (~/cyberflow-v2/servidor). Corre en el BASTIÓN como gadmin.
#   bash desplegar_codigo.sh codigo-<commit>.tgz <commit>
# Conserva el código anterior como codigo-<VERSION anterior> (no borra nada) y escribe VERSION.
# No se debe usar con una ejecución en curso (comprueba que no haya archivador ni generador).
set -euo pipefail
TGZ=${1:?tgz}; VER=${2:?commit}
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=8"
if $SSH sensor1 "pgrep -f '[a]rchivar_v2.py' >/dev/null" || $SSH clientes "pgrep -f '[c]lientes_lab_v2.py' >/dev/null"; then
  echo "hay una ejecución en curso: no se despliega"; exit 1; fi
sha256sum "$TGZ"
instalar='set -e; cd ~/cyberflow-v2; ant=$(cat codigo/VERSION 2>/dev/null || echo desconocida);
  if [ "$ant" != "'$VER'" ]; then [ -e codigo-$ant ] && mv codigo codigo-$ant-$(date +%s) || mv codigo codigo-$ant; fi
  mkdir -p codigo && tar -C codigo -xzf /tmp/'$(basename "$TGZ")' && echo '$VER' > codigo/VERSION && echo "$(hostname): $ant -> $(cat codigo/VERSION)"'
bash -c "$instalar"
for h in sensor1 clientes; do
  scp -q -o BatchMode=yes "$TGZ" "$h:/tmp/"
  $SSH "$h" "$instalar"
done
tar -xzf "$TGZ" -O servidor/registro_dns_v2.py | ssh -o BatchMode=yes dcadmin@10.10.10.20 \
  "cp ~/cyberflow-v2/servidor/registro_dns_v2.py ~/cyberflow-v2/servidor/registro_dns_v2.py.antes-$VER 2>/dev/null; cat > ~/cyberflow-v2/servidor/registro_dns_v2.py && sha256sum ~/cyberflow-v2/servidor/registro_dns_v2.py"
