# Comandos exactos de CyberFlow V2

Cada bloque indica la máquina y la cuenta. Se accede por el bastión (`gadmin@10.10.10.30`), que tiene los alias `clientes` y `sensor1`. `ID` es el identificador de la ejecución y tiene la forma `V2-<JORNADA>-AAAAMMDDTHHMMSSZ`, por ejemplo `V2-P0-20261125T150000Z`. **Ningún identificador se reutiliza.**

## 0. Corrección del espejo (bloqueante; necesita sudo en Sensor1)

[Sensor1 m4rk] Diagnóstico temporal, no persistente:

```bash
sudo ip link set dev ens37 mtu 9000
ip link show ens37 | head -1
```

[Bastión gadmin] Verificación (T4 repetida): 4 MB de descarga y bytes recibidos en `ens37`.

```bash
ssh sensor1 'cat /sys/class/net/ens37/statistics/rx_bytes' ; \
ssh clientes 'curl -s --interface 10.10.20.24 -o /dev/null -w "%{size_download}\n" http://10.10.30.10/estatico/4096k' ; \
sleep 2; ssh sensor1 'cat /sys/class/net/ens37/statistics/rx_bytes'
# aceptación: la diferencia de rx_bytes es >= 8 MB (dos copias del espejo de 4 MB)
```

[Sensor1 m4rk] Persistente, solo si la verificación pasa:

```bash
sudo mkdir -p /etc/systemd/system/cyberflow-capture-nic.service.d
printf '[Service]\nExecStartPre=/usr/sbin/ip link set ens37 mtu 9000\n' | sudo tee /etc/systemd/system/cyberflow-capture-nic.service.d/mtu-v2.conf
sudo systemctl daemon-reload
sudo systemctl restart ppi-motor-capture suricata
```

Reversión:

```bash
sudo rm /etc/systemd/system/cyberflow-capture-nic.service.d/mtu-v2.conf
sudo systemctl daemon-reload
sudo ip link set dev ens37 mtu 1500
sudo systemctl restart ppi-motor-capture suricata
```

## 1. Preparación

[Portátil PowerShell] Regenerar los programas y pasar las pruebas:

```powershell
python programas\generar_programas.py --comprobar
python -m unittest discover -s tests
```

[Bastión gadmin] Desplegar el código, que se copia tal cual (sin servicios ni sudo):

```bash
tar czf - generador operacion programas | ssh clientes 'mkdir -p ~/cyberflow-v2/codigo && cd ~/cyberflow-v2/codigo && tar xzf -'
tar czf - captura | ssh sensor1 'mkdir -p ~/cyberflow-v2/codigo ~/cyberflow-v2/capturas && cd ~/cyberflow-v2/codigo && tar xzf -'
```

[Clientes adminclientes] Preflight:

```bash
cd ~/cyberflow-v2/codigo; python3 operacion/v2ctl.py preflight --programa programas/piloto-30min.json
```

## 2. Inicio

[Sensor1 m4rk] Archivador: arranca primero, al menos 2 min antes del generador. `HASTA` = inicio previsto + duración + 600 s, en epoch UTC.

```bash
cd ~/cyberflow-v2/codigo; setsid nohup python3 captura/archivar_v2.py --ejecucion ID --hasta-epoch HASTA > ~/cyberflow-v2/capturas/archivador-ID.txt 2>&1 < /dev/null &
```

(No usar `cd … && … &`: el `&` mandaría toda la cadena a segundo plano y la sesión SSH quedaría retenida.)

[Clientes adminclientes] Generador:

```bash
cd ~/cyberflow-v2/codigo; python3 operacion/v2ctl.py iniciar --programa programas/piloto-30min.json --ejecucion ID
python3 operacion/v2ctl.py estado --ejecucion ID
```

[Sensor1 m4rk] Aislamiento de V1: añadir `*@<inicio>/<fin>` a `reentrenamiento.excluir_ventanas`, con respaldo y antes de las 00:30 UTC. Es el mismo procedimiento que se siguió el 24-nov (ACLARACIONES §2.2).

## 3. Parada

[Clientes adminclientes] Parada anticipada controlada (SIGTERM, termina la acción en curso):

```bash
cd ~/cyberflow-v2/codigo; python3 operacion/v2ctl.py parar --ejecucion ID
```

[Sensor1 m4rk] El archivador para solo en `HASTA`. Para pararlo antes:

```bash
touch ~/cyberflow-v2/capturas/ID/PARAR
```

## 4. Cierre y verificación

[Bastión gadmin] Llevar el registro de Clientes a Sensor1 y cruzarlo con el PCAP y el EVE:

```bash
ssh clientes "cd ~/cyberflow-v2/ejecuciones/ID && tar czf - ." > /tmp/ID.tgz
ssh sensor1 "mkdir -p ~/cyberflow-v2/pruebas/ID && cd ~/cyberflow-v2/pruebas/ID && tar xzf -" < /tmp/ID.tgz && rm /tmp/ID.tgz
ssh sensor1 "cd ~/cyberflow-v2/pruebas/ID && nice python3 ~/cyberflow-v2/codigo/captura/cobertura_v2.py --capturas ~/cyberflow-v2/capturas/ID --transacciones transacciones-*.jsonl --salida cobertura.json"
```

Archivar fuera de Sensor1 (el destino está pendiente). Conservar el `manifiesto.json`, el `inventario.jsonl`, el sha256 del tgz y la ubicación.

## 5. Recuperación tras una interrupción

1. No reanudar: un perfil muerto queda como `interrupcion` en `supervisor.jsonl`.
2. [Clientes] `v2ctl.py parar --ejecucion ID` si quedan perfiles vivos; [Sensor1] `touch .../ID/PARAR`.
3. Clasificar la causa (PROTOCOLO §8). Si es técnica, repetir la jornada completa con un `ID` nuevo y las mismas semillas del programa. Como máximo, una repetición.
4. Conservar la ejecución fallida y anotar su motivo en el registro de ejecuciones.
