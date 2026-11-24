# Comandos exactos de CyberFlow V2

Cada bloque indica la máquina y la cuenta. Se accede por el bastión (`gadmin@10.10.10.30`), que tiene los alias `clientes` y `sensor1`. `ID` es el identificador de la ejecución y tiene la forma `V2-<JORNADA>-AAAAMMDDTHHMMSSZ`, por ejemplo `V2-P0-20261125T150000Z`. **Ningún identificador se reutiliza.**

## 0. Corrección del espejo: APLICADA el 24-nov (T7)

[CORE-STACK, nivel 15] Aplicado en la *running-config*:

```
interface GigabitEthernet2/0/19
 mtu 9198
```

Antes se hizo `shutdown`/`no shutdown` para renegociar a 1000.

Para hacerlo persistente: `write memory`.
Para revertirlo: `interface GigabitEthernet2/0/19` + `no mtu`.

El destino real del SPAN es `Gi2/0/19`; `Gi1/0/23` y `Gi2/0/23` son los orígenes. El texto de abajo es el diagnóstico previo y conserva esa atribución errónea.

## 0-a. Diagnóstico previo (histórico)

[CORE-STACK consola/SSH, administrador] Diagnóstico de solo lectura:

```
show monitor session all
show interfaces GigabitEthernet1/0/23 | include line protocol|duplex|output drops|output buffer|BW
show interfaces GigabitEthernet1/0/23 status
show running-config interface GigabitEthernet1/0/23
```

Interpretación:

- Un `Total output drops` creciente durante una descarga confirma que el destino del SPAN no da abasto.
- Si aparece `100Mb/s` o `a-100`, el enlace negoció a 100 Mbit/s.

Corrección:

1. Que el enlace con `vmnic2` (I210-T1 de `esxi-hv-siem`) negocie **1 Gbit/s**. Si el puerto tiene `speed 100`, quitarlo (`no speed`). Si no lo tiene, cambiar el cable por uno Cat5e o Cat6 y revisar el conector, porque a 100 Mbit/s solo se usan 2 pares.
2. Comprobar que la sesión copia en los dos sentidos (`both`) y que el destino tiene `encapsulation replicate`.

Después de corregirlo, repetir la verificación de la descarga de 4 MB. Aceptación: Δ`rx_bytes` en `ens37` ≥ 8 MB.

## 0-bis. Pruebas ya hechas en el sensor y en ESXi (sin efecto)

> 24-nov, T5: el MTU 9000 en `ens37` **no** corrigió el problema. Las tramas grandes no llegan a la VM. **No apliques el drop-in persistente**: la corrección está en ESXi (INFORME §5, T5). Los comandos se conservan como registro de lo probado.

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
