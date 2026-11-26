$ErrorActionPreference = "Stop"
$B = "<carpeta-vacia>"
if (Test-Path $B) { throw "ya existe $B" }
New-Item -ItemType Directory $B, "$B\release", "$B\paquete", "$B\salida" | Out-Null
git clone -q https://github.com/marksato13/inv-cyberflow-v2 "$B\repo"
$commit = git -C "$B\repo" rev-parse HEAD
gh release download bloque1-cierre-2026-11-26 -R marksato13/inv-cyberflow-v2 -p paquete-bloque1.tgz -D "$B\release"
$sha = (Get-FileHash "$B\release\paquete-bloque1.tgz").Hash.ToLower()
tar -xzf "$B\release\paquete-bloque1.tgz" -C "$B\paquete"
$dirs = Get-ChildItem "$B\paquete" -Recurse -Directory -Filter "V2-*" | Select-Object -First 1
$paq = $dirs.Parent.FullName
"commit $commit"; "paquete sha256 $sha"; "carpeta paquete $paq"
$pcap = "$B\repo\evidencias\bloque1\dns-entradas\dns-e3-pcap\dns-dc1-V2-E3-20261125T230032Z.saneado.pcap"
"pcap DC1: " + (Test-Path $pcap) + " " + (Get-FileHash $pcap).Hash.ToLower()
$t0 = Get-Date
cmd /c "python -I `"$B\repo\operacion\reproducir_dns.py`" --paquete `"$paq`" --salida `"$B\salida`" < NUL 2>&1"
"rc $LASTEXITCODE  duracion " + [int]((Get-Date) - $t0).TotalSeconds + " s"
python -I -c "import json,sys;d=json.load(open(sys.argv[1],encoding='utf-8'));[print(f['ejecucion'],f['pcap_dc1'],f['rc'],f['total']['sin_discrepancias'],'/',f['total']['transacciones'],'sin_tx',f['sin_transaccion'],{k:f['sin_transaccion_clasificacion'].get(k) for k in ('explicados','inciertos','no_explicados')},'clasif_igual',f['clasificacion_igual_al_laboratorio'],'igual',f['igual_al_laboratorio']) for f in d['filas']];print('todo_igual',d['todo_igual'])" "$B\salida\reproduccion-dns.json"
