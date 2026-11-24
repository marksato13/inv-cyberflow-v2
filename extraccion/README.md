# Extracción V2 desde originales archivados

`extraer_v2.py` importa parser, atribución y `build_rows` de `origen_v1/scripts/features/extract_multilayer_v2.py`; usa `deduplicar_espejo` de V1 v3. No modifica los originales. Lee `capturas/<ID>/pcap/live-*.pcap` (también PCAP directamente bajo `<ID>`) y `capturas/<ID>/eve/eve-*.json`. Filtra cada paquete antes de atribuirlo: conserva ambos sentidos si cualquiera de sus extremos pertenece a la población. Solo emite filas de esa población (por omisión `10.10.20.21`–`26`).

```sh
python extraccion/extraer_v2.py capturas/ID --salida resultados/ID --poblacion poblacion.csv --fronteras fronteras.json
python extraccion/verificar_v2.py capturas/ID --salida resultados/ID --poblacion poblacion.csv --fronteras fronteras.json
```

`--poblacion`: CSV de IP o JSON lista/`{"ips": [...]}`. `--fronteras`: JSON lista/`{"fronteras": [...]}` de instantes UTC ISO 8601 o epoch; también un instante ISO 8601 por línea. El instante de frontera pertenece al bloque nuevo. Se calculan pasos de 10 s y ventanas `(t−10,t]`, `(t−30,t]`, `(t−60,t]`; las historias no incluyen paquetes del bloque anterior. Las filas de arranque (<60 s desde el primer original) y las que cubren una frontera se conservan y reciben `motivo_marca`. `n_paquetes_ventana` y `n_eventos_l7_ventana` cuentan observaciones atribuidas a la IP en `(t−10,t]`.

`filas.csv` contiene ocho columnas de control y las 28 variables del contrato. `inventario_ips.json` enumera todas las IPv4 de los PCAP **antes** de deduplicar, con paquetes, bytes IP declarados, VLAN, instantes e interlocutores. Su regla es `poblacion`, `respuesta_servicio_a_poblacion` (DNS/servidor conocidos que hablan con la población), `gestion_excluida` (bastión, Kali y cliente de gestión conocidos) u `otra_excluida`. `resumen.json` cuenta paquetes lógicos incluidos y descartados, eventos EVE y copias quitadas.

`verificar_v2.py` genera `verificacion.json` y `.md`: contrasta el orden con el contrato, lee la fórmula del AST de `build_rows` de V1, informa constantes y conteos, y recalcula cada fila sobre el prefijo PCAP/EVE hasta su cierre usando las mismas funciones que invoca `motor_decision.py`. Por omisión verifica todas; `--max-filas N` deja constancia de una auditoría parcial. La verificación completa relee los originales por cada cierre y puede ser lenta.

## Contrato de las 28 columnas

En **cada fila** de esta tabla, «sin datos» produce **0.0, nunca NaN** según `safe_ratio`, `mean`, `shannon_entropy_bits` y los conteos de V1. Los contadores de control distinguen cero medido de inactividad. `p10`, `p30` son paquetes atribuidos a la IP; `a10`, `a30` son intentos de flujo; `h`, `d`, `n`, `t` son eventos HTTP, consultas DNS, respuestas NXDOMAIN y TLS en 60 s. `tcp10` son paquetes TCP en 10 s. Un denominador nulo da cero.

| # | Columna | Fórmula V1 | Unidad | Denominador | Ventana | Sin datos | Observabilidad en seis perfiles |
|---:|---|---|---|---|---:|---|---|
| 1 | `packet_rate_10s` | `len(p10)/10` | paquetes/s | 10 s | 10 s | 0 | variable por ritmo |
| 2 | `byte_rate_10s` | `sum(ip_length en p10)/10` | bytes IP/s | 10 s | 10 s | 0 | variable; depende de longitud IP |
| 3 | `mean_ip_len_10s` | `sum(ip_length en p10)/len(p10)` | bytes | p10 | 10 s | 0 | variable por aplicación |
| 4 | `large_ip_ratio_10s` | `count(500<=ip_length<=1500)/len(p10)` | razón | p10 | 10 s | 0 | posible en HTTP/HTTPS |
| 5 | `unique_dst_ip_ratio_30s` | `unique(peer_ip en a30)/len(a30)` | razón | a30 | 30 s | 0 | limitada por DNS/servidor |
| 6 | `icmp_ratio_10s` | `count(protocol==1)/len(p10)` | razón | p10 | 10 s | 0 | cero si no hay ICMP |
| 7 | `flow_attempt_rate_10s` | `len(a10)/10` | intentos/s | 10 s | 10 s | 0 | variable por conexiones |
| 8 | `syn_rate_10s` | `count(syn en p10)/10` | SYN/s | 10 s | 10 s | 0 | variable en TCP |
| 9 | `syn_completion_ratio_10s` | `min(SYN,SYN-ACK)/SYN` | razón | SYN p10 | 10 s | 0 | observable si el espejo ve ambos sentidos |
| 10 | `rst_ratio_10s` | `count(rst en tcp10)/len(tcp10)` | razón | tcp10 | 10 s | 0 | usualmente bajo |
| 11 | `unique_dst_port_ratio_30s` | `unique(target_port en a30 con puerto)/len(a30 con puerto)` | razón | a30 con puerto | 30 s | 0 | limitado a servicios usados |
| 12 | `http_error_ratio_60s` | `count(status>=400 en h)/len(h)` | razón | h | 60 s | 0 | cero si EVE no ve HTTP claro |
| 13 | `dns_nxdomain_ratio_60s` | `min(1,len(n)/len(d))` | razón | d | 60 s | 0 | depende de consultas fallidas EVE |
| 14 | `tls_session_rate_60s` | `unique(event_key en t)/60` | sesiones/s | 60 s | 60 s | 0 | presente con TLS visible en EVE |
| 15 | `ttl_mean_10s` | `mean(ttl en p10)` | TTL IP | p10 | 10 s | 0 | dedup conserva TTL mayor |
| 16 | `fragment_ratio_10s` | `count(fragmented en p10)/len(p10)` | razón | p10 | 10 s | 0 | probablemente cero |
| 17 | `protocol_diversity_30s` | `unique(protocol en p30)/len(p30)` | razón | p30 | 30 s | 0 | TCP/UDP; baja diversidad |
| 18 | `tcp_retransmission_ratio_10s` | `count(retransmission en datos TCP)/len(datos TCP)` | razón | segmentos TCP con datos | 10 s | 0 | normalmente bajo |
| 19 | `flow_duration_mean_30s` | `mean(max(flow_duration_so_far) por flow_id en p30)` | s | flujos de p30 | 30 s | 0 | variable; usa primer paquete histórico |
| 20 | `tx_rx_byte_ratio_30s` | `tx_bytes/(tx_bytes+rx_bytes)` | razón | bytes IP tx+rx | 30 s | 0 | variable por tipo de tráfico |
| 21 | `http_request_rate_60s` | `len(h)/60` | peticiones/s | 60 s | 60 s | 0 | solo HTTP observado por EVE |
| 22 | `http_method_entropy_60s` | `entropy(method en h)` | bits | h | 60 s | 0 | cero si solo GET o sin HTTP |
| 23 | `http_auth_failure_ratio_60s` | `count(status 401/403 en h)/len(h)` | razón | h | 60 s | 0 | probablemente bajo |
| 24 | `dns_query_rate_60s` | `len(d)/60` | consultas/s | 60 s | 60 s | 0 | presente si EVE registra DNS |
| 25 | `unique_dns_name_ratio_60s` | `min(1,unique(dns_name no vacío en d)/len(d))` | razón | d | 60 s | 0 | variable; nombres ausentes solo en denominador |
| 26 | `tls_handshake_failure_ratio_60s` | `count(tls_incomplete en t)/len(t)` | razón | t | 60 s | 0 | subestima fallos sin evento TLS |
| 27 | `tls_version_ratio_60s` | `count(version contiene 1.3)/len(t con versión)` | razón | TLS con versión | 60 s | 0 | constante si todo es TLS 1.3 |
| 28 | `http_status_5xx_ratio_60s` | `count(500<=status<=599 en h)/len(h)` | razón | h | 60 s | 0 | probablemente bajo |

## Memoria y límites

`load_packet_observations` de V1 carga el PCAP completo y `load_app_observations` el EVE completo. El extractor procesa PCAP fichero a fichero, deduplica con 5 ms de espera, conserva 60 s de paquetes y EVE y persiste en SQLite los primeros paquetes de flujos y secuencias TCP necesarios para atribución y retransmisión. Las filas intermedias van a disco. RAM depende de la tasa de 60 s y del número de IP del inventario, no del tamaño total (~30 GB); SQLite y las filas temporales requieren espacio adicional en `--salida`. `test_tramos_igual_a_procesado_completo` compara cada fila con un cálculo V1 desde el prefijo completo, incluido un flujo de más de 60 s. Los archivos y registros PCAP deben llegar en orden temporal; una inversión produce error. Se presupone EVE ordenado por timestamp.

La paridad se refiere a las funciones V1 que el motor invoca sobre la **misma entrada filtrada y deduplicada**. Una ejecución V1 sin ese preprocesado todavía incluye gestión y duplicados. Los límites del espejo y de EVE no se rellenan con datos fabricados.
