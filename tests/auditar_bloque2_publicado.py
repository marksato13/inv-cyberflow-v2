#!/usr/bin/env python3
"""Contrasta T1/T2 publicados con los programas vigentes; no inicia tráfico ni servicios."""
from __future__ import annotations

import collections
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "generador"))
sys.path.insert(0, str(REPO / "programas"))
import programa
import generar_programas

EJECUCIONES = (
    ("V2-T1-20261125T062528Z", "prueba-perfiles-aislados.json"),
    ("V2-T2-20261125T070500Z", "prueba-niveles-transiciones.json"),
)


def auditar():
    resultados = []
    for identificador, nombre in EJECUCIONES:
        ruta_programa = REPO / "programas" / nombre
        p = programa.cargar(ruta_programa)
        for bloque in p["bloques"]:
            for perfil in programa.PERFILES:
                for flujo in programa.FLUJOS:
                    assert bloque["semillas"][perfil][flujo] == generar_programas.semilla(
                        p["programa_id"], bloque["id"], perfil, flujo)
        sha = hashlib.sha256(ruta_programa.read_bytes()).hexdigest()
        carpeta = REPO / "evidencias" / "bloque1" / "dns-entradas" / identificador / "generador" / identificador
        archivos = sorted(carpeta.glob("transacciones-P*.jsonl"))
        assert len(archivos) == 6, (identificador, archivos)
        txs = [json.loads(linea) for archivo in archivos
               for linea in archivo.read_text(encoding="utf-8").splitlines()]
        assert txs and {x["perfil"] for x in txs} == set(programa.PERFILES)
        errores = []
        for x in txs:
            perfil, t = x["perfil"], x["inicio_t_s"]
            jornada = programa.tramo_en(p["jornadas"], t)
            bloque = programa.tramo_en(p["bloques"], t)
            if (x["programa_sha256"] != sha or x["origen_ip"] != p["perfiles"][perfil]["origen"] or
                x["jornada_id"] != jornada["id"] or x["bloque_id"] != bloque["id"] or
                x["nivel"] != programa.nivel_en(p, perfil, t) or
                x["factor"] != p["factores"][x["nivel"]] or x["clase"] != "ok"):
                errores.append((x["transaccion_id"], "programa/origen/nivel/clase"))
            if x["accion"] == "dns":
                if (x["destino_ip"] != p["destinos"]["dns_servidor"] or x["destino_puerto"] != 53 or
                    x["dns_nombre"].split(".")[0] not in p["destinos"]["dns_nombres"] or
                    not x["dns_nombre"].endswith("." + p["destinos"]["dns_zona"]) or
                    x["dns_respuestas"] != [p["destinos"]["dns_ip_esperada"]] or x["dns_rcode"] != 0 or
                    (perfil == "P6" and not programa.on_p6(p, t))):
                    errores.append((x["transaccion_id"], "DNS/P6"))
            else:
                esperado_codigo = 201 if x["accion"] == "envio" else 200
                esperado_puerto = 443 if x["protocolo"] == "https" else 80
                if (x["destino_ip"] != p["destinos"]["servidor"] or
                    x["destino_puerto"] != esperado_puerto or
                    x["http_codigo"] != esperado_codigo or
                    (perfil != "P2" and x["protocolo"] != "http") or
                    (x["accion"] == "obtener" and
                     (x["bytes_cuerpo_recibidos"] != x["bytes_solicitados"] or
                      not x["ruta"].startswith("/contenido/"))) or
                    (x["accion"] == "consulta" and
                     (x["ruta"] != "/app/consulta?ref=" + str(x["ref"]) or
                      x["bytes_cuerpo_recibidos"] != 512)) or
                    (x["accion"] == "envio" and x["ruta"] != "/app/envio")):
                    errores.append((x["transaccion_id"], "HTTP/respuesta"))
        p2 = [x for x in txs if x["perfil"] == "P2" and x["accion"] != "dns"]
        paginas = collections.defaultdict(list)
        for x in p2:
            paginas[(x["bloque_id"], x["secuencia_id"])].append(x)
        for clave, xs in paginas.items():
            xs.sort(key=lambda x: x["inicio_t_s"])
            if (len({x["conexion_n"] for x in xs}) != 1 or
                [x["peticion_en_conexion"] for x in xs] != list(range(1, len(xs) + 1)) or
                xs[0]["tipo_objeto"] != "principal" or
                any(x["tipo_objeto"] != "secundario" for x in xs[1:])):
                errores.append((str(clave), "P2 conexion/objetos"))
        por_bloque = collections.defaultdict(list)
        for clave, xs in paginas.items():
            por_bloque[clave[0]].append((xs[0]["inicio_t_s"], xs[0]["protocolo"]))
        for bloque, paginas_bloque in por_bloque.items():
            protocolos = [proto for _, proto in sorted(paginas_bloque)]
            if protocolos != ["http" if i % 2 == 0 else "https" for i in range(len(protocolos))]:
                errores.append((bloque, "P2 alternancia"))
        assert not errores, (identificador, errores[:15])
        resultados.append({"id": identificador, "programa": nombre, "sha256_programa": sha,
                           "transacciones": len(txs), "errores": 0,
                           "por_perfil": dict(sorted(collections.Counter(x["perfil"] for x in txs).items())),
                           "por_accion": dict(sorted(collections.Counter(x["accion"] for x in txs).items())),
                           "por_nivel": dict(sorted(collections.Counter(x["nivel"] for x in txs).items())),
                           "p2_paginas": len(paginas),
                           "p2_http": sum(x["protocolo"] == "http" for x in p2),
                           "p2_https": sum(x["protocolo"] == "https" for x in p2)})
    return {"tipo": "auditoria de evidencia historica dirigida; no captura nueva",
            "ejecuciones": resultados}


if __name__ == "__main__":
    informe = auditar()
    datos = json.dumps(informe, ensure_ascii=False, indent=2) + "\n"
    if len(sys.argv) == 3 and sys.argv[1] == "--salida":
        Path(sys.argv[2]).write_text(datos, encoding="utf-8")
    print(datos)
