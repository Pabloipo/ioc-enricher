# ioc-enricher

Script en Python que consulta IPs, dominios y hashes en [VirusTotal](https://www.virustotal.com), [AbuseIPDB](https://www.abuseipdb.com) y [AlienVault OTX](https://otx.alienvault.com) y da un veredicto rápido. Lo uso para el triage de alertas.

Funciona con Python 3.8 o superior y no necesita instalar ninguna librería.

## Qué hace

- Reconoce si el IOC es una IPv4/IPv6, un dominio, una URL o un hash (MD5, SHA1 o SHA256).
- Acepta IOCs "defangeados" como vienen en los informes (`evil[.]com`, `hxxps://`, `1.2.3[.]4`).
- Las IPs privadas las salta para no gastar consultas.
- Consulta VirusTotal para todo y, si es una IP, también AbuseIPDB y Shodan (puertos abiertos, CVEs y tags). Con `SHODAN_API_KEY` usa la API completa (org/ISP, ASN, país, SO y servicios detectados); sin clave cae a InternetDB, que es gratis.
- Si tienes clave de OTX, dice en cuántos pulses aparece el IOC y el nombre de algunos.
- Si tienes clave de URLhaus (abuse.ch), comprueba si el IOC está en su feed de URLs de malware.
- Devuelve `MALICIOSO`, `SOSPECHOSO`, `LIMPIO` o `SIN DATOS`.
- Con `--json` saca el resultado en JSON, o con `--csv` en CSV, para pasarlo a otra herramienta.

## Instalación

```bash
git clone https://github.com/Pabloipo/ioc-enricher.git
cd ioc-enricher
```

Hace falta una API key gratuita de VirusTotal. Las de AbuseIPDB, OTX, URLhaus y Shodan son opcionales (sin clave de Shodan se usa InternetDB, que es gratis).

| Servicio | Dónde sacar la clave |
|---|---|
| VirusTotal | Crea una cuenta en virustotal.com, menú de tu usuario > API key |
| AbuseIPDB | Crea una cuenta en abuseipdb.com, Account > API > Create Key |
| AlienVault OTX | Crea una cuenta en otx.alienvault.com, tu usuario > Settings > OTX Key |
| URLhaus | Crea una cuenta en auth.abuse.ch, perfil > Auth-Key |
| Shodan | Crea una cuenta en shodan.io, Account > API Key (opcional: sin ella se usa InternetDB) |

```bash
# Linux / macOS
export VT_API_KEY="tu_clave"
export ABUSEIPDB_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"
export URLHAUS_API_KEY="tu_clave"
export SHODAN_API_KEY="tu_clave"
```

```powershell
# Windows (PowerShell)
$env:VT_API_KEY = "tu_clave"
$env:ABUSEIPDB_API_KEY = "tu_clave"
$env:OTX_API_KEY = "tu_clave"
$env:URLHAUS_API_KEY = "tu_clave"
$env:SHODAN_API_KEY = "tu_clave"
```

## Uso

```bash
python ioc_enricher.py 185.220.101[.]1 example.com 44d88612fea8a8f36de82e1278abb02f
python ioc_enricher.py -f iocs.txt
python ioc_enricher.py -f iocs.txt --json > resultado.json
python ioc_enricher.py -f iocs.txt --csv > resultado.csv
```

Ejemplo de salida (las cifras son inventadas):

```
[MALICIOSO] 44d88612fea8a8f36de82e1278abb02f (hash)
  VirusTotal: 62/76 maliciosos, 0 sospechosos, reputación -5
  name: eicar.com, type: Text
  https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f
```

## Cómo decide el veredicto

| Veredicto | Condición |
|---|---|
| MALICIOSO | 3 o más motores de VT lo marcan como malicioso, o AbuseIPDB ≥ 75 %, o una URL/hash está en URLhaus |
| SOSPECHOSO | Algún motor lo marca como malicioso o sospechoso, o AbuseIPDB ≥ 25 %, o una IP/dominio está en URLhaus |
| SIN DATOS | VirusTotal no lo conoce |
| LIMPIO | Ninguno de los anteriores |

Los umbrales están en la función `verdict()` y se pueden cambiar. Ojo: que salga LIMPIO no quiere decir que sea seguro. Puede que el IOC sea nuevo y nadie lo haya analizado todavía.

Shodan tampoco cuenta para el veredicto: los CVEs de InternetDB son servicios expuestos que *podrían* ser vulnerables (quizá ya parcheados), así que se muestran como contexto, no como señal de malicia.

OTX no cuenta para el veredicto. Dominios inofensivos como `example.com` aparecen en decenas de pulses porque la gente los mete en sus listas, así que el número de pulses se muestra como contexto para que lo valores tú.

## Caché local

Para no repetir consultas (y no gastar cuota), las respuestas se cachean en `~/.ioc_enricher_cache.json`. Una respuesta vale 24 horas por defecto; pasado ese tiempo se vuelve a consultar.

```bash
python ioc_enricher.py 8.8.8.8 --cache-ttl 6     # las respuestas valen 6 h
python ioc_enricher.py 8.8.8.8 --cache-file ./iocs.cache.json
python ioc_enricher.py 8.8.8.8 --no-cache        # ignora la caché
```

## Límites

- Con la API gratuita de VirusTotal solo puedes hacer 4 consultas por minuto y 500 al día. Si te pasas, el script espera 60 segundos y lo intenta una vez más.
- Las URLs se consultan enteras, pero solo si VirusTotal ya las conoce: el script no las envía a analizar (saldría `SIN DATOS`).

## Tests

```bash
python test_ioc_enricher.py
```

No usan la red ni necesitan API keys.

## Pendiente

- [x] Analizar URLs completas
- [x] Añadir AlienVault OTX
- [x] Añadir Shodan (InternetDB, sin key)
- [x] Añadir URLhaus
- [x] Soportar la API completa de Shodan con key (SHODAN_API_KEY)
- [x] Exportar a CSV
- [x] Guardar una caché local para no repetir consultas

## Licencia

MIT
