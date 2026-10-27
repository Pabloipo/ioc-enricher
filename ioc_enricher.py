#!/usr/bin/env python3
"""ioc-enricher: enriquece IPs, dominios y hashes con VirusTotal, AbuseIPDB y AlienVault OTX.

Uso:
    python ioc_enricher.py 8.8.8.8 evil[.]com 44d88612fea8a8f36de82e1278abb02f
    python ioc_enricher.py -f iocs.txt --json

Claves por variable de entorno: VT_API_KEY (obligatoria), ABUSEIPDB_API_KEY y OTX_API_KEY (opcionales).
Solo usa la librería estándar de Python.
"""
import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def refang(ioc):
    """Quita el 'defang' de los informes conservando la URL entera: evil[.]com,
    hxxp://, 1.2.3[.]4, hxxps://evil[.]com/payload.exe."""
    ioc = ioc.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return re.sub(r"^hxxp", "http", ioc, flags=re.I)


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def ioc_type(ioc):
    """Devuelve 'ip', 'private_ip', 'hash', 'domain', 'url' o None."""
    if re.match(r"^https?://", ioc, re.I):
        return "url"
    try:
        ip = ipaddress.ip_address(ioc)
        return "ip" if ip.is_global else "private_ip"
    except ValueError:
        pass
    if HASH_RE.match(ioc):
        return "hash"
    if DOMAIN_RE.match(ioc):
        return "domain"
    # host/ruta sin esquema (evil.com/x, 1.2.3.4/x) también es una URL
    host = ioc.split("/", 1)[0].split("?", 1)[0]
    if "/" in ioc and (DOMAIN_RE.match(host) or _is_ip(host)):
        return "url"
    return None


# ponytail: caché global en memoria, único proceso CLI; sqlite si hiciera falta concurrencia
_CACHE = None          # dict {url: [epoch, respuesta]} cuando está activa, None si no
_CACHE_TTL = 24 * 3600  # segundos; respuestas más viejas se reconsultan


def _http_get_live(url, headers):
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            # La API gratuita de VT permite 4 peticiones/minuto: esperamos y reintentamos una vez
            if e.code == 429 and attempt == 0:
                print("  límite de peticiones alcanzado, esperando 60 s...", file=sys.stderr)
                time.sleep(60)
                continue
            raise


def http_get(url, headers):
    now = time.time()
    if _CACHE is not None:
        hit = _CACHE.get(url)
        if hit and now - hit[0] < _CACHE_TTL:
            return hit[1]
    result = _http_get_live(url, headers)
    if _CACHE is not None:
        _CACHE[url] = [now, result]
    return result


VT_API_PATH = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
VT_GUI_PATH = {"ip": "ip-address", "domain": "domain", "hash": "file", "url": "url"}


def vt_url_id(url):
    """Identificador de URL en VT v3: base64url sin relleno (no se sube la URL)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def virustotal(ioc, kind, key):
    ident = vt_url_id(ioc) if kind == "url" else ioc
    data = http_get(f"https://www.virustotal.com/api/v3/{VT_API_PATH[kind]}/{ident}",
                    {"x-apikey": key})
    if data is None:
        return {"found": False}
    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    out = {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "engines": sum(stats.values()),
        "reputation": a.get("reputation"),
        "link": f"https://www.virustotal.com/gui/{VT_GUI_PATH[kind]}/{ident}",
    }
    if kind == "ip":
        out.update(country=a.get("country"), as_owner=a.get("as_owner"))
    elif kind == "domain":
        out.update(registrar=a.get("registrar"))
    elif kind == "url":
        out.update(title=a.get("title"))
    else:
        out.update(name=a.get("meaningful_name"), type=a.get("type_description"))
    return out


def abuseipdb(ip, key):
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    d = http_get(f"https://api.abuseipdb.com/api/v2/check?{q}",
                 {"Key": key, "Accept": "application/json"})["data"]
    return {
        "score": d.get("abuseConfidenceScore"),
        "reports": d.get("totalReports"),
        "isp": d.get("isp"),
        "usage": d.get("usageType"),
        "tor": d.get("isTor"),
    }


def shodan(ip):
    """Shodan InternetDB: gratis y sin API key. Puertos, CVEs y tags de una IP."""
    d = http_get(f"https://internetdb.shodan.io/{ip}", {"Accept": "application/json"})
    if d is None:
        return None
    return {
        "ports": d.get("ports", []),
        "vulns": d.get("vulns", []),
        "tags": d.get("tags", []),
        "hostnames": d.get("hostnames", []),
    }


def otx(ioc, kind, key):
    if kind == "ip":
        slug = "IPv6" if ":" in ioc else "IPv4"
    else:
        slug = {"domain": "domain", "hash": "file", "url": "url"}[kind]
    ident = urllib.parse.quote(ioc, safe="") if kind == "url" else ioc
    d = http_get(f"https://otx.alienvault.com/api/v1/indicators/{slug}/{ident}/general",
                 {"X-OTX-API-KEY": key})
    pulses = (d or {}).get("pulse_info", {})
    return {
        "pulses": pulses.get("count", 0),
        "names": [p.get("name") for p in pulses.get("pulses", [])[:3]],
    }


def verdict(result):
    """Veredicto simple. Ajusta los umbrales a tu SOC."""
    vt = result.get("virustotal") or {}
    abuse = (result.get("abuseipdb") or {}).get("score") or 0
    mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
    if mal >= 3 or abuse >= 75:
        return "MALICIOSO"
    if mal or sus or abuse >= 25:
        return "SOSPECHOSO"
    if not vt.get("found", True):
        return "SIN DATOS"
    return "LIMPIO"


def enrich(raw, vt_key, abuse_key, otx_key=None):
    ioc = refang(raw)
    kind = ioc_type(ioc)
    result = {"ioc": ioc, "type": kind}
    if kind in (None, "private_ip"):
        result["verdict"] = "NO VÁLIDO" if kind is None else "IP PRIVADA"
        return result
    try:
        result["virustotal"] = virustotal(ioc, kind, vt_key)
        if kind == "ip":
            if abuse_key:
                result["abuseipdb"] = abuseipdb(ioc, abuse_key)
            sh = shodan(ioc)  # InternetDB no necesita clave
            if sh:
                result["shodan"] = sh
        if otx_key:
            result["otx"] = otx(ioc, kind, otx_key)
    except (urllib.error.URLError, KeyError) as e:
        result["error"] = str(e)
    result["verdict"] = verdict(result)
    return result


def print_result(r):
    print(f"\n[{r['verdict']}] {r['ioc']}" + (f" ({r['type']})" if r["type"] else ""))
    if "error" in r:
        print(f"  error: {r['error']}")
    vt = r.get("virustotal")
    if vt and vt["found"]:
        print(f"  VirusTotal: {vt['malicious']}/{vt['engines']} maliciosos, "
              f"{vt['suspicious']} sospechosos, reputación {vt['reputation']}")
        extra = {k: v for k, v in vt.items()
                 if k in ("country", "as_owner", "registrar", "name", "type", "title") and v}
        if extra:
            print("  " + ", ".join(f"{k}: {v}" for k, v in extra.items()))
        print(f"  {vt['link']}")
    elif vt:
        print("  VirusTotal: sin resultados")
    ab = r.get("abuseipdb")
    if ab:
        print(f"  AbuseIPDB: score {ab['score']}%, {ab['reports']} reportes, "
              f"ISP {ab['isp']}, uso {ab['usage']}, Tor: {ab['tor']}")
    sh = r.get("shodan")
    if sh:
        ports = ", ".join(map(str, sh["ports"])) or "ninguno"
        line = f"  Shodan: puertos {ports}"
        if sh["vulns"]:
            line += f"; {len(sh['vulns'])} CVEs (p. ej. {', '.join(sh['vulns'][:3])})"
        if sh["tags"]:
            line += f"; tags: {', '.join(sh['tags'])}"
        print(line)
    ox = r.get("otx")
    if ox:
        names = f" (p. ej. {'; '.join(ox['names'])})" if ox["names"] else ""
        print(f"  AlienVault OTX: aparece en {ox['pulses']} pulses{names}")


CSV_COLUMNS = ["ioc", "type", "verdict", "vt_malicious", "vt_suspicious",
               "vt_engines", "vt_reputation", "abuse_score", "abuse_reports",
               "shodan_ports", "shodan_vulns", "otx_pulses", "link", "error"]


def csv_row(r):
    vt = r.get("virustotal") or {}
    ab = r.get("abuseipdb") or {}
    sh = r.get("shodan") or {}
    ox = r.get("otx") or {}
    return {
        "ioc": r.get("ioc"),
        "type": r.get("type"),
        "verdict": r.get("verdict"),
        "vt_malicious": vt.get("malicious"),
        "vt_suspicious": vt.get("suspicious"),
        "vt_engines": vt.get("engines"),
        "vt_reputation": vt.get("reputation"),
        "abuse_score": ab.get("score"),
        "abuse_reports": ab.get("reports"),
        "shodan_ports": len(sh["ports"]) if sh else None,
        "shodan_vulns": len(sh["vulns"]) if sh else None,
        "otx_pulses": ox.get("pulses"),
        "link": vt.get("link"),
        "error": r.get("error"),
    }


def print_csv(results):
    w = csv.DictWriter(sys.stdout, fieldnames=CSV_COLUMNS)
    w.writeheader()
    for r in results:
        w.writerow(csv_row(r))


DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".ioc_enricher_cache.json")


def load_cache(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_cache(path, cache):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError as e:
        print(f"  no se pudo guardar la caché: {e}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="Enriquece IOCs con VirusTotal y AbuseIPDB.")
    p.add_argument("iocs", nargs="*", help="IPs, dominios o hashes (MD5/SHA1/SHA256)")
    p.add_argument("-f", "--file", help="fichero con un IOC por línea (# para comentarios)")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="salida en JSON")
    out.add_argument("--csv", action="store_true", help="salida en CSV")
    p.add_argument("--no-cache", action="store_true",
                   help="no usar la caché local (por defecto se cachea en ~/.ioc_enricher_cache.json)")
    p.add_argument("--cache-file", default=DEFAULT_CACHE, help="ruta del fichero de caché")
    p.add_argument("--cache-ttl", type=float, default=24,
                   help="horas que vale una respuesta cacheada (por defecto 24)")
    args = p.parse_args()

    iocs = list(args.iocs)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            iocs += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not iocs:
        p.error("indica al menos un IOC o un fichero con -f")

    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        sys.exit("Falta la variable de entorno VT_API_KEY")
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    otx_key = os.environ.get("OTX_API_KEY")

    if not args.no_cache:
        global _CACHE, _CACHE_TTL
        _CACHE_TTL = args.cache_ttl * 3600
        _CACHE = load_cache(args.cache_file)

    results = [enrich(i, vt_key, abuse_key, otx_key) for i in dict.fromkeys(iocs)]

    if _CACHE is not None:
        save_cache(args.cache_file, _CACHE)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif args.csv:
        print_csv(results)
    else:
        for r in results:
            print_result(r)


if __name__ == "__main__":
    main()
