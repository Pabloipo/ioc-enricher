#!/usr/bin/env python3
"""ioc-enricher: enriquece IPs, dominios y hashes con VirusTotal, AbuseIPDB y AlienVault OTX.

Uso:
    python ioc_enricher.py 8.8.8.8 evil[.]com 44d88612fea8a8f36de82e1278abb02f
    python ioc_enricher.py -f iocs.txt --json

Claves por variable de entorno: VT_API_KEY (obligatoria), ABUSEIPDB_API_KEY y OTX_API_KEY (opcionales).
Solo usa la librería estándar de Python.
"""
import argparse
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
    """Quita el 'defang' típico de los informes: evil[.]com, hxxp://, 1.2.3[.]4."""
    ioc = ioc.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    ioc = re.sub(r"^hxxps?://", "", ioc, flags=re.I)
    ioc = re.sub(r"^https?://", "", ioc, flags=re.I)
    return ioc.split("/")[0] if "." in ioc and not HASH_RE.match(ioc) else ioc


def ioc_type(ioc):
    """Devuelve 'ip', 'private_ip', 'hash', 'domain' o None."""
    try:
        ip = ipaddress.ip_address(ioc)
        return "ip" if ip.is_global else "private_ip"
    except ValueError:
        pass
    if HASH_RE.match(ioc):
        return "hash"
    if DOMAIN_RE.match(ioc):
        return "domain"
    return None


def http_get(url, headers):
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


VT_API_PATH = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
VT_GUI_PATH = {"ip": "ip-address", "domain": "domain", "hash": "file"}


def virustotal(ioc, kind, key):
    data = http_get(f"https://www.virustotal.com/api/v3/{VT_API_PATH[kind]}/{ioc}",
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
        "link": f"https://www.virustotal.com/gui/{VT_GUI_PATH[kind]}/{ioc}",
    }
    if kind == "ip":
        out.update(country=a.get("country"), as_owner=a.get("as_owner"))
    elif kind == "domain":
        out.update(registrar=a.get("registrar"))
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


def otx(ioc, kind, key):
    if kind == "ip":
        slug = "IPv6" if ":" in ioc else "IPv4"
    else:
        slug = {"domain": "domain", "hash": "file"}[kind]
    d = http_get(f"https://otx.alienvault.com/api/v1/indicators/{slug}/{ioc}/general",
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
        if kind == "ip" and abuse_key:
            result["abuseipdb"] = abuseipdb(ioc, abuse_key)
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
                 if k in ("country", "as_owner", "registrar", "name", "type") and v}
        if extra:
            print("  " + ", ".join(f"{k}: {v}" for k, v in extra.items()))
        print(f"  {vt['link']}")
    elif vt:
        print("  VirusTotal: sin resultados")
    ab = r.get("abuseipdb")
    if ab:
        print(f"  AbuseIPDB: score {ab['score']}%, {ab['reports']} reportes, "
              f"ISP {ab['isp']}, uso {ab['usage']}, Tor: {ab['tor']}")
    ox = r.get("otx")
    if ox:
        names = f" (p. ej. {'; '.join(ox['names'])})" if ox["names"] else ""
        print(f"  AlienVault OTX: aparece en {ox['pulses']} pulses{names}")


def main():
    p = argparse.ArgumentParser(description="Enriquece IOCs con VirusTotal y AbuseIPDB.")
    p.add_argument("iocs", nargs="*", help="IPs, dominios o hashes (MD5/SHA1/SHA256)")
    p.add_argument("-f", "--file", help="fichero con un IOC por línea (# para comentarios)")
    p.add_argument("--json", action="store_true", help="salida en JSON")
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

    results = [enrich(i, vt_key, abuse_key, otx_key) for i in dict.fromkeys(iocs)]
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for r in results:
            print_result(r)


if __name__ == "__main__":
    main()
