"""Tests sin red: python test_ioc_enricher.py"""
import time

import ioc_enricher
from ioc_enricher import csv_row, ioc_type, otx, refang, verdict

real_http_get = ioc_enricher.http_get  # otx() de abajo sustituye http_get; guardamos el real

assert refang("evil[.]com") == "evil.com"
assert refang("hxxps://evil[.]com/payload.exe") == "evil.com"
assert refang("185.220.101[.]1") == "185.220.101.1"

assert ioc_type("8.8.8.8") == "ip"
assert ioc_type("192.168.1.10") == "private_ip"
assert ioc_type("2001:4860:4860::8888") == "ip"
assert ioc_type("example.com") == "domain"
assert ioc_type("44d88612fea8a8f36de82e1278abb02f") == "hash"  # MD5 de EICAR
assert ioc_type("a" * 64) == "hash"
assert ioc_type("no es un ioc") is None

assert verdict({"virustotal": {"found": True, "malicious": 5}}) == "MALICIOSO"
assert verdict({"virustotal": {"found": True, "malicious": 0}, "abuseipdb": {"score": 90}}) == "MALICIOSO"
assert verdict({"virustotal": {"found": True, "suspicious": 1}}) == "SOSPECHOSO"
assert verdict({"virustotal": {"found": False}}) == "SIN DATOS"
assert verdict({"virustotal": {"found": True, "malicious": 0}}) == "LIMPIO"

# OTX con una respuesta simulada: comprueba la URL y cómo se leen los pulses
calls = []
ioc_enricher.http_get = lambda url, headers: calls.append(url) or {
    "pulse_info": {"count": 5, "pulses": [{"name": f"p{i}"} for i in range(5)]}}
assert otx("2001:db8::1", "ip", "k") == {"pulses": 5, "names": ["p0", "p1", "p2"]}
assert calls[-1].endswith("/indicators/IPv6/2001:db8::1/general")
otx("a" * 64, "hash", "k")
assert "/indicators/file/" in calls[-1]
ioc_enricher.http_get = lambda url, headers: None  # 404
assert otx("evil.com", "domain", "k") == {"pulses": 0, "names": []}

# csv_row aplana el resultado y deja en blanco lo que no aplica a ese tipo
row = csv_row({"ioc": "8.8.8.8", "type": "ip", "verdict": "LIMPIO",
               "virustotal": {"malicious": 0, "engines": 70, "link": "x"},
               "abuseipdb": {"score": 0}})
assert row["vt_engines"] == 70 and row["abuse_score"] == 0 and row["link"] == "x"
assert row["otx_pulses"] is None
assert csv_row({"ioc": "bad", "type": None, "verdict": "NO VÁLIDO"})["vt_malicious"] is None

# caché: sirve lo fresco sin tocar la red; reconsulta lo caducado y lo refresca
ioc_enricher._http_get_live = lambda url, headers: "LIVE"
ioc_enricher._CACHE_TTL = 3600
ioc_enricher._CACHE = {"u": [time.time(), "FRESCO"]}
assert real_http_get("u", {}) == "FRESCO"      # hit, no llama a _http_get_live
ioc_enricher._CACHE = {"u": [0, "VIEJO"]}       # caducado (epoch 0)
assert real_http_get("u", {}) == "LIVE"         # miss por TTL
assert ioc_enricher._CACHE["u"][1] == "LIVE"    # y se guarda lo nuevo
assert real_http_get("v", {}) == "LIVE" and "v" in ioc_enricher._CACHE
ioc_enricher._CACHE = None                              # vuelve al estado por defecto

print("OK")
