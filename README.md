# ioc-enricher

[![tests](https://github.com/Pabloipo/ioc-enricher/actions/workflows/tests.yml/badge.svg)](https://github.com/Pabloipo/ioc-enricher/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Python script that looks up IPs, domains and hashes in [VirusTotal](https://www.virustotal.com), [AbuseIPDB](https://www.abuseipdb.com) and [AlienVault OTX](https://otx.alienvault.com) and gives a quick verdict. I use it for alert triage.

Runs on Python 3.8 or later and needs no third-party libraries.

> Note: the tool's console output and verdict labels are currently in Spanish (`MALICIOSO`, `SOSPECHOSO`, `LIMPIO`, `SIN DATOS`). This README is in English; the examples below show the real output verbatim.

## What it does

- Recognises whether the IOC is an IPv4/IPv6, a domain, a URL or a hash (MD5, SHA1 or SHA256).
- Accepts "defanged" IOCs as they appear in reports (`evil[.]com`, `hxxps://`, `1.2.3[.]4`).
- Skips private IPs so it doesn't waste lookups.
- Queries VirusTotal for everything and, for IPs, also AbuseIPDB and Shodan (open ports, CVEs and tags). With `SHODAN_API_KEY` it uses the full API (org/ISP, ASN, country, OS and detected services); without a key it falls back to InternetDB, which is free.
- With an OTX key, it reports how many pulses the IOC appears in and some of their names.
- With a URLhaus key (abuse.ch), it checks whether the IOC is in their malware-URL feed.
- Returns `MALICIOSO`, `SOSPECHOSO`, `LIMPIO` or `SIN DATOS` (malicious / suspicious / clean / no data).
- With `--json` it prints the result as JSON, or `--csv` as CSV, to pipe into another tool.

## Installation

```bash
git clone https://github.com/Pabloipo/ioc-enricher.git
cd ioc-enricher
```

You need a free VirusTotal API key. AbuseIPDB, OTX, URLhaus and Shodan are optional (without a Shodan key it uses InternetDB, which is free).

| Service | Where to get the key |
|---|---|
| VirusTotal | Create an account at virustotal.com, your user menu > API key |
| AbuseIPDB | Create an account at abuseipdb.com, Account > API > Create Key |
| AlienVault OTX | Create an account at otx.alienvault.com, your user > Settings > OTX Key |
| URLhaus | Create an account at auth.abuse.ch, profile > Auth-Key |
| Shodan | Create an account at shodan.io, Account > API Key (optional: without it, InternetDB is used) |

```bash
# Linux / macOS
export VT_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export OTX_API_KEY="your_key"
export URLHAUS_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
```

```powershell
# Windows (PowerShell)
$env:VT_API_KEY = "your_key"
$env:ABUSEIPDB_API_KEY = "your_key"
$env:OTX_API_KEY = "your_key"
$env:URLHAUS_API_KEY = "your_key"
$env:SHODAN_API_KEY = "your_key"
```

## Usage

```bash
python ioc_enricher.py 185.220.101[.]1 example.com 44d88612fea8a8f36de82e1278abb02f
python ioc_enricher.py -f iocs.txt
python ioc_enricher.py -f iocs.txt --json > result.json
python ioc_enricher.py -f iocs.txt --csv > result.csv
```

Example output (numbers are made up; output is in Spanish as noted above):

```
[MALICIOSO] 44d88612fea8a8f36de82e1278abb02f (hash)
  VirusTotal: 62/76 maliciosos, 0 sospechosos, reputación -5
  name: eicar.com, type: Text
  https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f
```

## How the verdict is decided

| Verdict | Condition |
|---|---|
| MALICIOSO | 3 or more VT engines flag it as malicious, or AbuseIPDB ≥ 75%, or a URL/hash is in URLhaus |
| SOSPECHOSO | Any engine flags it as malicious or suspicious, or AbuseIPDB ≥ 25%, or an IP/domain is in URLhaus |
| SIN DATOS | VirusTotal doesn't know it |
| LIMPIO | None of the above |

The thresholds live in the `verdict()` function and can be changed. Heads up: a `LIMPIO` result doesn't mean the IOC is safe — it may be new and simply not analysed by anyone yet.

Shodan doesn't count toward the verdict either: InternetDB CVEs are exposed services that *might* be vulnerable (perhaps already patched), so they're shown as context, not as a malice signal.

OTX doesn't count toward the verdict. Harmless domains like `example.com` show up in dozens of pulses because people add them to their lists, so the pulse count is shown as context for you to weigh.

## Local cache

To avoid repeating lookups (and burning quota), responses are cached in `~/.ioc_enricher_cache.json`. A response is valid for 24 hours by default; after that it is queried again.

```bash
python ioc_enricher.py 8.8.8.8 --cache-ttl 6     # responses valid for 6 h
python ioc_enricher.py 8.8.8.8 --cache-file ./iocs.cache.json
python ioc_enricher.py 8.8.8.8 --no-cache        # ignore the cache
```

## Limits

- With the free VirusTotal API you can only make 4 lookups per minute and 500 per day. If you exceed it, the script waits 60 seconds and retries once.
- URLs are looked up whole, but only if VirusTotal already knows them: the script doesn't submit them for analysis (that would show `SIN DATOS`).

## Tests

```bash
python test_ioc_enricher.py
```

They use no network and need no API keys.

## Roadmap

- [x] Analyse full URLs
- [x] Add AlienVault OTX
- [x] Add Shodan (InternetDB, keyless)
- [x] Add URLhaus
- [x] Support the full Shodan API with a key (SHODAN_API_KEY)
- [x] Export to CSV
- [x] Local cache to avoid repeated lookups

## License

MIT
