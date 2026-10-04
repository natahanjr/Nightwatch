# Nightwatch

> A dependency-free cybersecurity toolkit — phishing detection, pcap traffic
> analysis, honeypots, log correlation and a browser dashboard. Pure Python
> standard library, Python 3.9+.

![python](https://img.shields.io/badge/python-3.9%2B-blue)
![deps](https://img.shields.io/badge/dependencies-zero-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

## Overview

| Module | What it does |
| --- | --- |
| `phishing` | Heuristic URL/email scoring (typosquatting, punycode homographs, shorteners, credential-in-URL, suspicious TLDs) plus **live verification** (DNS resolution, redirect-chain following) and optional **local threat-intel blocklists** |
| `network` | Parses raw `.pcap` *and* `.pcapng` captures (Ethernet, Linux SLL, raw IP, IPv4 **and IPv6**): TCP flow tracking with handshake completion, **stream reassembly**, HTTP request/response extraction, DNS query extraction, **TLS SNI + JA3 fingerprinting**, and **C2 beaconing detection** |
| `honeypot` | TCP and HTTP decoy servers that log every connection (full multi-segment reads) and fingerprint attackers (suspicious path probing, brute-force patterns) |
| `logs` | Collects JSON/JSONL/CSV/syslog/text logs, correlates them with built-in or **custom JSON rules**, detects bursts with **real time-windowing** and writes markdown reports |
| `export` | **Persistence + SIEM integration**: append findings to a JSONL audit log or forward them to any HTTP endpoint (Splunk HEC, Elastic, Slack, …) |
| `web` | Browser dashboard (SOC-style dark UI) over a local HTTP API — no framework, no build step. Optional **bearer-token auth** on write endpoints |

Library-only modules are also included: `osint`, `threat_intel`, `cti`,
`dfir`, `crypto_audit`, `posture`, `sandbox` and a small `ml` package
(models, features, metrics) used by the detectors.

Every module reports findings in a unified shape: `severity` / `label` /
`count` / `detail`.

## Requirements

- Python **3.9 or newer**
- No third-party packages — standard library only

## Installation

```bash
pip install .
```

Or run it straight from the repository root without installing:

```bash
python3 -m nightwatch.cli --help
```

For development:

```bash
pip install -r requirements-dev.txt
python3 -m pytest
```

## CLI

```bash
# Check a URL for phishing (heuristic + optional live verification)
python3 -m nightwatch.cli phish --url https://example.com/login --verify
python3 -m nightwatch.cli phish --url https://paypai.com/account --json

# Check against a local threat-intel blocklist, export the verdict
python3 -m nightwatch.cli phish --url https://evil.test/login \
    --blocklist iocs.txt --export findings.jsonl

# Analyze a packet capture (.pcap or .pcapng, IPv4/IPv6)
python3 -m nightwatch.cli pcap capture.pcapng
python3 -m nightwatch.cli pcap capture.pcapng --json --export findings.jsonl \
    --webhook https://collector.example.com/ingest

# Run a decoy server
python3 -m nightwatch.cli honeypot --http --port 8080
python3 -m nightwatch.cli honeypot --port 2222 --respond "220 fake ftp"

# Analyze logs (custom rules optional)
python3 -m nightwatch.cli logs /var/log/ --json
python3 -m nightwatch.cli logs app.log --rules rules.json --out report.md

# Launch the web dashboard with write-auth (NIGHTWATCH_API_TOKEN or --token)
python3 -m nightwatch.cli web --port 8001 --token s3cr3t
python3 -m nightwatch.cli web --no-browser --blocklist iocs.txt
```

After `pip install .` the same commands are available as `nightwatch …`
(e.g. `nightwatch phish --url …`).

`phish` exits with code `1` when the verdict is `phishing`/`suspicious` and
`2` on usage errors, so it fits directly into CI pipelines.

## Library usage

```python
from nightwatch.phishing import check_url
from nightwatch.network import analyze_pcap
from nightwatch.logs import collect, analyze

verdict = check_url("https://paypai.com/login")
print(verdict["verdict"], verdict["score"], verdict["flags"])

traffic = analyze_pcap("capture.pcapng")    # flows, DNS, TLS, findings
report = analyze(collect("app.log"))        # findings, bursts, levels
```

## Web dashboard

The web UI runs entirely off the standard library (`ThreadingHTTPServer`)
and ships static assets as files — no npm, no Flask, nothing to build.

```bash
python3 -m nightwatch.cli web
# -> http://127.0.0.1:8000 (opens your browser automatically; --no-browser to skip)
```

Tabs:

- **Phishing** — paste a link or an email; optional live verification shows
  the IPs the domain resolves to, the redirect chain, and whether the link
  ends up on a different domain.
- **Traffic** — upload a `.pcap`; get connection counts, websites visited,
  DNS queries, possible C2 beacons and severity-ranked findings.
- **Honeypot** — start/stop a TCP or HTTP decoy, watch live connections and
  run attacker analysis.
- **Logs** — upload logs and get findings, bursts and a downloadable
  markdown report.
- **Threat Intel** — indicator lookup against local/remote feeds.
- **DFIR** — build an investigation timeline from event logs.
- **Sandbox** — static analysis of a suspicious sample.
- **OSINT** — surface reconnaissance on a domain.
- **Posture** — cloud/IAM misconfiguration analysis.
- **Crypto** — certificate, key and cipher hygiene checks.

### API

| Endpoint | Description |
| --- | --- |
| `GET /api/status` | Server and honeypot status |
| `POST /api/phish` | Check a URL (`"verify": true` for live checks) |
| `POST /api/phish/email` | Check an email body |
| `POST /api/pcap` | Upload and analyze a capture |
| `POST /api/logs` | Upload and analyze logs |
| `GET /api/honeypot/status` | Honeypot state |
| `GET /api/honeypot/events` | Captured connections |
| `GET /api/honeypot/analysis` | Attacker fingerprint analysis |
| `POST /api/honeypot/start` / `stop` / `clear` | Control the decoy |
| `POST /api/threat_intel` | Indicator lookup |
| `POST /api/dfir` | Timeline reconstruction |
| `POST /api/sandbox` | Static sample analysis |
| `POST /api/osint` | Domain reconnaissance |
| `POST /api/posture` | Posture analysis |
| `POST /api/crypto` | Crypto/cert checks |

Write endpoints require `Authorization: Bearer <token>` when the server is
started with `--token` / `NIGHTWATCH_API_TOKEN`.

## Recipes

### Custom log rules

```json
[
  {"pattern": "token expired", "severity": "HIGH", "label": "token-expiry"},
  {"pattern": "disk full", "severity": "LOW", "label": "disk-space"}
]
```

```bash
python3 -m nightwatch.cli logs app.log --rules rules.json
```

### Threat-intel blocklists

`phish` can be augmented with a local blocklist of known-bad indicators
(domains, URLs or keywords), one per line or as JSON
(`{"indicators": [...]}`):

```bash
python3 -m nightwatch.cli phish --url https://evil.test/login --blocklist iocs.txt
```

### Exporting & SIEM integration

Findings from `phish`, `pcap` and `logs` can be persisted to a JSONL audit
log (`--export`) and/or forwarded to any HTTP endpoint (`--webhook`, optional
`--webhook-token`) for Splunk/Elastic/Slack ingestion.

## Project structure

```
nightwatch/
  cli.py            # argparse CLI (phish, pcap, honeypot, logs, web)
  phishing/         # detector.py: heuristics + verify_url + blocklists
  network/          # pcap.py: pcap/pcapng, ETH/IPv4/IPv6, SLL, raw parsing
                    # analyzer.py: reassembly, HTTP/DNS, TLS (SNI/JA3), beaconing
  honeypot/         # server.py: TCP + HTTP decoys, tracker.py: fingerprinting
  logs/             # collector.py: format parsing, analyzer.py: rules + bursts
  cti/              # threat-intel feed fetching, caching and indicator store
  ml/               # features, linear/tree models, RNG and linalg helpers
  web/              # server.py: stdlib HTTP API (+ optional auth), static/: UI
  export.py         # persistence + SIEM/webhook sink
  osint.py          # external-domain reconnaissance
  threat_intel.py   # indicator lookups
  dfir.py           # timeline reconstruction from event logs
  crypto_audit.py   # crypto / key-management checks
  posture.py        # cloud & IAM posture analysis
  sandbox.py        # static malware-sample analysis
tests/              # pytest suite (69 tests, no internet access required)
docs/               # generated project documentation (HTML + PDF)
```

## Testing

```bash
python3 -m pytest          # whole suite
python3 -m pytest tests/test_phishing.py -v
```

The suite runs offline — network tests bind to `127.0.0.1` only.

## Documentation

Full reference documentation lives in [`docs/`](docs/) as HTML and PDF.

## License

MIT — see the `license` field in [`pyproject.toml`](pyproject.toml).
