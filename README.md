# Nightwatch

A dependency-free cybersecurity toolkit. Runs on Python 3.9+ with **zero
third-party packages** — only the standard library.

## Modules

| Module | What it does |
| --- | --- |
| `phishing` | Heuristic URL/email scoring (typosquatting, punycode homographs, shorteners, credential-in-URL, suspicious TLDs) plus **live verification** (DNS resolution, redirect-chain following) and optional **local threat-intel blocklists** |
| `network` | Parses raw `.pcap` *and* `.pcapng` captures (Ethernet, Linux SLL, raw IP, IPv4 **and IPv6**): TCP flow tracking with handshake completion, **stream reassembly**, HTTP request/response extraction, DNS query extraction, **TLS SNI + JA3 fingerprinting**, and **C2 beaconing detection** |
| `honeypot` | TCP and HTTP decoy servers that log every connection (full multi-segment reads) and fingerprint attackers (suspicious path probing, brute-force patterns) |
| `logs` | Collects JSON/JSONL/CSV/syslog/text logs, correlates them with built-in or **custom JSON rules**, detects bursts with **real time-windowing** and writes markdown reports |
| `export` | **Persistence + SIEM integration**: append findings to a JSONL audit log or forward them to any HTTP endpoint (Splunk HEC, Elastic, Slack, …) |
| `web` | Browser dashboard (SOC-style dark UI) over a local HTTP API — no framework, no build step. Optional **bearer-token auth** on write endpoints |

Every module reports findings in a unified shape: `severity` / `label` /
`count` / `detail`.

## Install

```powershell
pip install .
```

or run without installing (works from the repository root). For development:

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

## CLI

```powershell
# Check a URL for phishing (heuristic + optional live verification)
python -m nightwatch.cli phish --url https://example.com/login --verify
python -m nightwatch.cli phish --url https://paypai.com/account --json

# Check a URL against a local threat-intel blocklist, export the verdict
python -m nightwatch.cli phish --url https://evil.test/login \
    --blocklist iocs.txt --export findings.jsonl

# Analyze a packet capture (classic .pcap OR modern .pcapng, IPv4/IPv6)
python -m nightwatch.cli pcap capture.pcapng
python -m nightwatch.cli pcap capture.pcapng --json --export findings.jsonl \
    --webhook https://collector.example.com/ingest

# Run a decoy server
python -m nightwatch.cli honeypot --http --port 8080
python -m nightwatch.cli honeypot --port 2222 --respond "220 fake ftp"

# Analyze logs (custom rules optional)
python -m nightwatch.cli logs /var/log/ --json
python -m nightwatch.cli logs app.log --rules rules.json --out report.md

# Launch the web dashboard with write-auth (NIGHTWATCH_API_TOKEN or --token)
python -m nightwatch.cli web --port 8001 --token s3cr3t
```

`phish` exits with code 1 when the verdict is `phishing`/`suspicious`, so it
fits into CI pipelines.

## Web dashboard

The web UI runs entirely off the standard library (`ThreadingHTTPServer`) and
ships static assets as files — no npm, no Flask, nothing to build.

```powershell
python -m nightwatch.cli web
# -> http://127.0.0.1:8000
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

### API

`GET /api/status`, `GET /api/honeypot/*`, `POST /api/phish` (with `"verify":
true` for live checks), `POST /api/phish/email`, `POST /api/pcap`,
`POST /api/logs`.

## Custom log rules

```json
[
  {"pattern": "token expired", "severity": "HIGH", "label": "token-expiry"},
  {"pattern": "disk full", "severity": "LOW", "label": "disk-space"}
]
```

```powershell
python -m nightwatch.cli logs app.log --rules rules.json
```

## Threat-intel blocklists

`phish` can be augmented with a local blocklist of known-bad indicators
(domains, URLs or keywords), one per line or as JSON
(`{"indicators": [...]}`):

```powershell
python -m nightwatch.cli phish --url https://evil.test/login --blocklist iocs.txt
```

## Exporting & SIEM integration

Findings from `phish`, `pcap` and `logs` can be persisted to a JSONL audit
log (`--export`) and/or forwarded to any HTTP endpoint (`--webhook`, optional
`--webhook-token`) for Splunk/Elastic/Slack ingestion.

## Project layout

```
nightwatch/
  cli.py          # argparse CLI
  phishing/       # detector.py: heuristics + verify_url + blocklists
  network/        # pcap.py: pcap/pcapng, ETH/IPv4/IPv6, SLL, raw parsing
                  # analyzer.py: reassembly, HTTP/DNS, TLS (SNI/JA3), beaconing
  honeypot/       # server.py: TCP + HTTP decoys, tracker.py: fingerprinting
  logs/           # collector.py: format parsing, analyzer.py: rules + bursts
  export.py       # persistence + SIEM/webhook sink
  web/            # server.py: stdlib HTTP API (+ optional auth), static/: UI
tests/            # pytest suite (55 tests, no network access required)
```
