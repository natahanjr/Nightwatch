"""Nightwatch - modular cybersecurity toolkit.

Modules:
- phishing: URL/email phishing detection with heuristic scoring, live
  verification and optional local threat-intel blocklists
- network: pcap/pcapng parsing (IPv4/IPv6, Ethernet/SLL/raw), flow
  tracking, stream reassembly, HTTP/DNS extraction, TLS (SNI/JA3)
  fingerprinting and C2 beacon detection
- honeypot: TCP/HTTP decoys that log (full multi-segment reads) and track
  attackers
- logs: log collection, correlation (built-in or custom rules), burst
  detection (real time-windowing) and reporting
- export: findings persistence and SIEM/webhook integration
- web: dependency-free browser dashboard over a local HTTP API, with
  optional bearer-token auth on write endpoints
"""

__version__ = "0.2.0"
