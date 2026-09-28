"""Attacker tracking: load honeypot logs and profile repeat offenders."""

import json
from collections import Counter, defaultdict


def load_logs(path):
    """Load JSONL honeypot logs into a list of events."""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def fingerprint(events, ip):
    """Summarize everything a single source IP did."""
    mine = [e for e in events if e.get("src_ip") == ip]
    if not mine:
        return None
    paths = Counter(e.get("path") for e in mine if e.get("path"))
    methods = Counter(e.get("method") for e in mine if e.get("method"))
    suspicious = sum(1 for e in mine if e.get("suspicious_path"))
    return {
        "src_ip": ip,
        "total_events": len(mine),
        "paths_attempted": dict(paths),
        "methods": dict(methods),
        "suspicious_path_hits": suspicious,
    }


def analyze(path):
    """Summarize attacker activity in a honeypot log file."""
    events = load_logs(path)
    attacks = [e for e in events
               if e.get("event") in ("connection", "http_request")]
    by_ip = defaultdict(list)
    for e in attacks:
        by_ip[e.get("src_ip")].append(e)

    profiles = []
    findings = []
    for ip, entries in by_ip.items():
        prof = fingerprint(events, ip)
        if prof:
            profiles.append(prof)
            if prof["suspicious_path_hits"] >= 1:
                findings.append({
                    "severity": "HIGH",
                    "label": "sensitive-path-probing",
                    "count": prof["suspicious_path_hits"],
                    "detail": f"{ip} probed sensitive paths: "
                              f"{', '.join(prof['paths_attempted'])}",
                })
        if len(entries) >= 5:
            findings.append({
                "severity": "MEDIUM",
                "label": "brute-force-pattern",
                "count": len(entries),
                "detail": f"{ip} sent {len(entries)} requests",
            })

    profiles.sort(key=lambda p: p["total_events"], reverse=True)
    return {
        "total_events": len(attacks),
        "attacker_ips": len(by_ip),
        "profiles": profiles,
        "findings": findings,
    }
