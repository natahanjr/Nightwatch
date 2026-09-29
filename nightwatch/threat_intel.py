"""Threat-intelligence lookups for indicators (domains, URLs, IPs).

Matches a local blocklist, flags IDN/homoglyph look-alike domains, classifies
the indicator type, and performs a *live* DNS resolution (user-initiated,
read-only) so operators see the real records behind an indicator.
"""

import socket
from urllib.parse import urlparse

from nightwatch.phishing.detector import check_intel

# Minimal confusable map (Cyrillic / Greek look-alikes of Latin letters).
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ӏ": "l", "ԛ": "q", "қ": "k",
    "η": "n", "ν": "v", "ι": "i", "ο": "o", "μ": "u", "κ": "k", "τ": "t",
    "α": "a", "β": "b", "δ": "d", "λ": "l", "ζ": "z", "ω": "w",
}


def _homoglyphs(host):
    return [(ch, CONFUSABLES[ch]) for ch in host if ch in CONFUSABLES]


def _indicator_type(value):
    v = value.strip()
    if v.startswith(("http://", "https://")) or "://" in v or "/" in v:
        return "url"
    parts = v.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ip"
    return "domain"


def _resolve(host):
    ipv4, ipv6 = [], []
    try:
        for r in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = r[4][0]
            if ip not in ipv4:
                ipv4.append(ip)
    except (socket.gaierror, OSError):
        pass
    try:
        for r in socket.getaddrinfo(host, None, socket.AF_INET6):
            ip = r[4][0]
            if ip not in ipv6:
                ipv6.append(ip)
    except (socket.gaierror, OSError):
        pass
    return ipv4, ipv6


def _reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        return None


def analyze_indicator(value, blocklist=None):
    """Return intel for a single indicator string."""
    v = (value or "").strip()
    if not v:
        raise ValueError("indicator is required")
    kind = _indicator_type(v)
    if kind == "url":
        host = (urlparse(v if "://" in v else "http://" + v).hostname or "").lower()
    elif kind == "domain":
        host = v.lower()
    else:
        host = v.lower()

    ipv4, ipv6 = ([], [])
    reverse = None
    if kind in ("domain", "url"):
        ipv4, ipv6 = _resolve(host)
    elif kind == "ip":
        reverse = _reverse(host)

    return {
        "indicator": v,
        "type": kind,
        "host": host,
        "blocklist_hit": check_intel(v, blocklist) if blocklist else None,
        "homoglyphs": _homoglyphs(host),
        "idn": ("xn--" in host) or any(ord(c) > 127 for c in host),
        "resolved": {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "resolves": bool(ipv4 or ipv6),
            "reverse_dns": reverse,
        },
    }
