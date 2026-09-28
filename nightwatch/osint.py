"""OSINT / surface reconnaissance of an external domain.

Passive DNS + a light active check of common ports and the TLS certificate on
443. All network use is user-initiated and read-only; nothing is modified.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

from nightwatch.crypto_audit import check_cert

COMMON_PORTS = [21, 22, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
PORT_TIMEOUT = 0.6


def _host_only(domain):
    domain = (domain or "").strip().lower()
    domain = domain.split("://")[-1].split("/")[0]
    return domain


def _scan_port(domain, port):
    try:
        with socket.create_connection((domain, port), timeout=PORT_TIMEOUT):
            return port
    except OSError:
        return None


def _scan_ports(domain):
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as ex:
        return [p for p in ex.map(lambda pt: _scan_port(domain, pt), COMMON_PORTS)
                if p is not None]


def _reverse(ip):
    if not ip:
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        return None


def _safe_cert(domain):
    try:
        return check_cert(domain)
    except Exception as e:  # pragma: no cover - network dependent
        return {"error": str(e)}


def recon_domain(domain):
    domain = _host_only(domain)
    if not domain:
        raise ValueError("domain is required")

    info = {"domain": domain, "ipv4": [], "ipv6": [], "reverse_dns": None,
            "ports": [], "cert": None}

    for af, key in ((socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")):
        try:
            for r in socket.getaddrinfo(domain, None, af):
                ip = r[4][0]
                if ip not in info[key]:
                    info[key].append(ip)
        except (socket.gaierror, OSError):
            pass

    # Port scan, reverse DNS, and the TLS cert fetch all run concurrently so the
    # whole recon finishes in roughly the slowest single check (~a few seconds).
    with ThreadPoolExecutor(max_workers=3) as ex:
        ports_f = ex.submit(_scan_ports, domain)
        rev_f = ex.submit(_reverse, info["ipv4"][0] if info["ipv4"] else None)
        cert_f = ex.submit(_safe_cert, domain)
        info["ports"] = ports_f.result()
        info["cert"] = cert_f.result()
        try:
            info["reverse_dns"] = rev_f.result(timeout=2)
        except Exception:
            info["reverse_dns"] = None

    return info
