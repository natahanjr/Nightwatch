"""Cryptography & key-management checks.

Two safe, offline-friendly modes:
  * ``check_cert(host, port)`` — fetch a live TLS certificate (read-only) and
    surface subject/issuer/expiry so operators can catch expired or weak certs.
  * ``analyze_crypto(text)`` — scan a config/policy blob for weak algorithms.
"""

import re
import socket
import ssl
import time

WEAK_ALGS = ["md5", "sha1", "sha-1", "des", "3des", "rc4", "rc2", "md4"]

_OID_MAP = {
    "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress",
}


def _read_tlv(data, i):
    tag = data[i]
    i += 1
    l = data[i]
    i += 1
    if l & 0x80:
        nbytes = l & 0x7F
        l = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    return tag, i, i + l


def _children(value):
    out = []
    i = 0
    n = len(value)
    while i < n:
        tag, cs, ce = _read_tlv(value, i)
        out.append((tag, value[cs:ce]))
        i = ce
    return out


def _oid_to_str(raw):
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _name_to_dict(name_der):
    out = {}
    for _, rdn in _children(name_der):
        for _, atv in _children(rdn):
            sub = _children(atv)
            if len(sub) >= 2 and sub[0][0] == 0x06:
                oid = _oid_to_str(sub[0][1])
                key = _OID_MAP.get(oid)
                if key:
                    out[key] = sub[1][1].decode("utf-8", "replace")
    return out


def _parse_cert_der(der):
    top = _children(der)
    tbs = _children(top[0][1])
    serial = None
    issuer = None
    subject = None
    not_before = not_after = None
    for tag, val in tbs:
        if tag == 0x02 and serial is None:
            serial = "0x" + val.hex()
    for idx, (tag, val) in enumerate(tbs):
        if tag != 0x30:
            continue
        kids = _children(val)
        if kids and kids[0][0] == 0x31:  # SET -> a Name (RDNSequence)
            if issuer is None:
                issuer = _name_to_dict(val)
            elif subject is None:
                subject = _name_to_dict(val)
        elif kids and kids[0][0] in (0x17, 0x18):  # Validity (two times)
            times = [k[1].decode("ascii", "replace").rstrip("Z") for k in kids
                     if k[0] in (0x17, 0x18)]
            if len(times) == 2:
                not_before, not_after = times
    return {
        "subject": subject or {},
        "issuer": issuer or {},
        "serialNumber": serial or "",
        "notBefore": not_before,
        "notAfter": not_after,
    }


def _check_cert_untrusted(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("no certificate presented")
    parsed = _parse_cert_der(der)
    expires_in_days = expired = expiring_soon = None
    if parsed["notAfter"]:
        try:
            ts = ssl.cert_time_to_seconds(parsed["notAfter"] + "Z")
            expires_in_days = (ts - time.time()) / 86400.0
            expired = expires_in_days < 0
            expiring_soon = 0 <= expires_in_days <= 30
        except (ValueError, OverflowError):
            pass
    parsed.update({
        "host": host, "port": port, "verified": False,
        "expires_in_days": round(expires_in_days, 1) if expires_in_days is not None else None,
        "expired": expired, "expiring_soon": expiring_soon,
    })
    return parsed


def check_cert(host, port=443):
    host = (host or "").strip()
    if not host:
        raise ValueError("host is required")
    ctx = ssl.create_default_context()
    # Keep chain verification ON (so getpeercert() returns the real cert and we
    # can report trust status), but allow hostname mismatch so callers can check
    # a cert by IP address or alternate SNI.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError:
        # Untrusted / self-signed / expired-chain cert: still surface the real
        # certificate fields via a stdlib-only DER parse.
        return _check_cert_untrusted(host, port)

    subject = {}
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            subject.setdefault(k, v)
    issuer = {}
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            issuer.setdefault(k, v)

    not_after = cert.get("notAfter")
    expires_in_days = None
    expired = None
    expiring_soon = None
    if not_after:
        try:
            import time
            ts = ssl.cert_time_to_seconds(not_after)
            expires_in_days = (ts - time.time()) / 86400.0
            expired = expires_in_days < 0
            expiring_soon = 0 <= expires_in_days <= 30
        except (ValueError, OverflowError):
            pass

    return {
        "host": host,
        "port": port,
        "verified": True,
        "subject": subject,
        "issuer": issuer,
        "notBefore": cert.get("notBefore"),
        "notAfter": not_after,
        "serialNumber": str(cert.get("serialNumber", "")),
        "expires_in_days": round(expires_in_days, 1) if expires_in_days is not None else None,
        "expired": expired,
        "expiring_soon": expiring_soon,
    }


def analyze_crypto(text=""):
    text = text or ""
    found = sorted({a for a in WEAK_ALGS if re.search(r"\b" + re.escape(a) + r"\b", text, re.I)})
    return {"weak_algorithms": found, "risk": "high" if found else "low"}


def analyze_crypto_input(host=None, text=None):
    if host:
        return check_cert(host)
    if text:
        return analyze_crypto(text)
    raise ValueError("provide 'host' or 'text'")
