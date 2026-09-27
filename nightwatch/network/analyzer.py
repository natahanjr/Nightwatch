"""Traffic analysis: flow tracking, HTTP/DNS extraction, TLS fingerprinting
and suspicious behavior detection over parsed packets.
"""

import hashlib
import re
import struct
from collections import Counter, defaultdict

from .pcap import (read_pcap, TCP_SYN, TCP_ACK, IP_ICMP, LINKTYPE_ETHERNET,
                   LINKTYPE_LINUX_SLL, LINKTYPE_RAW, LINKTYPE_NULL)

try:
    from nightwatch.phishing.detector import BRANDS, KEYWORDS
    BRAND_HINTS = BRANDS | KEYWORDS
except Exception:  # pragma: no cover - phishing is always present
    BRAND_HINTS = set()

SUSPICIOUS_PORTS = {23, 445, 1433, 3306, 6379, 27017, 3389, 5555, 1337, 5900}
HTTP_PORTS = {80, 8080, 8000, 8888}
DNS_PORT = 53

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")

# Suspicious TLDs reused from the phishing detector for SNI scoring.
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link",
    ".zip", ".mov", ".country", ".icu", ".monster",
}


def _flow_key(ip):
    a = (ip["src"], ip["sport"])
    b = (ip["dst"], ip["dport"])
    if a <= b:
        return (a[0], a[1], b[0], b[1])
    return (b[0], b[1], a[0], a[1])


def _parse_http(payload):
    for method in HTTP_METHODS:
        if payload.startswith(method):
            line = payload.split(b"\r\n", 1)[0].decode("ascii",
                                                        errors="replace")
            parts = line.split(" ")
            host = None
            user_agent = None
            low = payload.lower()
            for marker, attr in ((b"host: ", "host"),
                                 (b"user-agent: ", "user_agent")):
                idx = low.find(marker)
                if idx != -1:
                    end = payload.find(b"\r\n", idx)
                    if end == -1:
                        end = len(payload)
                    value = payload[idx + len(marker):end].decode(
                        "ascii", errors="replace").strip()
                    if attr == "host":
                        host = value
                    else:
                        user_agent = value
            return {"kind": "request", "method": parts[0],
                    "path": parts[1] if len(parts) > 1 else None,
                    "host": host, "user_agent": user_agent}
    if payload.startswith(b"HTTP/"):
        line = payload.split(b"\r\n", 1)[0].decode("ascii",
                                                   errors="replace")
        parts = line.split(" ", 2)
        return {"kind": "response", "version": parts[0],
                "status": parts[1] if len(parts) > 1 else None}
    return None


def _iter_http_messages(buf, kind):
    if kind == "request":
        pat = re.compile(rb"([A-Z]+) (\S+) HTTP/\d\.\d")
    else:
        pat = re.compile(rb"HTTP/\d\.\d (\d{3})")
    for m in pat.finditer(buf):
        start = m.start()
        end = buf.find(b"\r\n\r\n", start)
        block = buf[start:end if end != -1 else start + len(m.group(0))]
        parsed = _parse_http(block)
        if parsed:
            yield parsed


def _decode_dns_name(payload, i):
    """Decode a DNS name, following compression pointers (0xC0)."""
    labels = []
    end = None
    jumped = False
    while i < len(payload):
        ln = payload[i]
        if ln & 0xC0 == 0xC0:  # compression pointer
            if i + 1 >= len(payload):
                return None, None
            ptr = ((ln & 0x3F) << 8) | payload[i + 1]
            if end is None:
                end = i + 2
            i = ptr
            jumped = True
            continue
        if ln == 0:
            if end is None:
                end = i + 1
            break
        if i + 1 + ln > len(payload):
            return None, None
        labels.append(payload[i + 1:i + 1 + ln].decode("ascii", errors="replace"))
        i += 1 + ln
    name = ".".join(labels)
    if jumped:
        return name, end
    return name, (end if end else i)


def _parse_dns(payload):
    if len(payload) < 12:
        return None
    qdcount = struct.unpack(">H", payload[4:6])[0]
    if qdcount == 0:
        return None
    name, _ = _decode_dns_name(payload, 12)
    return name


# GREASE values are reserved for future use and must be ignored by JA3.
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def _parse_tls_client_hello(buf):
    """Extract SNI and a standard JA3 fingerprint from a TLS ClientHello."""
    i = 0
    while i + 5 <= len(buf):
        if buf[i] != 0x16:  # not a TLS handshake record
            break
        version = struct.unpack(">H", buf[i + 1:i + 3])[0]
        if not (0x0300 <= version <= 0x0303):
            break
        rec_len = struct.unpack(">H", buf[i + 3:i + 5])[0]
        body = buf[i + 5:i + 5 + rec_len]
        if not body or body[0] != 0x01:  # not a ClientHello
            break
        off = 4
        if len(body) < off + 2 + 32 + 1:
            break
        ch_version = struct.unpack(">H", body[off:off + 2])[0]  # handshake ver
        off += 2 + 32           # skip client version + random
        sid_len = body[off]
        off += 1 + sid_len
        if len(body) < off + 2:
            break
        cs_len = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        ciphers = []
        j = off
        while j + 2 <= off + cs_len and j + 2 <= len(body):
            c = struct.unpack(">H", body[j:j + 2])[0]
            if c not in _GREASE:
                ciphers.append(c)
            j += 2
        off += cs_len
        if len(body) < off + 1:
            break
        comp_len = body[off]
        off += 1 + comp_len
        if len(body) < off + 2:
            break
        ext_total = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
        ext_types = []
        curves = []
        point_formats = []
        ext_end = off + ext_total
        sni = None
        while off + 4 <= ext_end and off + 4 <= len(body):
            etype = struct.unpack(">H", body[off:off + 2])[0]
            elen = struct.unpack(">H", body[off + 2:off + 4])[0]
            edata = body[off + 4:off + 4 + elen]
            if etype not in _GREASE:
                ext_types.append(etype)
            if etype == 0x0000:  # SNI
                if len(edata) >= 3:
                    sn_len = struct.unpack(">H", edata[0:2])[0]
                    sn_off = 2
                    while sn_off + 3 <= len(edata) and sn_off + 3 <= 2 + sn_len:
                        ntype = edata[sn_off]
                        nlen = struct.unpack(">H", edata[sn_off + 1:sn_off + 3])[0]
                        if ntype == 0:
                            sni = edata[sn_off + 3:sn_off + 3 + nlen].decode(
                                "ascii", errors="replace")
                        sn_off += 3 + nlen
            elif etype == 0x000a and len(edata) >= 2:  # supported_groups
                n = struct.unpack(">H", edata[0:2])[0]
                k = 2
                while k + 2 <= 2 + n and k + 2 <= len(edata):
                    g = struct.unpack(">H", edata[k:k + 2])[0]
                    if g not in _GREASE:
                        curves.append(g)
                    k += 2
            elif etype == 0x000b and len(edata) >= 1:  # ec_point_formats
                nfmt = edata[0]
                for k in range(nfmt):
                    if 1 + k < len(edata):
                        point_formats.append(edata[1 + k])
            off += 4 + elen
        ja3_str = ",".join(map(str, [
            ch_version,
            ",".join(map(str, ciphers)),
            ",".join(map(str, ext_types)),
            ",".join(map(str, curves)),
            ",".join(map(str, point_formats)),
        ]))
        ja3 = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
        return {"sni": sni, "ja3": ja3}
    return None


def _reassemble(segments):
    """Reorder TCP segments by sequence number into a contiguous stream."""
    if not segments:
        return b""
    base = min(seq for seq, _ in segments)
    stream = {}
    for seq, data in segments:
        for k, b in enumerate(data):
            stream[seq - base + k] = b
    if not stream:
        return b""
    return bytes(stream.get(i, 0) for i in range(max(stream) + 1))


def _detect_beacons(times_by_peer, srcs_by_peer):
    beacons = []
    for (dst, dport), times in times_by_peer.items():
        times = sorted(times)
        if len(times) < 5:
            continue
        intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(intervals) < 4:
            continue
        intervals.sort()
        median = intervals[len(intervals) // 2]
        if median <= 0:
            continue
        variance = sum(abs(i - median) for i in intervals) / len(intervals)
        if variance / median < 0.3:
            srcs = srcs_by_peer[(dst, dport)]
            beacons.append({
                "src": srcs.most_common(1)[0][0], "dst": dst, "port": dport,
                "count": len(times), "interval": round(median, 3),
                "regularity": round(1.0 - variance / median, 4),
                "jitter": round(variance, 3)})
    return beacons


def analyze_pcap(path):
    """Analyze a pcap/pcapng file and return summary stats and findings."""
    packets = list(read_pcap(path))

    proto_counts = Counter()
    src_counter = Counter()
    dst_counter = Counter()
    dst_ports = Counter()
    flows = {}
    syn_counts = defaultdict(Counter)
    icmp_echo_src = defaultdict(set)
    suspicious_ports_hit = set()
    http_requests = []
    http_responses = []
    http_hosts = Counter()
    user_agents = Counter()
    dns_queries = Counter()
    beacon_times = defaultdict(list)
    beacon_srcs = defaultdict(Counter)
    reasm = defaultdict(lambda: {"f": [], "r": []})
    tls_sni = Counter()
    tls_ja3 = Counter()

    for p in packets:
        ip = p.get("ip")
        if not ip:
            continue
        proto_counts[ip["proto_name"]] += 1
        src_counter[ip["src"]] += 1
        dst_counter[ip["dst"]] += 1

        if ip.get("transport") in ("tcp", "udp"):
            key = _flow_key(ip)
            flow = flows.setdefault(key, {
                "transport": ip["transport"], "packets": 0, "bytes": 0,
                "start": p["time"], "end": p["time"],
                "syn_seen": False, "synack_seen": False,
                "ack_seen": False, "completed": False,
                "ports": (ip["sport"], ip["dport"]),
            })
            flow["packets"] += 1
            payload = ip.get("payload") or b""
            flow["bytes"] += len(payload)
            flow["start"] = min(flow["start"], p["time"])
            flow["end"] = max(flow["end"], p["time"])
            dst_ports[ip["dport"]] += 1
            if ip["dport"] in SUSPICIOUS_PORTS:
                suspicious_ports_hit.add(ip["dport"])

            if ip["transport"] == "tcp":
                beacon_times[(ip["dst"], ip["dport"])].append(p["time"])
                beacon_srcs[(ip["dst"], ip["dport"])][ip["src"]] += 1
                flags = ip["flags"]
                if flags & TCP_SYN and not flags & TCP_ACK:
                    flow["syn_seen"] = True
                elif flags & TCP_SYN and flags & TCP_ACK:
                    flow["synack_seen"] = True
                elif flags & TCP_ACK and not flags & TCP_SYN:
                    flow["ack_seen"] = True
                if flow["syn_seen"] and flow["synack_seen"] and flow[
                        "ack_seen"]:
                    flow["completed"] = True
                if flags & TCP_SYN and not flags & TCP_ACK:
                    syn_counts[ip["src"]][ip["dport"]] += 1
                if payload:
                    if (ip["src"], ip["sport"]) == (key[0], key[1]):
                        reasm[key]["f"].append((ip.get("seq", 0), payload))
                    else:
                        reasm[key]["r"].append((ip.get("seq", 0), payload))
            elif ip["transport"] == "udp" and ip["dport"] == DNS_PORT:
                domain = _parse_dns(payload)
                if domain:
                    dns_queries[domain] += 1

        if ip.get("icmp_type") == 8:
            icmp_echo_src[ip["src"]].add(ip["dst"])

    # Analyze reassembled TCP streams (handles segmented HTTP/TLS).
    for key, bufs in reasm.items():
        fwd = _reassemble(bufs["f"])
        rev = _reassemble(bufs["r"])
        for msg in _iter_http_messages(fwd, "request"):
            http_requests.append(msg)
            if msg.get("host"):
                http_hosts[msg["host"]] += 1
            if msg.get("user_agent"):
                user_agents[msg["user_agent"]] += 1
        for msg in _iter_http_messages(rev, "response"):
            http_responses.append(msg)
        tls = _parse_tls_client_hello(fwd)
        if tls:
            if tls.get("sni"):
                tls_sni[tls["sni"]] += 1
            tls_ja3[tls["ja3"]] += 1

    findings = []
    for src, ports in syn_counts.items():
        unique_ports = len(ports)
        if unique_ports >= 3:
            findings.append({
                "severity": "HIGH",
                "label": "syn-scan",
                "count": unique_ports,
                "detail": f"{src} probed {unique_ports} ports "
                          f"({', '.join(map(str, ports))})",
            })
    for src, dsts in icmp_echo_src.items():
        if len(dsts) >= 5:
            findings.append({
                "severity": "MEDIUM",
                "label": "icmp-sweep",
                "count": len(dsts),
                "detail": f"{src} probed {len(dsts)} destinations",
            })
    if suspicious_ports_hit:
        findings.append({
            "severity": "MEDIUM",
            "label": "sensitive-port-traffic",
            "count": len(suspicious_ports_hit),
            "detail": ", ".join(str(p) for p in sorted(suspicious_ports_hit)),
        })
    beacons = _detect_beacons(beacon_times, beacon_srcs)
    for beacon in beacons:
        findings.append({
            "severity": "HIGH",
            "label": "possible-beacon",
            "count": beacon["count"],
            "detail": (f"{beacon['src']} -> {beacon['dst']}:{beacon['port']} "
                       f"at ~{beacon['interval']}s intervals"),
        })
    for sni, count in tls_sni.items():
        low = sni.lower()
        if any(sni.endswith(t) for t in SUSPICIOUS_TLDS):
            findings.append({
                "severity": "HIGH",
                "label": "tls-suspicious-sni",
                "count": count,
                "detail": f"SNI {sni} uses a high-risk TLD",
            })
        elif any(b in low for b in BRAND_HINTS):
            findings.append({
                "severity": "MEDIUM",
                "label": "tls-brand-sni",
                "count": count,
                "detail": f"TLS SNI references a known brand: {sni}",
            })

    completed = sum(1 for f in flows.values() if f["completed"])
    return {
        "packets_total": len(packets),
        "packets_parsed": sum(proto_counts.values()),
        "protocols": dict(proto_counts),
        "top_sources": src_counter.most_common(10),
        "top_destinations": dst_counter.most_common(10),
        "top_destination_ports": dst_ports.most_common(10),
        "unique_connections": len(flows),
        "completed_connections": completed,
        "suspicious_ports": sorted(suspicious_ports_hit),
        "http_requests": len(http_requests),
        "http_responses": len(http_responses),
        "http_hosts": http_hosts.most_common(10),
        "user_agents": user_agents.most_common(10),
        "dns_queries": dns_queries.most_common(10),
        "tls_sni": tls_sni.most_common(10),
        "tls_ja3": tls_ja3.most_common(10),
        "beacons": beacons,
        "findings": findings,
    }
