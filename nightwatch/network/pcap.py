"""Minimal libpcap / pcapng file reader with Ethernet/IPv4/IPv6 parsing.

No external dependencies - parses the pcap container format (classic and
pcapng), the most common link layers (Ethernet, Linux cooked capture / SLL,
raw IP, BSD loopback) and the network layers (IPv4 and IPv6, including
extension headers) by hand.
"""

import socket
import struct

# Link-layer types we understand.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101          # raw IP (v4 or v6, decided by version nibble)
LINKTYPE_LINUX_SLL = 113    # Linux "cooked" capture v1

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD

IP_TCP = 6
IP_UDP = 17
IP_ICMP = 1
IP_ICMPV6 = 58

TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_RST = 0x04
TCP_FIN = 0x01

PROTO_NAMES = {IP_TCP: "tcp", IP_UDP: "udp", IP_ICMP: "icmp",
               IP_ICMPV6: "icmpv6"}

# IPv6 extension headers that carry no transport payload themselves.
_IPV6_EXT = (0, 43, 44, 51, 60, 135)


def _parse_ipv4(payload):
    if len(payload) < 20:
        return None
    ihl = (payload[0] & 0x0F) * 4
    proto = payload[9]
    src = socket.inet_ntop(socket.AF_INET, payload[12:16])
    dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
    info = {"protocol": proto, "proto_name": PROTO_NAMES.get(proto, "other"),
            "src": src, "dst": dst, "ipv4": True}
    if proto == IP_TCP and len(payload) >= ihl + 20:
        sport, dport = struct.unpack(">HH", payload[ihl:ihl + 4])
        seq = struct.unpack(">I", payload[ihl + 4:ihl + 8])[0]
        flags = payload[ihl + 13] & 0x3F
        info["transport"] = "tcp"
        info["sport"] = sport
        info["dport"] = dport
        info["seq"] = seq
        info["flags"] = flags
        info["payload"] = payload[ihl + 20:]
    elif proto == IP_UDP and len(payload) >= ihl + 8:
        sport, dport = struct.unpack(">HH", payload[ihl:ihl + 4])
        info["transport"] = "udp"
        info["sport"] = sport
        info["dport"] = dport
        info["payload"] = payload[ihl + 8:]
    elif proto == IP_ICMP and len(payload) >= ihl + 1:
        info["transport"] = "icmp"
        info["icmp_type"] = payload[ihl]
    return info


def _parse_ipv6(payload):
    if len(payload) < 40:
        return None
    if (payload[0] >> 4) != 6:
        return None
    next_header = payload[6]
    src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    off = 40
    # Skip extension headers until we reach a transport protocol.
    while next_header in _IPV6_EXT:
        if len(payload) < off + 2:
            return None
        if next_header == 44:  # fragment header has fixed 8-byte size
            next_header = payload[off]
            off += 8
        else:
            hdr_len = (payload[off + 1] + 1) * 8
            next_header = payload[off]
            off += hdr_len
    info = {"protocol": next_header,
            "proto_name": PROTO_NAMES.get(next_header, "other"),
            "src": src, "dst": dst, "ipv4": False, "ipv6": True}
    if next_header == IP_TCP and len(payload) >= off + 20:
        sport, dport = struct.unpack(">HH", payload[off:off + 4])
        seq = struct.unpack(">I", payload[off + 4:off + 8])[0]
        flags = payload[off + 13] & 0x3F
        info["transport"] = "tcp"
        info["sport"] = sport
        info["dport"] = dport
        info["seq"] = seq
        info["flags"] = flags
        info["payload"] = payload[off + 20:]
    elif next_header == IP_UDP and len(payload) >= off + 8:
        sport, dport = struct.unpack(">HH", payload[off:off + 4])
        info["transport"] = "udp"
        info["sport"] = sport
        info["dport"] = dport
        info["payload"] = payload[off + 8:]
    elif next_header == IP_ICMPV6 and len(payload) >= off + 1:
        info["transport"] = "icmpv6"
        info["icmp_type"] = payload[off]
    return info


def _parse_ethernet(frame, ts):
    if len(frame) < 14:
        return {"time": ts, "eth_type": None}
    dst_mac = ":".join(f"{b:02x}" for b in frame[0:6])
    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    if frame[12:14] == b"\x81\x00":
        eth_type = struct.unpack(">H", frame[16:18])[0]
        payload = frame[18:]
    else:
        eth_type = struct.unpack(">H", frame[12:14])[0]
        payload = frame[14:]

    packet = {"time": ts, "eth_type": eth_type, "src_mac": src_mac,
              "dst_mac": dst_mac}
    if eth_type == ETH_IPV4:
        packet["ip"] = _parse_ipv4(payload)
    elif eth_type == ETH_ARP:
        packet["arp"] = True
    elif eth_type == ETH_IPV6:
        packet["ip"] = _parse_ipv6(payload)
    return packet


def _parse_linux_sll(frame, ts):
    """Linux cooked capture v1 (LINKTYPE_LINUX_SLL)."""
    if len(frame) < 16:
        return {"time": ts, "linktype": LINKTYPE_LINUX_SLL}
    proto = struct.unpack(">H", frame[14:16])[0]
    payload = frame[16:]
    packet = {"time": ts, "linktype": LINKTYPE_LINUX_SLL}
    if proto == ETH_IPV4:
        packet["ip"] = _parse_ipv4(payload)
    elif proto == ETH_IPV6:
        packet["ip"] = _parse_ipv6(payload)
    return packet


def _parse_raw_ip(frame, ts):
    """Raw IP (LINKTYPE_RAW) or BSD loopback (LINKTYPE_NULL)."""
    if not frame:
        return {"time": ts}
    packet = {"time": ts}
    ver = frame[0] >> 4
    if ver == 4:
        packet["ip"] = _parse_ipv4(frame)
    elif ver == 6:
        packet["ip"] = _parse_ipv6(frame)
    return packet


def _parse_null(frame, ts):
    """BSD loopback: 4-byte family header, then IP."""
    if len(frame) < 4:
        return {"time": ts, "linktype": LINKTYPE_NULL}
    family = struct.unpack(">I", frame[:4])[0]
    if family in (0x02000000, 2):
        return _parse_raw_ip(frame[4:], ts)
    family_le = struct.unpack("<I", frame[:4])[0]
    if family_le in (0x02000000, 2):
        return _parse_raw_ip(frame[4:], ts)
    return {"time": ts, "linktype": LINKTYPE_NULL}


def _parse_packet(frame, ts, linktype):
    if linktype == LINKTYPE_ETHERNET:
        return _parse_ethernet(frame, ts)
    if linktype == LINKTYPE_LINUX_SLL:
        return _parse_linux_sll(frame, ts)
    if linktype == LINKTYPE_RAW:
        return _parse_raw_ip(frame, ts)
    if linktype == LINKTYPE_NULL:
        return _parse_null(frame, ts)
    return {"time": ts, "linktype": linktype, "unsupported": True}


# --------------------------------------------------------------------------
# Classic pcap
# --------------------------------------------------------------------------

def _read_classic_pcap(f, magic, header):
    endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    _, _, _, _, _, linktype = struct.unpack(endian + "HHIIII", header[4:])
    while True:
        rec = f.read(16)
        if not rec:
            break
        ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", rec)
        data = f.read(incl_len)
        if len(data) < incl_len:
            break
        yield _parse_packet(data, ts_sec + ts_usec / 1_000_000, linktype)


# --------------------------------------------------------------------------
# pcapng
# --------------------------------------------------------------------------

def _read_pcapng(data):
    if len(data) < 8:
        raise ValueError("File too small to be a pcapng capture")
    if data[0:4] != b"\n\r\r\n":
        raise ValueError("Not a pcapng file (bad magic)")
    if data[8:12] == b"\x1a\x2b\x3c\x4d":
        en = ">"    # big-endian section
    elif data[8:12] == b"\x4d\x3c\x2b\x1a":
        en = "<"    # little-endian section
    else:
        raise ValueError("Bad pcapng byte-order magic")
    if len(data) < 28:
        return
    # Parse the Section Header Block to learn the default interface.
    shb_len = struct.unpack(en + "I", data[4:8])[0]
    pos = shb_len
    linktypes = {}            # interface id -> linktype
    resolutions = {}          # interface id -> timestamp divisor
    cur_en = en
    while pos + 8 <= len(data):
        btype = struct.unpack(cur_en + "I", data[pos:pos + 4])[0]
        blen = struct.unpack(cur_en + "I", data[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 0x0A0D0D0A:  # another Section Header Block
            if body[4:8] == b"\x1a\x2b\x3c\x4d":
                cur_en = "<"
            elif body[4:8] == b"\x4d\x3c\x2b\x1a":
                cur_en = ">"
            pos += blen
            continue
        if btype == 0x00000001:  # Interface Description Block
            iface_id = len(linktypes)
            linktype = struct.unpack(cur_en + "H", body[0:2])[0]
            linktypes[iface_id] = linktype
            resolutions[iface_id] = _parse_tsresol(cur_en, body)
        elif btype in (0x00000006, 0x00000002):  # Enhanced / Packet Block
            iface = struct.unpack(cur_en + "I", body[0:4])[0]
            ts_high = struct.unpack(cur_en + "I", body[4:8])[0]
            ts_low = struct.unpack(cur_en + "I", body[8:12])[0]
            incl_len = struct.unpack(cur_en + "I", body[12:16])[0]
            # The Original Packet Length field (4 bytes) sits between the
            # captured length and the packet data; skip it so the payload is
            # aligned correctly (real Wireshark/tshark captures include it).
            pkt = body[20:20 + incl_len]
            ts_raw = (ts_high << 32) | ts_low
            ts = ts_raw * resolutions.get(iface, 1e-6)
            yield _parse_packet(pkt, ts, linktypes.get(iface,
                                                        LINKTYPE_ETHERNET))
        elif btype == 0x00000003:  # Simple Packet Block
            incl_len = struct.unpack(cur_en + "I", body[4:8])[0]
            pkt = body[8:8 + incl_len]
            yield _parse_packet(pkt, 0.0, linktypes.get(0,
                                                        LINKTYPE_ETHERNET))
        pos += blen


def _parse_tsresol(en, body):
    """Read the timestamp resolution option of an IDB (default 1e-6 seconds)."""
    if len(body) < 20:
        return 1e-6
    # Skip linktype(2), reserved(2), snaplen(4) -> options start at 8
    opt = body[8:]
    i = 0
    while i + 4 <= len(opt):
        code = struct.unpack(en + "H", opt[i:i + 2])[0]
        length = struct.unpack(en + "H", opt[i + 2:i + 4])[0]
        val = opt[i + 4:i + 4 + length]
        if code == 9 and val:
            base = val[0]
            if base & 0x80:
                return 1.0 / (2 ** (base & 0x7F))
            return 1.0 / base
        i += 4 + length + (length % 2)
        if code == 0:  # opt_endofopt
            break
    return 1e-6


def read_pcap(path):
    """Yield parsed packets from a pcap or pcapng file, one dict at a time."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("File too small to be a pcap capture")
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            yield from _read_classic_pcap(f, magic, header)
        elif magic == b"\n\r\r\n":
            data = header + f.read()
            yield from _read_pcapng(data)
        else:
            raise ValueError("Not a pcap or pcapng file (bad magic)")
