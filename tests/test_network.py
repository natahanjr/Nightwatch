import socket
import struct

import pytest

from nightwatch.network import analyze_pcap
from nightwatch.network.pcap import read_pcap


def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def _ip(s):
    return socket.inet_aton(s)


def _ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto,
                       0, _ip(src), _ip(dst)) + payload


def _tcp(sport, dport, flags, seq=0, ack=0):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                       0xffff, 0, 0)


def _udp(sport, dport, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp_echo():
    return struct.pack(">BBHHH", 8, 0, 0, 1, 0) + b"abc"


def _frame(src_mac, dst_mac, payload, eth_type=0x0800):
    return _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", eth_type) + payload


def _build_pcap(packets):
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, data in packets:
        out += struct.pack("<IIII", ts, 0, len(data), len(data))
        out += data
    return bytes(out)


@pytest.fixture
def sample_pcap(tmp_path):
    syn = lambda port: _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                              _ipv4("10.0.0.1", "10.0.0.2", 6,
                                    _tcp(40000, port, 0x02)))
    udp_dns = _frame("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
                     _ipv4("10.0.0.3", "8.8.8.8", 17, _udp(5353, 53)))
    icmp = _frame("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
                  _ipv4("10.0.0.4", "10.0.0.2", 1, _icmp_echo()))
    path = tmp_path / "capture.pcap"
    path.write_bytes(_build_pcap([(1, syn(80)), (2, syn(443)), (3, syn(22)),
                                  (4, udp_dns), (5, icmp)]))
    return str(path)


def test_read_pcap_counts_packets(sample_pcap):
    packets = list(read_pcap(sample_pcap))
    assert len(packets) == 5
    tcp = [p for p in packets if p.get("ip", {}).get("transport") == "tcp"]
    assert len(tcp) == 3
    assert tcp[0]["ip"]["sport"] == 40000
    assert tcp[0]["ip"]["dport"] == 80


def test_analyze_pcap_summary(sample_pcap):
    result = analyze_pcap(sample_pcap)
    assert result["packets_total"] == 5
    assert result["packets_parsed"] == 5
    assert result["protocols"] == {"tcp": 3, "udp": 1, "icmp": 1}
    assert result["unique_connections"] == 4
    assert ("10.0.0.1", 3) in result["top_sources"]


def test_analyze_pcap_detects_syn_scan(sample_pcap):
    result = analyze_pcap(sample_pcap)
    assert any(f["label"] == "syn-scan" for f in result["findings"])


def test_flow_completion_tracking(tmp_path):
    handshake = [
        (1, _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                   _ipv4("10.0.0.1", "10.0.0.2", 6,
                         _tcp(40000, 80, 0x02)))),
        (2, _frame("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
                   _ipv4("10.0.0.2", "10.0.0.1", 6,
                         _tcp(80, 40000, 0x12)))),
        (3, _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                   _ipv4("10.0.0.1", "10.0.0.2", 6,
                         _tcp(40000, 80, 0x10)))),
    ]
    path = tmp_path / "flow.pcap"
    path.write_bytes(_build_pcap(handshake))
    result = analyze_pcap(str(path))
    assert result["unique_connections"] == 1
    assert result["completed_connections"] == 1
    assert not any(f["label"] == "syn-scan" for f in result["findings"])


def test_http_request_extraction(tmp_path):
    payload = (b"GET /login HTTP/1.1\r\nHost: bank.example.com\r\n"
               b"User-Agent: curl/8.0\r\n\r\n")
    pkt = _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                 _ipv4("10.0.0.1", "10.0.0.2", 6,
                       _tcp(50000, 80, 0x10) + payload))
    path = tmp_path / "http.pcap"
    path.write_bytes(_build_pcap([(1, pkt)]))
    result = analyze_pcap(str(path))
    assert result["http_requests"] == 1
    assert ("bank.example.com", 1) in result["http_hosts"]
    assert ("curl/8.0", 1) in result["user_agents"]


def test_dns_query_extraction(tmp_path):
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    query += b"\x06google\x03com\x00" + struct.pack(">HH", 1, 1)
    pkt = _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                 _ipv4("10.0.0.1", "8.8.8.8", 17, _udp(5353, 53, query)))
    path = tmp_path / "dns.pcap"
    path.write_bytes(_build_pcap([(1, pkt)]))
    result = analyze_pcap(str(path))
    assert ("google.com", 1) in result["dns_queries"]


def test_beacon_detection(tmp_path):
    packets = []
    for i in range(6):
        packets.append((i * 5 + 1, _frame(
            "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
            _ipv4("10.0.0.1", "203.0.113.9", 6, _tcp(40000, 443, 0x10)))))
    path = tmp_path / "beacon.pcap"
    path.write_bytes(_build_pcap(packets))
    result = analyze_pcap(str(path))
    beacons = [b for b in result["beacons"] if b["dst"] == "203.0.113.9"]
    assert beacons
    assert beacons[0]["interval"] == 5.0
    assert any(f["label"] == "possible-beacon" for f in result["findings"])


def test_findings_have_unified_shape(sample_pcap):
    result = analyze_pcap(sample_pcap)
    for f in result["findings"]:
        assert set(f) == {"severity", "label", "count", "detail"}


def test_arp_frames_are_parsed_but_not_counted_as_ip(tmp_path):
    arp = _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", b"x" * 28,
                 eth_type=0x0806)
    path = tmp_path / "arp.pcap"
    path.write_bytes(_build_pcap([(1, arp)]))
    packets = list(read_pcap(str(path)))
    assert len(packets) == 1
    assert packets[0].get("arp") is True
    result = analyze_pcap(str(path))
    assert result["packets_parsed"] == 0


def test_invalid_pcap_raises(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a pcap file at all")
    with pytest.raises(ValueError):
        list(read_pcap(str(path)))


def _build_pcapng(packets):
    shb = (b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 32) + b"\x4d\x3c\x2b\x1a"
           + struct.pack("<HH", 1, 0)
           + b"\xff\xff\xff\xff\xff\xff\xff\xff"
           + struct.pack("<HH", 0, 0) + struct.pack("<I", 32))
    idb = (b"\x01\x00\x00\x00" + struct.pack("<I", 24)
           + struct.pack("<HH", 1, 0) + struct.pack("<I", 0)
           + struct.pack("<HH", 0, 0) + struct.pack("<I", 24))
    out = shb + idb
    for ts, data in packets:
        incl = len(data)
        # Enhanced Packet Block: type(4) len(4) interface(4) ts_high(4)
        # ts_low(4) caplen(4) origlen(4) data caplen crc(4)
        blen = 32 + incl
        epb = (b"\x06\x00\x00\x00" + struct.pack("<I", blen)
               + struct.pack("<I", 0) + struct.pack("<I", 0)
               + struct.pack("<I", 0) + struct.pack("<I", incl)
               + struct.pack("<I", incl) + data + struct.pack("<I", blen))
        out += epb
    return bytes(out)


def test_pcapng_read_and_http(tmp_path):
    payload = b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    pkt = _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                 _ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(5000, 80, 0x18) + payload))
    path = tmp_path / "c.pcapng"
    path.write_bytes(_build_pcapng([(1, pkt)]))
    packets = list(read_pcap(str(path)))
    assert len(packets) == 1
    assert packets[0]["ip"]["transport"] == "tcp"
    result = analyze_pcap(str(path))
    assert result["http_requests"] == 1
    assert ("x", 1) in result["http_hosts"]


def test_ipv6_tcp_parsed():
    from nightwatch.network.pcap import _parse_ipv6
    v6 = (b"\x6a\x00\x00\x00\x00\x14\x06\x40"
          + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
          + socket.inet_pton(socket.AF_INET6, "2001:db8::2")
          + struct.pack(">HHIIBBHHH", 5000, 443, 0, 0, 0x50, 0x18, 0xffff, 0, 0)
          + b"GET / HTTP/1.1\r\n\r\n")
    info = _parse_ipv6(v6)
    assert info["transport"] == "tcp"
    assert info["dport"] == 443
    assert info["ipv6"] is True


def _build_client_hello(sni):
    snl = (struct.pack(">H", len(sni.encode()) + 3) + b"\x00"
           + struct.pack(">H", len(sni.encode())) + sni.encode())
    extr = snl
    cipher = struct.pack(">H", 0x1301)
    exts = struct.pack(">HH", 0, len(extr)) + extr
    body = (struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
            + struct.pack(">H", 2) + cipher + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hello = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16" + struct.pack(">H", 0x0301) + struct.pack(">H", len(hello)) + hello


def test_tls_sni_and_ja3():
    from nightwatch.network.analyzer import _parse_tls_client_hello
    hello = _build_client_hello("secure-login-paypal.example.com")
    parsed = _parse_tls_client_hello(hello)
    assert parsed["sni"] == "secure-login-paypal.example.com"
    assert len(parsed["ja3"]) == 32


def test_reassemble_joins_segments():
    from nightwatch.network.analyzer import _reassemble
    buf = _reassemble([(100, b"GET /a"), (106, b" HTTP/1.1\r\n\r\n")])
    assert b"GET /a HTTP/1.1" in buf


def test_dns_name_compression():
    from nightwatch.network.analyzer import _decode_dns_name
    base = b"\x07example\x03com\x00"
    buf = base + b"\x00" * (20 - len(base)) + b"\xc0\x00"  # pointer to 0
    name, end = _decode_dns_name(buf, 20)
    assert name == "example.com"
    assert end == 22


