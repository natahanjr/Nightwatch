import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from nightwatch.web.server import make_server


def _request(port, method, path, body=None):
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, method=method)
    if data is not None and not isinstance(body, bytes):
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


@pytest.fixture
def web():
    server = make_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_index_page_served(web):
    req = urllib.request.Request(f"http://127.0.0.1:{web}/")
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "Nightwatch" in body
        assert "Launch console" in body


def test_static_css_served(web):
    req = urllib.request.Request(f"http://127.0.0.1:{web}/static/styles.css")
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        assert b"backdrop-filter" in resp.read()


def test_status_api(web):
    status, data = _request(web, "GET", "/api/status")
    assert status == 200
    assert data["version"]
    assert data["honeypot"]["running"] is False


def test_phish_api(web):
    status, data = _request(web, "POST", "/api/phish",
                            {"url": "https://secure-login-bank.tk"})
    assert status == 200
    assert data["verdict"] == "phishing"
    assert data["score"] >= 70


def test_phish_api_requires_url(web):
    status, data = _request(web, "POST", "/api/phish", {})
    assert status == 400
    assert "url is required" in data["error"]


def test_phish_email_api(web):
    status, data = _request(web, "POST", "/api/phish/email",
                            {"text": "Check this: https://bit.ly/abc123"})
    assert status == 200
    assert data["urls_checked"] == 1
    assert data["overall_verdict"] == "suspicious"


def test_phish_api_honors_blocklist(web, tmp_path):
    from nightwatch.web.server import set_blocklist
    bl = tmp_path / "bl.txt"
    bl.write_text("blocked-domain.com\n", encoding="utf-8")
    set_blocklist(str(bl))
    try:
        status, data = _request(web, "POST", "/api/phish",
                                {"url": "http://blocked-domain.com/x"})
        assert status == 200
        assert any(f.startswith("blocklist-match:") for f in data["flags"])
    finally:
        set_blocklist(None)


def test_upload_size_limit_enforced(web, monkeypatch):
    import nightwatch.web.server as srv
    monkeypatch.setattr(srv, "MAX_UPLOAD", 16)
    status, data = _request(web, "POST", "/api/pcap", b"x" * 64)
    assert status == 400
    assert "maximum" in data["error"].lower()


def test_pcap_api(web):
    from test_network import _build_pcap, _frame, _ipv4, _tcp
    syn = lambda port: _frame("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                              _ipv4("10.0.0.1", "10.0.0.2", 6,
                                    _tcp(40000, port, 0x02)))
    pcap_bytes = _build_pcap([(1, syn(22)), (2, syn(80)), (3, syn(443))])
    status, data = _request(web, "POST", "/api/pcap", pcap_bytes)
    assert status == 200
    assert data["packets_total"] == 3
    assert any(f["label"] == "syn-scan" for f in data["findings"])


def test_pcap_api_rejects_garbage(web):
    status, data = _request(web, "POST", "/api/pcap", b"not a pcap")
    assert status == 400


def test_logs_api(web):
    content = (
        '{"timestamp": "2026-08-03T10:00:00", "level": "ERROR", '
        '"message": "Failed password for root"}\n'
    ).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{web}/api/logs?name=app.jsonl", data=content,
        method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    assert data["analysis"]["events_total"] == 1
    labels = [f["label"] for f in data["analysis"]["findings"]]
    assert "failed-login" in labels
    assert "# Nightwatch Log Analysis Report" in data["report"]


def test_auth_required_then_accepted():
    from nightwatch.web.server import make_server, set_api_token
    set_api_token("secret")
    try:
        server = make_server(port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            bad = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/phish",
                data=json.dumps({"url": "https://a.tk"}).encode(),
                method="POST")
            bad.add_header("Content-Type", "application/json")
            try:
                urllib.request.urlopen(bad, timeout=5)
                code = 200
            except urllib.error.HTTPError as e:
                code = e.code
            assert code == 401

            good = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/phish",
                data=json.dumps({"url": "https://a.tk"}).encode(),
                method="POST")
            good.add_header("Content-Type", "application/json")
            good.add_header("Authorization", "Bearer secret")
            with urllib.request.urlopen(good, timeout=5) as resp:
                assert resp.status == 200
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    finally:
        set_api_token(None)


def test_honeypot_api_lifecycle(web):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    status, data = _request(web, "POST", "/api/honeypot/start",
                            {"mode": "http", "host": "127.0.0.1",
                             "port": port})
    assert status == 200
    assert data["running"] is True

    deadline = time.time() + 5
    events = []
    while time.time() < deadline:
        _, status_data = _request(web, "GET", "/api/honeypot/status")
        if status_data["running"]:
            break
        time.sleep(0.05)

    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")

    deadline = time.time() + 5
    while time.time() < deadline:
        _, events_data = _request(web, "GET", "/api/honeypot/events")
        events = events_data["events"]
        if any(e["event"] == "http_request" for e in events):
            break
        time.sleep(0.05)

    reqs = [e for e in events if e["event"] == "http_request"]
    assert len(reqs) == 1
    assert reqs[0]["path"] == "/admin"
    assert reqs[0]["suspicious_path"] is True

    _, analysis = _request(web, "GET", "/api/honeypot/analysis")
    assert analysis["attacker_ips"] == 1
    assert any(f["label"] == "sensitive-path-probing"
               for f in analysis["findings"])

    status, data = _request(web, "POST", "/api/honeypot/stop", {})
    assert status == 200
    assert data["running"] is False


def test_api_threat_intel(web):
    status, body = _request(web, "POST", "/api/threat_intel", {"value": "xn--e-xample.com"})
    assert status == 200
    assert body["idn"] is True
    assert body["type"] == "domain"


def test_api_sandbox(web):
    sample = b"MZ\x00\x00powershell invoke-webrequest evil.com"
    status, body = _request(web, "POST", "/api/sandbox?name=s.bin", sample)
    assert status == 200
    assert body["file_type"].startswith("PE")
    assert set(body["hashes"]) == {"md5", "sha1", "sha256"}


def test_api_posture(web):
    status, body = _request(
        web, "POST", "/api/posture?name=p.json",
        b'{"Effect":"Allow","Action":"*","Principal":"*"}')
    assert status == 200
    assert body["risk"] == "high"
    assert any("Wildcard" in f for f in body["findings"])


def test_api_crypto_text(web):
    status, body = _request(web, "POST", "/api/crypto", {"text": "weak sha1 rc4"})
    assert status == 200
    assert "sha1" in body["weak_algorithms"]


def test_api_dfir(web):
    status, body = _request(
        web, "POST", "/api/dfir?name=e.jsonl",
        b'{"timestamp":"2026-01-01T10:00:00","type":"auth"}')
    assert status == 200
    assert body["total_events"] == 1
    assert body["first_seen"] == "2026-01-01T10:00:00"
