import base64
import json
import socket
import threading
import time

from nightwatch.honeypot import HoneypotLogger, run_tcp, run_http, analyze, fingerprint


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for(fn, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(0.05)
    return False


def _read_jsonl(path):
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def test_tcp_honeypot_logs_connection(tmp_path):
    log = tmp_path / "honey.jsonl"
    port = _free_port()
    shutdown = threading.Event()
    thread = threading.Thread(target=run_tcp,
                              args=("127.0.0.1", port, HoneypotLogger(str(log)),
                                    None, 5, shutdown), daemon=True)
    thread.start()
    assert _wait_for(lambda: any(e["event"] == "server_start"
                                for e in _read_jsonl(log)))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(b"hello attacker")
    assert _wait_for(lambda: any(e["event"] == "connection"
                                for e in _read_jsonl(log)))
    shutdown.set()
    thread.join(timeout=5)

    events = _read_jsonl(log)
    conns = [e for e in events if e["event"] == "connection"]
    assert len(conns) == 1
    assert conns[0]["src_ip"] == "127.0.0.1"
    assert conns[0]["payload"] == "hello attacker"


def test_http_honeypot_logs_request_and_suspicious_path(tmp_path):
    log = tmp_path / "http.jsonl"
    port = _free_port()
    shutdown = threading.Event()
    thread = threading.Thread(target=run_http,
                              args=("127.0.0.1", port, HoneypotLogger(str(log)),
                                    None, 5, shutdown), daemon=True)
    thread.start()
    assert _wait_for(lambda: any(e["event"] == "server_start"
                                for e in _read_jsonl(log)))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(b"GET /wp-login.php HTTP/1.1\r\n"
                     b"Host: 127.0.0.1\r\nUser-Agent: evil-bot\r\n\r\n")
    assert _wait_for(lambda: any(e["event"] == "http_request"
                                for e in _read_jsonl(log)))
    shutdown.set()
    thread.join(timeout=5)

    events = _read_jsonl(log)
    reqs = [e for e in events if e["event"] == "http_request"]
    assert len(reqs) == 1
    assert reqs[0]["method"] == "GET"
    assert reqs[0]["path"] == "/wp-login.php"
    assert reqs[0]["suspicious_path"] is True
    assert reqs[0]["headers"]["User-Agent"] == "evil-bot"

    result = analyze(str(log))
    assert result["attacker_ips"] == 1
    assert result["findings"]
    assert any(f["label"] == "sensitive-path-probing"
               for f in result["findings"])
    for f in result["findings"]:
        assert set(f) == {"severity", "label", "count", "detail"}


def test_http_honeypot_captures_credentials_and_keepalive(tmp_path):
    log = tmp_path / "creds.jsonl"
    port = _free_port()
    shutdown = threading.Event()
    thread = threading.Thread(target=run_http,
                              args=("127.0.0.1", port, HoneypotLogger(str(log)),
                                    None, 5, shutdown), daemon=True)
    thread.start()
    assert _wait_for(lambda: any(e["event"] == "server_start"
                                for e in _read_jsonl(log)))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        form = "username=admin&password=s3cret!"
        conn.sendall(
            f"POST /login HTTP/1.1\r\nHost: x\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(form)}\r\nConnection: keep-alive\r\n\r\n"
            f"{form}".encode())
        # Second request on the same connection (keep-alive) with Basic auth.
        conn.sendall(b"GET /admin HTTP/1.1\r\n"
                     b"Authorization: Basic " + base64.b64encode(b"root:toor")
                     + b"\r\nConnection: close\r\n\r\n")
    assert _wait_for(lambda: len([e for e in _read_jsonl(log)
                                  if e.get("credentials")]) >= 2, timeout=5)
    shutdown.set()
    thread.join(timeout=5)

    events = _read_jsonl(log)
    reqs = [e for e in events if e["event"] == "http_request"]
    # keep-alive: both requests on one connection were logged separately
    assert len(reqs) == 2
    creds = [e["credentials"] for e in reqs if e.get("credentials")]
    assert any(c.get("username") == "admin" and c.get("password") == "s3cret!"
               for c in creds)
    assert any(c.get("username") == "root" and c.get("password") == "toor"
               for c in creds)
    # attacker events only (server_start/stop excluded)
    result = analyze(str(log))
    assert result["total_events"] == 2


def test_fingerprint_profiles_attacker(tmp_path):
    log = tmp_path / "honey.jsonl"
    events = [
        {"event": "http_request", "src_ip": "203.0.113.9", "method": "GET",
         "path": "/admin", "suspicious_path": True},
        {"event": "http_request", "src_ip": "203.0.113.9", "method": "POST",
         "path": "/login", "suspicious_path": True},
        {"event": "http_request", "src_ip": "198.51.100.7", "method": "GET",
         "path": "/", "suspicious_path": False},
    ]
    with open(log, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    prof = fingerprint(events, "203.0.113.9")
    assert prof["total_events"] == 2
    assert prof["suspicious_path_hits"] == 2

    result = analyze(str(log))
    assert result["attacker_ips"] == 2
    assert result["profiles"][0]["src_ip"] == "203.0.113.9"
