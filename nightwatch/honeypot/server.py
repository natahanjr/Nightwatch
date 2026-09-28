"""TCP and HTTP honeypot servers that log attacker interaction to JSONL."""

import base64
import json
import socket
import threading
import time
import urllib.parse

DEFAULT_RESPONSE = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"

SUSPICIOUS_PATHS = {
    "/admin", "/wp-login.php", "/wp-admin", "/shell", "/cmd.exe", "/login",
    "/api", "/phpmyadmin", "/.env", "/wp-content", "/config.php", "/actuator",
    "/console", "/manager/html", "/solr", "/hadoop",
}


class HoneypotLogger:
    """Appends JSON lines to a log file from any thread."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def log(self, event):
        event = dict(event)
        event.setdefault("timestamp", time.time())
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")


def _decode(data):
    return data.decode("utf-8", errors="replace")


_MAX_TCP_READ = 1 << 20  # 1 MiB cap per connection


def _recv_all(conn, first, timeout):
    """Read everything the client sends until close/error, capped."""
    chunks = [first] if first else []
    total = len(first)
    conn.settimeout(1.0)
    while total < _MAX_TCP_READ:
        try:
            more = conn.recv(4096)
        except OSError:
            break
        if not more:
            break
        chunks.append(more)
        total += len(more)
    return b"".join(chunks)


def _handle_tcp_client(conn, addr, logger, respond, timeout):
    conn.settimeout(timeout)
    try:
        first = conn.recv(4096)
    except OSError:
        first = b""
    data = _recv_all(conn, first, timeout) if first else b""
    event = {
        "event": "connection",
        "src_ip": addr[0],
        "src_port": addr[1],
        "bytes_received": len(data),
    }
    if data:
        event["payload"] = _decode(data)[:500]
    logger.log(event)
    if respond:
        try:
            conn.sendall(respond.encode("utf-8"))
        except OSError:
            pass
    conn.close()


def run_tcp(host, port, logger, respond=None, timeout=10, shutdown=None):
    """Run a TCP honeypot until shutdown event is set. Blocking."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(16)
        server.settimeout(0.5)
        logger.log({"event": "server_start", "mode": "tcp", "host": host,
                    "port": port})
        while shutdown is None or not shutdown.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle_tcp_client,
                             args=(conn, addr, logger, respond, timeout),
                             daemon=True).start()
        logger.log({"event": "server_stop", "mode": "tcp"})


def run_http(host, port, logger, respond=None, timeout=10, shutdown=None):
    """Run a fake HTTP honeypot that logs method, path and headers."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(16)
        server.settimeout(0.5)
        logger.log({"event": "server_start", "mode": "http", "host": host,
                    "port": port})
        while shutdown is None or not shutdown.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle_http_client,
                             args=(conn, addr, logger, respond, timeout),
                             daemon=True).start()
        logger.log({"event": "server_stop", "mode": "http"})


_CRED_FIELDS = ("username", "user", "email", "mail", "login",
                 "password", "passwd", "pwd", "pass")


def _extract_credentials(headers, body):
    """Pull attacker-supplied credentials from a request, if any."""
    creds = {}
    auth = headers.get("Authorization", "")
    if isinstance(auth, str) and auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
            if ":" in decoded:
                creds["username"], creds["password"] = decoded.split(":", 1)
        except Exception:
            pass
    ctype = (headers.get("Content-Type") or "").lower()
    if body:
        if "application/json" in ctype:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for k in _CRED_FIELDS:
                        if k in data and data[k]:
                            creds[k] = str(data[k])
            except Exception:
                pass
        elif "application/x-www-form-urlencoded" in ctype:
            for pair in body.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                k = urllib.parse.unquote_plus(k).lower()
                v = urllib.parse.unquote_plus(v)
                if k in _CRED_FIELDS and v:
                    creds[k] = v
    norm = {}
    user = (creds.get("username") or creds.get("user") or creds.get("login")
            or creds.get("email") or creds.get("mail"))
    pw = (creds.get("password") or creds.get("passwd") or creds.get("pwd")
          or creds.get("pass"))
    if user:
        norm["username"] = user
    if pw:
        norm["password"] = pw
    return norm or None


def _parse_one_request(buf):
    """Parse a single HTTP request from ``buf``.

    Returns ``(event_fields, body, rest)`` or ``None`` if more data is needed.
    """
    header_end = buf.find(b"\r\n\r\n")
    if header_end == -1:
        return None
    header_block = buf[:header_end]
    rest = buf[header_end + 4:]
    lines = _decode(header_block).split("\r\n")
    request_line = lines[0].split(" ") if lines else []
    headers = {part.split(":", 1)[0].strip(): part.split(":", 1)[1].strip()
               for part in lines[1:] if ":" in part}
    content_length = 0
    for k, v in headers.items():
        if k.lower() == "content-length":
            try:
                content_length = int(v)
            except ValueError:
                content_length = 0
    if len(rest) < content_length:
        return None
    body = rest[:content_length]
    path = (request_line[1] if len(request_line) > 1 else None or "").split("?")[0]
    return {
        "method": request_line[0] if request_line else None,
        "path": path,
        "headers": headers,
        "suspicious_path": path in SUSPICIOUS_PATHS,
        "body": _decode(body),
        "bytes": len(header_block) + 4 + content_length,
    }, body, rest[content_length:]


def _handle_http_client(conn, addr, logger, respond, timeout):
    conn.settimeout(timeout)
    buf = b""
    keep_alive = True
    while keep_alive:
        try:
            chunk = conn.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > (1 << 20):  # safety cap per connection
            break
        while True:
            parsed = _parse_one_request(buf)
            if parsed is None:
                break
            fields, body, rest = parsed
            buf = rest
            event = {"event": "http_request", "src_ip": addr[0],
                     "src_port": addr[1]}
            event.update(fields)
            event.pop("body", None)
            if body:
                event["body_excerpt"] = _decode(body)[:500]
            creds = _extract_credentials(fields["headers"], _decode(body))
            if creds:
                event["credentials"] = creds
                event["suspicious_path"] = True
            logger.log(event)
            try:
                conn.sendall((respond or DEFAULT_RESPONSE).encode("utf-8"))
            except OSError:
                pass
            if "close" in (fields["headers"].get("Connection", "")).lower():
                keep_alive = False
                break
    conn.close()
