"""Nightwatch web dashboard - a dependency-free HTTP server and static UI."""

import hmac
import json
import os
import socket
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from nightwatch import __version__
from nightwatch.honeypot import HoneypotLogger, run_tcp, run_http
from nightwatch.honeypot import analyze as analyze_honeypot
from nightwatch.logs import collect, generate_markdown_report
from nightwatch.network import analyze_pcap
from nightwatch.phishing import check_url, check_email, verify_url, load_blocklist
from nightwatch import threat_intel as ti
from nightwatch import dfir as dfir_mod
from nightwatch import sandbox as sandbox_mod
from nightwatch import osint as osint_mod
from nightwatch import posture as posture_mod
from nightwatch import crypto_audit as crypto_mod

STATIC_DIR = Path(__file__).parent / "static"
TEXT_EXTENSIONS = {".json", ".jsonl", ".csv", ".log", ".txt"}

# Hard cap on request bodies (uploads) to prevent memory-exhaustion DoS.
MAX_UPLOAD = 200 * 1024 * 1024

# Optional API token. When set, all state-changing (POST) requests must carry
# an `Authorization: Bearer <token>` header. Configure via the NIGHTWATCH_API_TOKEN
# environment variable or `set_api_token` (e.g. from the CLI).
_api_token = os.environ.get("NIGHTWATCH_API_TOKEN") or os.environ.get(
    "NIGHTWATCH_TOKEN")


def set_api_token(token):
    """Enable token authentication for the dashboard API."""
    global _api_token
    _api_token = token or None


# Optional local threat-intel blocklist (mirrors the CLI ``--blocklist``).
_blocklist = None


def set_blocklist(path):
    """Load a blocklist that the dashboard's phishing checks will use."""
    global _blocklist
    _blocklist = load_blocklist(path) if path else None


_started_at = time.time()

_active = {
    "thread": None, "shutdown": None, "logger": None, "log_path": None,
    "mode": None, "host": None, "port": None, "started_at": None,
}


def _port_free(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
        return True
    except OSError:
        return False


def honeypot_status():
    running = _active["thread"] is not None and _active["thread"].is_alive()
    return {
        "running": running,
        "mode": _active["mode"] if running else None,
        "host": _active["host"] if running else None,
        "port": _active["port"] if running else None,
        "log_path": _active["log_path"] if running else None,
        "started_at": _active["started_at"] if running else None,
    }


def honeypot_start(mode, host, port, respond=None):
    if _active["thread"] and _active["thread"].is_alive():
        raise RuntimeError("Honeypot is already running")
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    if not _port_free(host, port):
        raise RuntimeError(f"Port {port} is already in use")
    _active["mode"] = "http" if mode == "http" else "tcp"
    _active["host"] = host
    _active["port"] = port
    _active["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _active["log_path"] = str(
        Path(tempfile.gettempdir()) / f"nightwatch_{_active['mode']}_{port}.jsonl")
    _active["logger"] = HoneypotLogger(_active["log_path"])
    _active["shutdown"] = threading.Event()
    target = run_http if _active["mode"] == "http" else run_tcp
    _active["thread"] = threading.Thread(
        target=target,
        args=(host, port, _active["logger"], respond, 10, _active["shutdown"]),
        daemon=True)
    _active["thread"].start()
    return honeypot_status()


def honeypot_stop():
    if _active["shutdown"]:
        _active["shutdown"].set()
    if _active["thread"]:
        _active["thread"].join(timeout=5)
    return honeypot_status()


def honeypot_clear():
    if _active["log_path"] and os.path.exists(_active["log_path"]):
        os.remove(_active["log_path"])
    return {"cleared": True}


def _read_honeypot_events():
    path = _active.get("log_path")
    if not path or not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def _empty_honeypot_analysis():
    return {"total_events": 0, "attacker_ips": 0, "profiles": [],
            "findings": []}


class NightwatchHandler(BaseHTTPRequestHandler):
    server_version = "Nightwatch/" + __version__
    quiet = True

    def log_message(self, format, *args):
        if not self.quiet:
            super().log_message(format, *args)

    def _send(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, "application/json", json.dumps(obj).encode("utf-8"))

    def _json_error(self, status, message):
        self._json(status, {"error": message})

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            raise ValueError("Upload exceeds the maximum allowed size")
        return self.rfile.read(length) if length else b""

    def _json_body(self):
        raw = self._read_body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError("Invalid JSON body")

    def _serve_static(self, rel):
        target = (STATIC_DIR / rel).resolve()
        root = STATIC_DIR.resolve()
        if not str(target).startswith(str(root)) or not target.is_file():
            self._send(404, "text/plain", b"not found")
            return
        if target.suffix == ".html":
            ctype = "text/html"
        elif target.suffix == ".js":
            ctype = "text/javascript"
        elif target.suffix == ".css":
            ctype = "text/css"
        else:
            ctype = "application/octet-stream"
        self._send(200, ctype, target.read_bytes())

    def do_GET(self):
        try:
            self._route_get()
        except Exception as e:
            import sys as _sys
            print(f"[nightwatch] GET {self.path} failed: {e}", file=_sys.stderr)
            self._json_error(500, "Internal server error")

    def _route_get(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            return self._serve_static("index.html")
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])
        if path == "/api/status":
            return self._json(200, {
                "version": __version__,
                "uptime_seconds": round(time.time() - _started_at),
                "auth_required": bool(_api_token),
                "honeypot": honeypot_status(),
            })
        if path == "/api/honeypot/status":
            return self._json(200, honeypot_status())
        if path == "/api/honeypot/events":
            return self._json(200, {
                "events": _read_honeypot_events()[-200:],
                "running": honeypot_status()["running"],
            })
        if path == "/api/honeypot/analysis":
            if not _active.get("log_path") or not os.path.exists(
                    _active["log_path"]):
                return self._json(200, _empty_honeypot_analysis())
            return self._json(200, analyze_honeypot(_active["log_path"]))
        self._json_error(404, f"Unknown path: {path}")

    def _authorized(self):
        provided = self.headers.get("Authorization", "").strip()
        expected = f"Bearer {_api_token}"
        return hmac.compare_digest(provided, expected)

    def do_POST(self):
        if _api_token and not self._authorized():
            self._json_error(401, "Unauthorized: missing/invalid API token")
            return
        try:
            self._route_post()
        except ValueError as e:
            self._json_error(400, str(e))
        except Exception as e:
            import sys as _sys
            print(f"[nightwatch] POST {self.path} failed: {e}", file=_sys.stderr)
            self._json_error(500, "Internal server error")

    def _route_post(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/phish":
            try:
                body = self._json_body()
                url = body.get("url")
                if not url:
                    raise ValueError("url is required")
                result = check_url(url, blocklist=_blocklist)
                if body.get("verify"):
                    result["verification"] = verify_url(url, total_timeout=15)
                return self._json(200, result)
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/phish/email":
            try:
                body = self._json_body()
                text = body.get("text")
                if not text:
                    raise ValueError("text is required")
                return self._json(200, check_email(text, blocklist=_blocklist))
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/pcap":
            raw = self._read_body()
            if not raw:
                return self._json_error(400, "Upload a .pcap file")
            fd, tmp = tempfile.mkstemp(suffix=".pcap")
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(raw)
            try:
                return self._json(200, analyze_pcap(tmp))
            except ValueError as e:
                return self._json_error(400, str(e))
            finally:
                os.remove(tmp)
        if path == "/api/logs":
            raw = self._read_body()
            if not raw:
                return self._json_error(400, "Upload a log file")
            name = parse_qs(parsed.query).get("name", ["upload.log"])[0]
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                ext = ".log"
            fd, tmp = tempfile.mkstemp(suffix=ext)
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(raw)
            try:
                events = collect(tmp)
                report_path = tmp + ".md"
                result = generate_markdown_report(report_path, events)
                with open(report_path, "r", encoding="utf-8-sig") as f:
                    report = f.read()
                return self._json(200, {"analysis": result, "report": report})
            except ValueError as e:
                return self._json_error(400, str(e))
            finally:
                os.remove(tmp)
                if os.path.exists(tmp + ".md"):
                    os.remove(tmp + ".md")
        if path == "/api/honeypot/start":
            try:
                body = self._json_body()
                mode = body.get("mode", "http")
                host = body.get("host", "0.0.0.0")
                port = int(body.get("port", 8080))
                respond = body.get("respond")
                return self._json(200, honeypot_start(mode, host, port,
                                                      respond))
            except (ValueError, RuntimeError, TypeError) as e:
                return self._json_error(400, str(e))
        if path == "/api/honeypot/stop":
            return self._json(200, honeypot_stop())
        if path == "/api/honeypot/clear":
            return self._json(200, honeypot_clear())
        if path == "/api/threat_intel":
            try:
                body = self._json_body()
                value = body.get("value")
                if not value:
                    raise ValueError("value is required")
                return self._json(200, ti.analyze_indicator(value, blocklist=_blocklist))
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/dfir":
            raw = self._read_body()
            if not raw:
                return self._json_error(400, "Upload a log file")
            try:
                return self._json(200, dfir_mod.analyze_logs(raw.decode("utf-8", "replace")))
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/sandbox":
            raw = self._read_body()
            if not raw:
                return self._json_error(400, "Upload a sample")
            name = parse_qs(parsed.query).get("name", ["sample.bin"])[0]
            try:
                return self._json(200, sandbox_mod.analyze_sample(raw, filename=name))
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/osint":
            try:
                body = self._json_body()
                domain = body.get("domain")
                if not domain:
                    raise ValueError("domain is required")
                return self._json(200, osint_mod.recon_domain(domain))
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/posture":
            raw = self._read_body()
            if not raw:
                return self._json_error(400, "Upload a policy/config file")
            name = parse_qs(parsed.query).get("name", ["policy.json"])[0]
            try:
                return self._json(200, posture_mod.analyze_posture(
                    raw.decode("utf-8", "replace"), filename=name))
            except ValueError as e:
                return self._json_error(400, str(e))
        if path == "/api/crypto":
            try:
                body = self._json_body()
                host = body.get("host")
                text = body.get("text")
                return self._json(200, crypto_mod.analyze_crypto_input(host=host, text=text))
            except ValueError as e:
                return self._json_error(400, str(e))
        self._json_error(404, f"Unknown path: {path}")


def make_server(host="127.0.0.1", port=0, quiet=True):
    NightwatchHandler.quiet = quiet
    return ThreadingHTTPServer((host, port), NightwatchHandler)


def run_web(host="127.0.0.1", port=8000, open_browser=True):
    try:
        server = make_server(host, port)
    except OSError as e:
        print(f"error: could not start web UI on {host}:{port} ({e})")
        print(f"hint: another process is probably using port {port}; "
              f"try --port 8001")
        return
    url = f"http://{host}:{port}"
    print(f"Nightwatch web UI running at {url} (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
