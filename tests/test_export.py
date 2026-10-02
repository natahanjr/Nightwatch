import json
import threading

import pytest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from nightwatch.export import (write_jsonl, persist_findings, dispatch,
                               forward_webhook)


def test_write_and_persist_jsonl(tmp_path):
    path = tmp_path / "findings.jsonl"
    n = write_jsonl(str(path), [{"severity": "HIGH", "label": "x",
                                "count": 1, "detail": "d"}])
    assert n == 1
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    assert rows[0]["label"] == "x"

    out = persist_findings(str(path), "pcap",
                           [{"severity": "LOW", "label": "y", "count": 2,
                             "detail": "d2"}])
    assert out == 1
    last = json.loads(path.read_text().splitlines()[-1])
    assert last["_source"] == "pcap"
    assert last["label"] == "y"


def test_dispatch_webhook(tmp_path):
    received = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            received["body"] = json.loads(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/hook"
        summary = dispatch([{"severity": "HIGH", "label": "z", "count": 1,
                             "detail": "d"}], source="logs",
                           jsonl_path=str(tmp_path / "f.jsonl"),
                           webhook_url=url, webhook_token="tok")
        assert summary["persisted"] is True
        assert summary["forwarded"]["ok"] is True
        assert received["body"]["source"] == "logs"
        assert received["body"]["findings"][0]["label"] == "z"
    finally:
        server.shutdown()
        thread.join(timeout=5)
