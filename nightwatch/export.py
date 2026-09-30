"""Findings persistence and outbound integrations (SIEM / webhook / file).

Dependency-free: writes findings to a JSONL file and/or forwards them to an
HTTP endpoint (Splunk HEC, Elastic, Slack, a generic collector, ...). All
network calls are best-effort and time-bounded so they never block the CLI.
"""

import json
import time
import urllib.error
import urllib.request


def write_jsonl(path, rows):
    """Append one or more finding rows to a JSONL file."""
    if not isinstance(rows, list):
        rows = [rows]
    with open(path, "a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return len(rows)


def persist_findings(path, source, findings):
    """Append findings to a JSONL audit log with a source tag and timestamp."""
    rows = []
    for f in findings:
        row = dict(f)
        row["_source"] = source
        row["_ts"] = time.time()
        rows.append(row)
    return write_jsonl(path, rows)


def forward_webhook(url, payload, token=None, timeout=5):
    """POST ``payload`` (JSON) to ``url``. Returns a status dict.

    Never raises - failures are reported in the returned dict so callers can
    decide whether to fall back to local persistence.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": str(e)}
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e.reason)}


def dispatch(findings, source="nightwatch", jsonl_path=None, webhook_url=None,
             webhook_token=None):
    """Persist findings locally and/or forward them to a webhook.

    Returns a summary dict describing what happened.
    """
    result = {"findings": len(findings), "persisted": False, "forwarded": None}
    if jsonl_path:
        persist_findings(jsonl_path, source, findings)
        result["persisted"] = True
    if webhook_url:
        result["forwarded"] = forward_webhook(
            webhook_url,
            {"source": source, "findings": findings},
            token=webhook_token,
        )
    return result
