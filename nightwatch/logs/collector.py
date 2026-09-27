"""Collect and normalize log events from JSON, CSV, syslog and plain files."""

import csv
import json
import os
import re

TS_KEY_CANDIDATES = ("timestamp", "ts", "time", "datetime", "date")
LEVEL_KEY_CANDIDATES = ("level", "severity", "loglevel", "priority")
MSG_KEY_CANDIDATES = ("message", "msg", "event", "detail")
SRC_KEY_CANDIDATES = ("source", "host", "hostname", "logger", "process")

SYSLOG_RE = re.compile(
    r"^<\d+>\s*(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>\S+?)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?")


def _normalize(raw, default_source):
    event = {"source": default_source}
    for key, value in raw.items():
        low = key.lower()
        if low in TS_KEY_CANDIDATES and "timestamp" not in event:
            event["timestamp"] = value
        elif low in LEVEL_KEY_CANDIDATES and "level" not in event:
            event["level"] = str(value)
        elif low in MSG_KEY_CANDIDATES and "message" not in event:
            event["message"] = str(value)
        elif low in SRC_KEY_CANDIDATES and event["source"] == default_source:
            event["source"] = str(value)
        else:
            event.setdefault("extra", {})[key] = value
    return event


def parse_json_log(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = [data]
    return [_normalize(d, os.path.basename(path)) for d in data]


def parse_jsonl_log(path):
    events = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(_normalize(json.loads(line),
                                         os.path.basename(path)))
    return events


def parse_csv_log(path):
    events = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(_normalize(row, os.path.basename(path)))
    return events


def _parse_line(line, source):
    m = SYSLOG_RE.match(line)
    if m:
        return {
            "timestamp": m.group("ts"),
            "source": m.group("host") or source,
            "level": None,
            "message": f"{m.group('tag')}: {m.group('msg')}",
        }
    m = ISO_TS_RE.match(line)
    if m:
        ts = m.group(0)
        rest = line[m.end():].strip(" -:")
        return {"timestamp": ts, "source": source, "level": None,
                "message": rest}
    return {"timestamp": None, "source": source, "level": None,
            "message": line.strip()}


def parse_text_log(path):
    events = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(_parse_line(line, os.path.basename(path)))
    return events


def collect(path):
    """Parse a file or every supported file in a directory."""
    if os.path.isdir(path):
        events = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                events.extend(collect(full))
        return events
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return parse_json_log(path)
    if ext == ".jsonl":
        return parse_jsonl_log(path)
    if ext == ".csv":
        return parse_csv_log(path)
    return parse_text_log(path)
