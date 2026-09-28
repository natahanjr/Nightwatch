"""Threat-intelligence feed definitions and response parsers.

Every feed is described by a :class:`Feed` record: where to get it, how to
ask for it, how to read it, and how often it is worth re-reading. Adding a
provider is a data change, not a code change.

The bundled registry covers four provider families, each with a different
wire format, so the parsers are exercised for real rather than in theory:

``abuse.ch``
    URLhaus, ThreatFox and MalwareBazaar are JSON APIs. ThreatFox answers on
    POST, so :meth:`Feed.encode_body` exists for it.
``Feodo Tracker``
    A plain-CSV blocklist of botnet C2 endpoints, which is the easiest
    possible format and the most useful for beacon correlation.
``Generic``
    Any ``{"indicators": [...]}`` JSON, newline-delimited text, or RSS/Atom
    document, so an organisation can point Nightwatch at its own MISP export
    or internal TI list without writing a parser.
``STIX 2.x``
    A TAXII-style JSON bundle. Only the indicator-pattern objects are read,
    which covers the ``[domain-name:value = '...']`` and
    ``[file:hashes.'SHA-256' = '...']`` forms used by most public feeds.

All parsing is tolerant: a single malformed entry is skipped rather than
aborting the whole feed, because a partial threat feed is far more useful
than no threat feed.
"""

import csv
import io
import json
import re
import time
import xml.etree.ElementTree as ET

from .store import classify, normalise

# STIX indicator patterns we understand, most specific first.
_STIX_PATTERNS = (
    re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]", re.I),
    re.compile(r"\[url:value\s*=\s*'([^']+)'\]", re.I),
    re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", re.I),
    re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", re.I),
    re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]", re.I),
    re.compile(r"\[file:hashes\.(?:MD5|SHA-1|SHA-256)\s*=\s*'([^']+)'\]",
               re.I),
)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v]
    return []


def _tags_from(record):
    tags = _as_list(record.get("tags"))
    for key in ("malware", "malware_printable", "threat_type", "type",
                "categories", "confidence"):
        value = record.get(key)
        if isinstance(value, str) and value:
            tags.append(value)
    return tags


def _epoch(value):
    """Best-effort conversion of a feed timestamp to a unix epoch int."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(time.mktime(time.strptime(text[:len(fmt) + 2], fmt)))
        except ValueError:
            continue
    return None


# -- parser functions ------------------------------------------------------
# Each takes raw bytes (or a decoded str) and returns a list of records in
# the canonical shape accepted by IndicatorStore.add.


def parse_urlhaus(raw):
    """abuse.ch URLhaus: ``{"url_status": [...]}`` plus optional host list."""
    data = _load_json(raw)
    records = []
    for entry in data.get("url_status", []) or []:
        url = entry.get("url")
        if not url:
            continue
        records.append({
            "value": url,
            "type": "url",
            "source": "urlhaus",
            "confidence": 100,
            "tags": _tags_from(entry),
            "malware": entry.get("threat"),
            "first_seen": _epoch(entry.get("date_added")),
            "last_seen": _epoch(entry.get("last_online")),
            "reference": entry.get("urlhaus_link") or url,
        })
    return records


def parse_threatfox(raw):
    """abuse.ch ThreatFox: ``{"data": [IOC, ...]}`` on a POST request."""
    data = _load_json(raw)
    records = []
    for entry in data.get("data", []) or []:
        value = entry.get("ioc")
        kind = classify(entry.get("ioc") or "")
        if not value or kind is None:
            continue
        confidence = entry.get("confidence")
        records.append({
            "value": value,
            "type": kind,
            "source": "threatfox",
            "confidence": _pct(confidence),
            "tags": _tags_from(entry),
            "malware": entry.get("malware_printable") or entry.get("malware"),
            "first_seen": _epoch(entry.get("first_seen")),
            "last_seen": _epoch(entry.get("last_seen")),
            "reference": entry.get("reference"),
        })
    return records


def parse_malwarebazaar(raw):
    """abuse.ch MalwareBazaar: recent SHA-256 hashes of uploaded samples."""
    data = _load_json(raw)
    records = []
    for entry in data.get("data", []) or []:
        if isinstance(entry, str):
            entry = {"sha256_hash": entry}
        digest = entry.get("sha256_hash") or entry.get("hash")
        if not digest:
            continue
        records.append({
            "value": digest,
            "type": "hash",
            "source": "malwarebazaar",
            "confidence": 100,
            "tags": _tags_from(entry),
            "malware": entry.get("signature"),
            "first_seen": _epoch(entry.get("file_date") or
                                 entry.get("timestamp")),
            "reference": f"https://bazaar.abuse.ch/sample/{digest}/",
        })
    return records


def parse_feodo(raw):
    """Feodo Tracker blocklist: CSV of C2 endpoints.

    Columns are ``first_seen, host, port, malware, source_ip, source_port,
    status``; older files omit the leading timestamp. Malformed rows are
    skipped, and rows marked as offline are still kept but marked expired so
    they stop generating alerts without being silently dropped.
    """
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    records = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].strip().lower().startswith("#"):
            continue
        if len(row) < 2:
            continue
        host = row[1].strip()
        if classify(host) is None:
            continue
        kind = classify(host)
        records.append({
            "value": host,
            "type": kind,
            "source": "feodo",
            "confidence": 100,
            "tags": ["c2", "botnet"],
            "malware": row[3].strip() if len(row) > 3 else None,
            "first_seen": _epoch(row[0]),
            "expires_at": _feodo_expiry(row),
            "reference": "https://feodotracker.abuse.ch/",
        })
    return records


def parse_generic_json(raw):
    """A JSON list, or ``{"indicators": [...]}``, of strings or objects."""
    data = _load_json(raw)
    if isinstance(data, dict):
        data = data.get("indicators") or data.get("values") or \
            data.get("data") or []
    if not isinstance(data, list):
        return []
    records = []
    for item in data:
        if isinstance(item, str):
            records.append({"value": item})
        elif isinstance(item, dict):
            records.append(item)
    return [r for r in (normalise(r) for r in records) if r]


def parse_plaintext(raw):
    """One indicator per line, ``#`` for comments (MISP export, ad-hoc)."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    records = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        records.append({"value": line})
    return [r for r in (normalise(r) for r in records) if r]


def parse_rss(raw):
    """RSS 2.0 or Atom. Each item's title/description becomes an indicator."""
    root = ET.fromstring(raw)
    if root.tag.rsplit("}", 1)[-1] == "rss":
        items = root.iter("item")
    else:
        items = root.iter("{http://www.w3.org/2005/Atom}entry")
    records = []
    for item in items:
        parts = []
        for el in item:
            name = el.tag.rsplit("}", 1)[-1]
            if name in ("title", "description", "summary", "content"):
                parts.append(el.text or "")
            elif name == "link":
                parts.append(el.get("href") or el.text or "")
        text = " ".join(p for p in parts if p)
        for value in re.findall(r"https?://[^\s<>\"']+", text) or [
                text.strip()]:
            if classify(value):
                records.append({"value": value, "source": "rss",
                                "confidence": 60})
    return records


def parse_stix(raw):
    """A STIX 2.x bundle: pull Indicator objects out of ``objects``."""
    data = _load_json(raw)
    objects = data.get("objects")
    if objects is None and isinstance(data.get("bundle"), dict):
        objects = data["bundle"].get("objects")
    records = []
    for obj in objects or []:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "indicator" and "pattern" not in obj:
            continue
        pattern = obj.get("pattern") or ""
        labels = _as_list(obj.get("labels")) + _as_list(obj.get(
            "indicator_types"))
        for regex in _STIX_PATTERNS:
            for match in regex.finditer(pattern):
                value = match.group(1).strip()
                if not value:
                    continue
                record = {"value": value, "source": "stix",
                          "tags": labels, "confidence": _pct(
                              obj.get("confidence"))}
                if classify(value):
                    records.append(record)
                break
    return records


def _feodo_expiry(row):
    """Feodo flags offline entries in the last column; expire them now."""
    if len(row) >= 7 and row[6].strip().lower() in ("offline", "0", "false"):
        return int(time.time())
    return None


def _pct(value):
    """Feeds express confidence as 0-100 or 0-1; normalise to 0-100."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number <= 0:
        return 0
    return int(min(100.0, number * 100 if number <= 1.0 else number))


def _load_json(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return json.loads(raw)


class Feed:
    """One threat-intelligence source.

    ``parser`` is any callable in this module, ``ttl`` overrides the cache
    default for this feed, and ``method``/``encode_body``/``headers`` cover
    providers that need a POST or an auth header.
    """

    def __init__(self, name, url, parser, kind="json", ttl=3600,
                 method="GET", accept=None, headers=None, body=None,
                 enabled=True, description=""):
        self.name = name
        self.url = url
        self.parser = parser
        self.kind = kind
        self.ttl = ttl
        self.method = method
        self.accept = accept or ("application/json" if kind == "json"
                                 else "*/*")
        self.headers = headers or {}
        self.body = body
        self.enabled = enabled
        self.description = description

    def encode_body(self):
        if self.body is None:
            return None
        if isinstance(self.body, bytes):
            return self.body
        return json.dumps(self.body).encode("utf-8")

    def parse(self, raw):
        return self.parser(raw)

    def as_dict(self):
        return {
            "name": self.name,
            "url": self.url,
            "kind": self.kind,
            "ttl": self.ttl,
            "method": self.method,
            "enabled": self.enabled,
            "description": self.description,
        }

    def __repr__(self):
        return f"<Feed {self.name} {self.url}>"


# -- the bundled registry --------------------------------------------------

FEEDS = {}


def _register(feed):
    FEEDS[feed.name] = feed
    return feed


_register(Feed(
    "urlhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    parse_urlhaus, ttl=1800,
    description="abuse.ch URLhaus: recently reported malicious URLs"))

_register(Feed(
    "urlhaus-host", "https://urlhaus.abuse.ch/hosts/hosts.txt",
    parse_plaintext, kind="text", ttl=3600,
    description="abuse.ch URLhaus: hosts serving malicious payloads"))

_register(Feed(
    "threatfox", "https://threatfox-api.abuse.ch/api/v1/",
    parse_threatfox, method="POST", body={"query": "get_iocs",
                                          "days": 1},
    ttl=3600,
    description="abuse.ch ThreatFox: recent IOCs with malware attribution"))

_register(Feed(
    "malwarebazaar", "https://mb-api.abuse.ch/api/v1/",
    parse_malwarebazaar, method="POST", body={"query": "get_recent"},
    ttl=3600,
    description="abuse.ch MalwareBazaar: SHA-256 of recent malware samples"))

_register(Feed(
    "feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    parse_feodo, kind="text", ttl=3600,
    description="abuse.ch Feodo Tracker: active botnet C2 endpoints"))

_register(Feed(
    "tor-exit", "https://check.torproject.org/torbulkexitlist",
    parse_plaintext, kind="text", ttl=86400,
    description="Tor bulk exit list: anonymising relays"))

_register(Feed(
    "stix", "https://raw.githubusercontent.com/"
            "abusech/ThreatFox/master/stix/enterprise-attack.json",
    parse_stix, ttl=86400,
    description="STIX 2.x bundle: indicator objects with confidence scores"))


def get_feed(name):
    """Look up a feed by name, raising ValueError with the valid options."""
    if name not in FEEDS:
        raise ValueError(f"unknown feed '{name}'; available: "
                         f"{', '.join(sorted(FEEDS))}")
    return FEEDS[name]


def enabled_feeds(names=None):
    """Resolve names to :class:`Feed` objects, defaulting to all enabled."""
    if not names:
        return [f for f in FEEDS.values() if f.enabled]
    return [get_feed(n) for n in names]


def custom_feed(name, url, kind="json", ttl=3600, description=""):
    """Build an ad-hoc feed for a URL the user supplies.

    The format is inferred from ``kind`` so a user can point Nightwatch at
    their own TI endpoint without understanding the parser internals.
    """
    parsers = {
        "json": parse_generic_json,
        "text": parse_plaintext,
        "rss": parse_rss,
        "stix": parse_stix,
        "urlhaus": parse_urlhaus,
        "feodo": parse_feodo,
    }
    if kind not in parsers:
        raise ValueError(f"unknown feed kind '{kind}'; available: "
                         f"{', '.join(sorted(parsers))}")
    return Feed(name, url, parsers[kind], kind=kind, ttl=ttl,
                description=description or f"custom {kind} feed")


def feed_catalog():
    """All known feeds with a short description, for CLI help and the UI."""
    return [f.as_dict() for f in sorted(FEEDS.values(), key=lambda f: f.name)]
