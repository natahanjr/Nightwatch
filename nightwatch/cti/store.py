"""In-memory threat-indicator store with O(1) lookups.

Every indicator from every feed is normalised into a common record shape::

    {"value": "evil.example", "type": "domain", "source": "urlhaus",
     "sources": ("urlhaus",), "confidence": 80, "tags": ["trojan"],
     "malware": "Emotet", "first_seen": 1710000000, "last_seen": 1710003600,
     "expires_at": None, "reference": "https://..."}

An indicator seen in several feeds keeps them all in ``sources``, which makes
corroboration count meaningful: three independent feeds reporting the same
host is a stronger signal than one feed reporting it once.

Indicators are bucketed by type into plain dictionaries, so membership tests
are O(1) regardless of how many indicators are loaded.

Domain matching is *label-suffix aware*: an indicator for ``evil.example``
matches ``cdn.evil.example`` but never ``notevil.example``. Resolution walks
the query host label by label (``a.b.evil.example`` -> ``b.evil.example`` ->
``evil.example``) and stops at the public suffix, so a lookup costs O(labels)
rather than O(indicators).
"""

import time
from collections import Counter
from urllib.parse import urlparse

TYPES = ("url", "domain", "ip", "hash")

# Labels we never treat as a registrable domain on their own.
_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "co.nz", "com.br", "com.cn", "com.mx",
    "co.in", "co.za", "com.tr", "com.sg", "com.hk", "com.tw",
}

# Deterministic record shape so callers can rely on every key existing.
_EMPTY = {
    "source": None,
    "sources": (),
    "confidence": 0,
    "tags": (),
    "malware": None,
    "first_seen": None,
    "last_seen": None,
    "expires_at": None,
    "reference": None,
}


def _is_ipv4(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or len(part) > 3:
            return False
        if int(part) > 255:
            return False
    return True


def is_ip(value):
    """True for a bare IPv4 or IPv6 address (no brackets, no port)."""
    v = (value or "").strip()
    if not v:
        return False
    if _is_ipv4(v):
        return True
    if ":" not in v:
        return False
    try:
        socket_pton_probe(v)
    except OSError:
        return False
    return True


def socket_pton_probe(value):
    """Validate an IPv6 literal using the stdlib resolver, offline.

    ``socket.inet_pton`` is the only trustworthy pure-stdlib IPv6 validator,
    but it is not exposed on every platform, so fall back to a structural
    check rather than importing it at module scope.
    """
    import socket as _socket
    if not hasattr(_socket, "inet_pton"):
        if not value or len(value) > 45 or value.count("::") > 1:
            raise OSError("not an IPv6 address")
        return None
    return _socket.inet_pton(_socket.AF_INET6, value)


def classify(value):
    """Infer an indicator type from its text.

    Returns one of :data:`TYPES`, or ``None`` when the value cannot be
    classified (empty, whitespace, or not a recognisable observable).
    """
    v = (value or "").strip()
    if not v or " " in v:
        return None
    low = v.lower()
    if "://" in low:
        return "url"
    if "/" in v:
        return "url"
    if _is_ipv4(low):
        return "ip"
    if ":" in v and all(c in "0123456789abcdefABCDEF:." for c in v):
        return "ip"
    if len(v) in (32, 40, 64, 128) and all(
            c in "0123456789abcdefABCDEF" for c in v):
        return "hash"
    if low.startswith("www.") or "." in low:
        return "domain"
    return None


def host_of(value, kind=None):
    """Extract the comparable host from an indicator of any type."""
    v = (value or "").strip()
    kind = kind or classify(v)
    if kind == "url":
        return (urlparse(v if "://" in v else "http://" + v).hostname
                or "").lower()
    if kind in ("domain", "ip"):
        return v.lower()
    return ""


def _domain_candidates(host):
    """Yield a host and each of its parent domains, most specific first."""
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return
    labels = host.split(".")
    if len(labels) < 2:
        if host not in _PUBLIC_SUFFIXES:
            yield host
        return
    for i in range(0, len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in _PUBLIC_SUFFIXES:
            continue
        yield candidate


def normalise(record, source=None, now=None):
    """Coerce a feed record into the canonical shape, or return None.

    ``record`` may be a bare indicator string or a mapping. ``now`` is only
    used to stamp ``last_seen`` when the record omits it.
    """
    now = time.time() if now is None else now
    if isinstance(record, str):
        record = {"value": record}
    if not isinstance(record, dict):
        return None
    value = (record.get("value") or record.get("indicator")
             or record.get("domain") or record.get("url")
             or record.get("ip") or record.get("hash") or "")
    value = str(value).strip()
    if not value:
        return None
    kind = record.get("type") or classify(value)
    if kind not in TYPES:
        return None
    out = dict(_EMPTY)
    out["value"] = value if kind in ("hash",) else value.lower()
    out["type"] = kind
    out["source"] = record.get("source") or source
    if out["source"]:
        out["sources"] = (out["source"],)
    try:
        out["confidence"] = int(record.get("confidence") or 0)
    except (TypeError, ValueError):
        out["confidence"] = 0
    tags = record.get("tags") or ()
    if isinstance(tags, str):
        tags = [tags]
    out["tags"] = tuple(sorted({str(t) for t in tags if t}))
    out["malware"] = record.get("malware") or None
    for key in ("first_seen", "last_seen", "expires_at"):
        raw = record.get(key)
        try:
            out[key] = int(raw) if raw not in (None, "") else None
        except (TypeError, ValueError):
            out[key] = None
    if out["last_seen"] is None:
        out["last_seen"] = int(now)
    out["reference"] = record.get("reference") or None
    return out


class IndicatorStore:
    """A typed, expiry-aware collection of threat indicators."""

    def __init__(self, records=None, source=None, now=None):
        self._by_type = {t: {} for t in TYPES}
        self._sources = Counter()
        self._tags = Counter()
        if records:
            self.extend(records, source=source, now=now)

    # -- population ---------------------------------------------------------

    def add(self, record, source=None, now=None):
        """Add one indicator. Returns the canonical record, or None."""
        norm = normalise(record, source=source, now=now)
        if norm is None:
            return None
        bucket = self._by_type[norm["type"]]
        existing = bucket.get(norm["value"])
        if existing is not None:
            norm = _merge(existing, norm)
        bucket[norm["value"]] = norm
        for src in norm["sources"]:
            self._sources[src] += 1
        for tag in norm["tags"]:
            self._tags[tag] += 1
        return norm

    def extend(self, records, source=None, now=None):
        """Add many indicators. Returns the number accepted."""
        added = 0
        for record in records or ():
            if self.add(record, source=source, now=now) is not None:
                added += 1
        return added

    # -- querying -----------------------------------------------------------

    def lookup(self, value, now=None, include_expired=False):
        """Return the best matching record for ``value``, or None.

        Resolution order is exact URL, IP, hash, then label-suffix domain
        walk, so a full malicious URL beats the domain it happens to sit on.
        """
        now = time.time() if now is None else now
        kind = classify(value)
        if kind is None:
            return None
        for candidate, match_type in self._candidates(value, kind):
            record = self._by_type[match_type].get(candidate)
            if record is None:
                continue
            if not include_expired and _expired(record, now):
                continue
            return self._describe(record, candidate, match_type, now)
        return None

    def _candidates(self, value, kind):
        raw = (value or "").strip()
        if kind == "url":
            yield raw.lower(), "url"
            yield raw, "url"
            host = host_of(raw, "url")
            if is_ip(host):
                yield host, "ip"
            elif host:
                for cand in _domain_candidates(host):
                    yield cand, "domain"
            return
        if kind in ("domain", "ip"):
            for cand in _domain_candidates(raw):
                yield cand, "ip" if is_ip(cand) else "domain"
            return
        yield raw.lower(), "hash"

    def _describe(self, record, matched, match_type, now):
        age = None
        if record["first_seen"] is not None:
            age = max(0, int(now - record["first_seen"]))
        result = dict(record)
        result["matched"] = matched
        result["matched_type"] = match_type
        result["age_seconds"] = age
        result["confidence_norm"] = max(0.0, min(1.0,
                                                 record["confidence"] / 100.0))
        return result

    def match_all(self, value, now=None):
        """Return every matching record, most specific first.

        Useful for correlation: a URL can be listed in three independent
        feeds, and the number of corroborating sources is itself a signal.
        """
        now = time.time() if now is None else now
        kind = classify(value)
        if kind is None:
            return []
        seen = set()
        hits = []
        for candidate, match_type in self._candidates(value, kind):
            record = self._by_type[match_type].get(candidate)
            if record is None or candidate in seen:
                continue
            if _expired(record, now):
                continue
            seen.add(candidate)
            hits.append(self._describe(record, candidate, match_type, now))
        return hits

    def corroboration(self, value, now=None):
        """Count distinct sources reporting ``value`` (0 when unknown)."""
        hits = self.match_all(value, now=now)
        return len(hits[0]["sources"]) if hits else 0

    # -- interop ------------------------------------------------------------

    def to_blocklist(self, now=None):
        """Render as a plain indicator set for :func:`check_intel`.

        This is the bridge to the existing phishing detector, which already
        accepts a set of indicators and matches domains by label suffix.
        """
        out = set()
        now = time.time() if now is None else now
        for kind, bucket in self._by_type.items():
            for value, record in bucket.items():
                if _expired(record, now):
                    continue
                out.add(value.lower())
        return out

    def domains(self, now=None):
        """Active domain and URL indicators, as a set of hosts."""
        now = time.time() if now is None else now
        out = set()
        for kind in ("domain", "url"):
            for value, record in self._by_type[kind].items():
                if _expired(record, now):
                    continue
                host = host_of(value, kind)
                if host:
                    out.add(host)
        return out

    def hashes(self, now=None):
        """Active file hashes, as a set of lower-case digests."""
        now = time.time() if now is None else now
        return {v for v, r in self._by_type["hash"].items()
                if not _expired(r, now)}

    def stats(self, now=None):
        """Counts, sources and top tags, for CLI and dashboard display."""
        now = time.time() if now is None else now
        active = {k: 0 for k in TYPES}
        expired = 0
        for bucket in self._by_type.values():
            for record in bucket.values():
                if _expired(record, now):
                    expired += 1
                else:
                    active[record["type"]] += 1
        return {
            "total": sum(active.values()),
            "expired": expired,
            "by_type": active,
            "sources": dict(self._sources),
            "top_tags": self._tags.most_common(15),
        }

    def prune(self, now=None):
        """Drop expired indicators. Returns the number removed."""
        now = time.time() if now is None else now
        removed = 0
        for kind, bucket in self._by_type.items():
            stale = [v for v, r in bucket.items() if _expired(r, now)]
            for value in stale:
                record = bucket.pop(value)
                for src in record["sources"]:
                    self._sources[src] -= 1
                    if self._sources[src] <= 0:
                        del self._sources[src]
                for tag in record["tags"]:
                    self._tags[tag] -= 1
                    if self._tags[tag] <= 0:
                        del self._tags[tag]
            removed += len(stale)
        return removed

    # -- container protocol -------------------------------------------------

    def __len__(self):
        return sum(len(b) for b in self._by_type.values())

    def __contains__(self, value):
        return self.lookup(value) is not None

    def __iter__(self):
        for bucket in self._by_type.values():
            for record in bucket.values():
                yield dict(record)

    def __repr__(self):
        return f"<IndicatorStore {len(self)} indicators>"


def _expired(record, now):
    expires = record.get("expires_at")
    return expires is not None and expires <= now


def _merge(old, new):
    """Combine two records for the same indicator, keeping the best signal."""
    out = dict(old)
    for key in ("confidence", "first_seen", "last_seen", "expires_at"):
        a, b = old.get(key), new.get(key)
        if a is None and b is not None:
            out[key] = b
        elif a is not None and b is not None:
            if key == "confidence":
                out[key] = max(a, b)
            elif key == "first_seen":
                out[key] = min(a, b)
            elif key == "last_seen":
                out[key] = max(a, b)
            else:
                out[key] = max(a, b)
    for key in ("source", "malware", "reference"):
        if not out.get(key) and new.get(key):
            out[key] = new[key]
    out["tags"] = tuple(sorted(set(old["tags"]) | set(new["tags"])))
    out["sources"] = tuple(sorted(set(old["sources"]) | set(new["sources"])))
    out["source"] = old["source"] or new["source"]
    return out


def load_store(records, source=None, now=None):
    """Convenience constructor: build a store from an iterable of records."""
    return IndicatorStore(records, source=source, now=now)
