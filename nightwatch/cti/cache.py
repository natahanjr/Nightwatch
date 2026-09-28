"""On-disk cache for threat-intel feeds.

Each feed is stored as two files inside a cache directory::

    <name>.json       parsed indicator records
    <name>.meta.json  validators and timestamps for the next fetch

Keeping the cache on disk (rather than only in memory) is what makes a
refresh cheap and a repeated run offline-capable. Every write goes to a
temporary file in the same directory and is then moved into place with
:func:`os.replace`, so a crash or a full disk can never leave a half-written
indicator set behind for the next run to read.

Feeds are re-fetched with ``If-None-Match`` / ``If-Modified-Since`` when the
server supports them, which turns a scheduled refresh into a single 304 with
no body transfer.
"""

import json
import os
import tempfile
import time
import urllib.error
import urllib.request

USER_AGENT = "Nightwatch/cti (+https://localhost)"
DEFAULT_TIMEOUT = 15


class FetchResult:
    """Outcome of one feed fetch: data plus cache metadata."""

    def __init__(self, name, records, status, fetched_at, from_cache=False,
                 error=None, not_modified=False, headers=None):
        self.name = name
        self.records = records
        self.status = status
        self.fetched_at = fetched_at
        self.from_cache = from_cache
        self.error = error
        self.not_modified = not_modified
        self.headers = headers or {}

    @property
    def ok(self):
        return self.error is None

    @property
    def count(self):
        return len(self.records)

    def as_dict(self):
        return {
            "feed": self.name,
            "ok": self.ok,
            "status": self.status,
            "records": self.count,
            "fetched_at": self.fetched_at,
            "from_cache": self.from_cache,
            "not_modified": self.not_modified,
            "error": self.error,
        }


def _read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def _atomic_write(path, payload):
    """Write ``payload`` (str) to ``path`` without ever exposing a partial file."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class FeedCache:
    """Persistent, TTL-aware, conditional-request-aware feed cache."""

    def __init__(self, directory, ttl=3600, timeout=DEFAULT_TIMEOUT,
                 offline=False):
        self.directory = os.path.abspath(os.path.expanduser(directory))
        self.ttl = ttl
        self.timeout = timeout
        self.offline = offline
        os.makedirs(self.directory, exist_ok=True)

    # -- paths --------------------------------------------------------------

    def data_path(self, name):
        return os.path.join(self.directory, _safe(name) + ".json")

    def meta_path(self, name):
        return os.path.join(self.directory, _safe(name) + ".meta.json")

    # -- state --------------------------------------------------------------

    def meta(self, name):
        """Cached validators for ``name``, or an empty dict."""
        return _read_json(self.meta_path(name), {}) or {}

    def is_fresh(self, name, ttl=None):
        """True when the cached copy is younger than the TTL.

        A zero or negative TTL disables freshness, forcing every caller to
        revalidate against the feed.
        """
        ttl = self.ttl if ttl is None else ttl
        if ttl <= 0:
            return False
        fetched = self.meta(name).get("fetched_at")
        if not fetched:
            return False
        return (time.time() - fetched) < ttl

    def age(self, name):
        """Seconds since ``name`` was last fetched, or None if never."""
        fetched = self.meta(name).get("fetched_at")
        return None if not fetched else time.time() - fetched

    def cached_records(self, name):
        """Parsed indicator records for ``name`` (possibly empty)."""
        data = _read_json(self.data_path(name), []) or []
        return data if isinstance(data, list) else []

    def has(self, name):
        return os.path.exists(self.data_path(name))

    def clear(self, name=None):
        """Remove one feed's cache, or the whole directory. Returns count."""
        targets = ([name] if name else
                   [f[:-5] for f in os.listdir(self.directory)
                    if f.endswith(".json")])
        removed = 0
        for target in targets:
            for path in (self.data_path(target), self.meta_path(target)):
                try:
                    os.unlink(path)
                    removed += 1
                except OSError:
                    pass
        return removed

    # -- fetching -----------------------------------------------------------

    def fetch(self, feed, ttl=None, force=False):
        """Fetch ``feed`` through the cache.

        Order of preference: a fresh cache entry, a conditional request that
        may return 304, a full download, and finally the previous cache when
        the network fails. The cache is only ever replaced by a *successful*
        parse, so a malformed or truncated response cannot poison it.
        """
        name = feed.name
        if not force and self.is_fresh(name, ttl):
            return FetchResult(name, self.cached_records(name), 200,
                               self.meta(name).get("fetched_at"),
                               from_cache=True)
        if self.offline:
            cached = self.cached_records(name)
            if cached:
                return FetchResult(name, cached, 0,
                                   self.meta(name).get("fetched_at"),
                                   from_cache=True)
            return FetchResult(name, [], 0, None, error="offline and "
                                                          "no cached copy")

        meta = self.meta(name)
        request = urllib.request.Request(feed.url, method=feed.method)
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", feed.accept)
        if meta.get("etag") and not force:
            request.add_header("If-None-Match", meta["etag"])
        if meta.get("last_modified") and not force:
            request.add_header("If-Modified-Since", meta["last_modified"])
        for header, value in (feed.headers or {}).items():
            request.add_header(header, value)
        body = feed.encode_body() if feed.method == "POST" else None

        try:
            with urllib.request.urlopen(request, data=body,
                                        timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
                headers = dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            if e.code == 304:
                headers = dict(e.headers.items()) if e.headers else {}
                return FetchResult(name, self.cached_records(name), 304,
                                   self._revalidate(name, headers),
                                   not_modified=True, headers=headers)
            return self._fallback(name, e, status=e.code)
        except (urllib.error.URLError, OSError, ValueError) as e:
            return self._fallback(name, e)

        try:
            records = feed.parse(raw)
        except (ValueError, KeyError, TypeError, IndexError) as e:
            return self._fallback(name, e, status=status)

        now = time.time()
        _atomic_write(self.data_path(name), json.dumps(records))
        new_meta = {
            "fetched_at": now,
            "etag": headers.get("ETag") or headers.get("Etag"),
            "last_modified": headers.get("Last-Modified"),
            "count": len(records),
            "url": feed.url,
        }
        _atomic_write(self.meta_path(name), json.dumps(new_meta, indent=2))
        return FetchResult(name, records, status, now, headers=headers)

    def _revalidate(self, name, headers):
        """Refresh the freshness stamp after a 304 and return the new time."""
        now = time.time()
        meta = self.meta(name)
        meta["fetched_at"] = now
        if headers.get("ETag") or headers.get("Etag"):
            meta["etag"] = headers.get("ETag") or headers.get("Etag")
        if headers.get("Last-Modified"):
            meta["last_modified"] = headers["Last-Modified"]
        try:
            _atomic_write(self.meta_path(name), json.dumps(meta, indent=2))
        except OSError:
            return self.meta(name).get("fetched_at")
        return now

    def _fallback(self, name, error, status=None):
        """Serve the stale cache after a failed fetch, and say so."""
        cached = self.cached_records(name)
        if cached:
            return FetchResult(name, cached, status,
                               self.meta(name).get("fetched_at"),
                               from_cache=True, error=str(error))
        return FetchResult(name, [], status, None, error=str(error))

    def save_store(self, name, records):
        """Persist an already-built record set as if it had been fetched."""
        now = time.time()
        _atomic_write(self.data_path(name), json.dumps(records))
        _atomic_write(self.meta_path(name), json.dumps(
            {"fetched_at": now, "count": len(records), "etag": None,
             "last_modified": None}, indent=2))
        return now


def _safe(name):
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in name)
