"""CTI client: refresh feeds into a store, and look indicators up.

The public surface is three calls:

:func:`refresh`
    Pull every enabled feed through a :class:`~nightwatch.cti.cache.FeedCache`
    and return both the merged :class:`~nightwatch.cti.store.IndicatorStore`
    and a per-feed report.
:func:`load`
    Rebuild a store from an existing cache with no network access at all.
:func:`lookup`
    Resolve one indicator against a store and merge the verdict with the
    live DNS/IDN context from :mod:`nightwatch.threat_intel`.

:func:`blocklist` is the bridge to the pre-existing phishing detector: it
renders a store as the plain indicator set that
:func:`nightwatch.phishing.detector.check_intel` already consumes, so CTI
becomes a first-class signal without changing that module's contract.
"""

import json
import os
import tempfile

from .cache import DEFAULT_TIMEOUT, FeedCache
from .feeds import enabled_feeds, feed_catalog, get_feed
from .store import IndicatorStore

DEFAULT_CACHE_DIR = os.path.join("~", ".nightwatch", "cti")


def default_cache_dir():
    return os.path.expanduser(DEFAULT_CACHE_DIR)


def refresh(feeds=None, cache_dir=None, ttl=None, offline=False, force=False,
            now=None, extra_feeds=None):
    """Fetch feeds and return ``(store, report)``.

    ``feeds`` is a list of feed names (default: all enabled). ``extra_feeds``
    takes :class:`~nightwatch.cti.feeds.Feed` objects for ad-hoc URLs. A feed
    that fails is reported and skipped: one unreachable provider must never
    prevent the others from loading.
    """
    cache = FeedCache(cache_dir or default_cache_dir(),
                      timeout=DEFAULT_TIMEOUT, offline=offline)
    selected = list(enabled_feeds(feeds)) + list(extra_feeds or [])
    results = []
    records = []
    for feed in selected:
        result = cache.fetch(feed, ttl=ttl, force=force)
        results.append(result.as_dict())
        for record in result.records:
            records.append(record)
    store = IndicatorStore(records, now=now)
    store.prune(now=now)
    report = {
        "cache_dir": cache.directory,
        "feeds": results,
        "ok": sum(1 for r in results if r["ok"]),
        "failed": sum(1 for r in results if not r["ok"]),
        "records_ingested": sum(r["records"] for r in results),
        "stats": store.stats(now=now),
    }
    return store, report


def load(cache_dir=None, now=None, prune=True):
    """Rebuild a store from the cache without touching the network."""
    cache = FeedCache(cache_dir or default_cache_dir())
    records = []
    for path in sorted(os.listdir(cache.directory)):
        if not path.endswith(".json") or path.endswith(".meta.json"):
            continue
        records.extend(cache.cached_records(path[:-len(".json")]))
    store = IndicatorStore(records, now=now)
    if prune:
        store.prune(now=now)
    return store


def blocklist(store, now=None):
    """Render a store as an indicator set for the phishing detector."""
    return store.to_blocklist(now=now) if store else set()


def lookup(value, store=None, cache_dir=None, with_dns=True, now=None):
    """Resolve ``value`` against CTI, enriched with DNS and IDN context.

    Returns a dict that always contains ``indicator``, ``cti`` and
    ``corroboration``; when ``store`` is omitted the cache is loaded first, so
    a caller with no store object still gets an answer.
    """
    from nightwatch.threat_intel import analyze_indicator
    if store is None:
        store = load(cache_dir=cache_dir, now=now, prune=False)
    context = analyze_indicator(value, blocklist=blocklist(store, now=now))
    hits = store.match_all(value, now=now) if store else []
    best = hits[0] if hits else None
    payload = {
        "indicator": value,
        "cti": best,
        "cti_hits": hits,
        "corroboration": len(best["sources"]) if best else 0,
        "known_bad": bool(hits),
        "context": context if with_dns else None,
    }
    if best:
        payload["verdict"] = _verdict(best, hits)
    else:
        payload["verdict"] = "unknown"
    return payload


def _verdict(best, hits):
    """Turn a match into an operator-facing verdict.

    Corroboration matters more than any single feed's confidence, so two or
    more independent sources always outrank a lone high-confidence hit.
    """
    sources = len(best["sources"])
    if sources >= 3:
        return "malicious"
    if sources == 2 or best["confidence"] >= 80:
        return "malicious"
    if best["confidence"] >= 50:
        return "suspicious"
    return "informational"


def save(store, path):
    """Write a store to disk as JSON, for sharing or later offline replay."""
    rows = list(store)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)
    os.replace(tmp, path)
    return len(rows)


def catalog():
    """Known feeds, for CLI and dashboard listings."""
    return feed_catalog()


def feed_names():
    """Sorted names of every registered feed."""
    from .feeds import FEEDS
    return sorted(FEEDS)


__all__ = ["refresh", "load", "lookup", "blocklist", "save", "catalog",
           "default_cache_dir", "feed_names", "DEFAULT_CACHE_DIR",
           "get_feed"]
