"""Digital Forensics & IR — reconstruct timelines from event logs.

Builds a chronological timeline and a case summary from arbitrary event
records (the same event shapes produced by the log collector).
"""

import json
import tempfile
import os

from nightwatch.logs import collect

_TS_KEYS = ("timestamp", "time", "ts", "@timestamp", "date", "event_time", "datetime")
_CAT_KEYS = ("type", "category", "event", "level", "severity")


def _find(ev, keys):
    if not isinstance(ev, dict):
        return None
    for k in keys:
        if k in ev and ev[k] not in (None, ""):
            return ev[k]
    for v in ev.values():
        if isinstance(v, dict):
            r = _find(v, keys)
            if r:
                return r
        elif isinstance(v, list):
            for item in v:
                r = _find(item, keys)
                if r:
                    return r
    return None


def _ts(ev):
    return str(_find(ev, _TS_KEYS) or "")


def build_timeline(events):
    rows = []
    for ev in events:
        if isinstance(ev, dict):
            rows.append((_ts(ev), ev))
    rows.sort(key=lambda r: r[0])

    cats = {}
    timeline = []
    for ts, ev in rows:
        cat = _find(ev, _CAT_KEYS) or "event"
        cats[cat] = cats.get(cat, 0) + 1
        timeline.append({
            "time": ts,
            "category": str(cat),
            "summary": json.dumps(ev, ensure_ascii=False)[:400],
        })
    return {
        "total_events": len(timeline),
        "first_seen": timeline[0]["time"] if timeline else None,
        "last_seen": timeline[-1]["time"] if timeline else None,
        "categories": cats,
        "timeline": timeline[:500],
    }


def analyze_logs(raw_text):
    """Collect events from raw log text and build a forensic timeline."""
    fd, tmp = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(tmp, "w", encoding="utf-8", errors="replace") as f:
        f.write(raw_text or "")
    try:
        events = collect(tmp)
    finally:
        os.remove(tmp)
    # The collector often nests the original record as a JSON string in
    # ``message``; surface those fields so the timeline can use them.
    enriched = []
    for ev in events:
        if isinstance(ev, dict) and isinstance(ev.get("message"), str):
            try:
                inner = json.loads(ev["message"])
            except (ValueError, TypeError):
                inner = None
            if isinstance(inner, dict):
                merged = dict(inner)
                for k, v in ev.items():
                    if v not in (None, ""):
                        merged.setdefault(k, v)
                ev = merged
        enriched.append(ev)
    return build_timeline(enriched)
