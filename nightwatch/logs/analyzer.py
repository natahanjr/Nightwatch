"""Log correlation: keyword rules, burst detection and markdown reports."""

import re
from collections import Counter, defaultdict
from datetime import datetime

DEFAULT_RULES = [
    (re.compile(r"failed password"), "HIGH", "failed-login"),
    (re.compile(r"authentication failure"), "HIGH", "failed-login"),
    (re.compile(r"invalid user"), "MEDIUM", "invalid-user"),
    (re.compile(r"\b401\b"), "MEDIUM", "forbidden-access"),
    (re.compile(r"\b403\b"), "MEDIUM", "forbidden-access"),
    (re.compile(r"\b(?:root|admin|sudo)\b"), "MEDIUM", "privileged-account"),
    (re.compile(r"union\s+select"), "HIGH", "sql-injection"),
    (re.compile(r"\binjection\b"), "HIGH", "sql-injection"),
    (re.compile(r"'?\s*or\s+'"), "HIGH", "sql-injection"),
    (re.compile(r"<script"), "HIGH", "xss"),
    (re.compile(r"\.\./"), "MEDIUM", "path-traversal"),
    (re.compile(r"\bdenied\b"), "LOW", "denied"),
    (re.compile(r"\bmalware\b"), "HIGH", "malware-indicator"),
]


def _matches(rule, message):
    pattern, severity, label = rule
    return pattern.search(message.lower())


def load_rules(path):
    """Load custom rules from a JSON file.

    Format: [{"pattern": "regex", "severity": "HIGH", "label": "name"}, ...]
    """
    import json as _json
    with open(path, "r", encoding="utf-8-sig") as f:
        data = _json.load(f)
    rules = []
    for item in data:
        pattern = item.get("pattern")
        if not pattern:
            raise ValueError("Every rule needs a 'pattern'")
        rules.append((
            re.compile(pattern, re.IGNORECASE),
            str(item.get("severity", "MEDIUM")).upper(),
            str(item.get("label", "custom")),
        ))
    return rules


def correlate(events, rules=None):
    """Run keyword/pattern rules over normalized events and group findings.

    Rules matching the same event under the same label are merged.
    """
    rules = rules or DEFAULT_RULES
    grouped = defaultdict(list)
    for event in events:
        message = event.get("message")
        if not message:
            continue
        for pattern, severity, label in rules:
            if pattern.search(message.lower()):
                grouped[(label, severity)].append(event)
    findings = []
    for (label, severity), hits in sorted(grouped.items()):
        findings.append({
            "label": label,
            "severity": severity,
            "count": len(hits),
            "sample": hits[0]["message"][:200],
        })
    return findings


def _to_epoch(ts):
    """Best-effort conversion of a timestamp to a Unix epoch float."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    try:
        return float(s)
    except ValueError:
        return None


def _fmt_ts(epoch):
    """Render an epoch as a readable timestamp (falls back to raw value)."""
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, OverflowError):
        return str(epoch)


def detect_bursts(events, window_seconds=60, threshold=10):
    """Flag sources producing at least `threshold` events within any sliding
    window of `window_seconds`. Uses a true sliding window (not fixed buckets)
    so bursts that straddle a bucket boundary are still caught, and records
    the peak rate seen during each contiguous burst.
    """
    bursts = []
    by_source = defaultdict(list)
    for e in events:
        epoch = _to_epoch(e.get("timestamp"))
        if epoch is None:
            continue
        by_source[e.get("source", "unknown")].append(epoch)
    for source, times in by_source.items():
        times.sort()
        left = 0
        seg_start = None
        seg_max = 0
        for right in range(len(times)):
            while times[right] - times[left] > window_seconds:
                left += 1
            count = right - left + 1
            if count >= threshold:
                if seg_start is None:
                    seg_start = times[left]
                    seg_max = count
                else:
                    seg_max = max(seg_max, count)
            else:
                if seg_start is not None:
                    bursts.append({
                        "source": source,
                        "window_start": _fmt_ts(seg_start),
                        "window_start_epoch": seg_start,
                        "count": seg_max,
                    })
                    seg_start = None
        if seg_start is not None:
            bursts.append({
                "source": source,
                "window_start": _fmt_ts(seg_start),
                "window_start_epoch": seg_start,
                "count": seg_max,
            })
    return bursts


def analyze(events, rules=None, window_seconds=60, threshold=10):
    return {
        "events_total": len(events),
        "levels": dict(Counter(e.get("level") for e in events if e.get("level"))),
        "sources": dict(Counter(e.get("source") for e in events).most_common(10)),
        "findings": correlate(events, rules),
        "bursts": detect_bursts(events, window_seconds, threshold),
    }


def generate_markdown_report(path, events, rules=None, window_seconds=60,
                             threshold=10):
    """Write a markdown analysis report to `path`."""
    result = analyze(events, rules, window_seconds, threshold)
    lines = [
        "# Nightwatch Log Analysis Report",
        "",
        f"- Total events: {result['events_total']}",
        f"- Findings: {len(result['findings'])}",
        f"- Bursts: {len(result['bursts'])}",
        "",
        "## Findings",
        "",
    ]
    if result["findings"]:
        for f in result["findings"]:
            lines.append(f"- [{f['severity']}] {f['label']}: {f['count']} "
                         f"events (sample: `{f['sample']}`)")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Event sources")
    lines.append("")
    for source, count in result["sources"].items():
        lines.append(f"- {source}: {count}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return result
