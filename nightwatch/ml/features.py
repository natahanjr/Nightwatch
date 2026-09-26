"""Feature engineering: turn Nightwatch detections into model input.

This is the join point between threat intelligence and machine learning. Every
detector in the project already produces a structured result - a URL verdict, a
log finding, a pcap flow summary - and this module flattens any of them into
a fixed-width, named, numeric vector that a model can consume.

Three properties matter more than the individual features:

**Names are part of the contract.** :data:`FEATURES` is an ordered tuple, and
every model stores the names it was trained on. A model refuses to score a
vector whose names differ, which turns "the column order changed" from a
silent wrong answer into an exception.

**CTI contributes as graded evidence, not a binary flag.** ``cti_hit``,
``cti_confidence``, ``cti_sources`` and ``cti_age_log`` are separate columns,
so a model can learn that a corroborated, high-confidence, long-known indicator
means something different from a single low-confidence mention.

**Counts are log-compressed.** Packet counts and byte totals span six orders
of magnitude; ``log1p`` keeps them influential without letting one large flow
distort the standardisation of the whole column.

Each extractor fills only the columns it can actually measure and zeroes the
rest, so a URL row and a flow row are directly comparable in one model.
"""

from urllib.parse import urlparse

from nightwatch.phishing.detector import (BRANDS, SUSPICIOUS_TLDS, _levenshtein,
                                          check_url)

from .linalg import entropy, log1p_scaled

# Ordered feature contract. Appending is safe; reordering or removing breaks
# already-saved models, so existing entries must never be rewritten in place.
FEATURES = (
    # heuristic + CTI evidence
    "url_score",
    "rule_hits",
    "cti_hit",
    "cti_confidence",
    "cti_sources",
    "cti_age_log",
    "cti_verdict_severity",
    # lexical shape of the host
    "host_length",
    "label_count",
    "digit_ratio",
    "hyphen_ratio",
    "host_entropy",
    "longest_label",
    # risk markers
    "suspicious_tld",
    "punycode",
    "ip_literal_host",
    "url_shortener",
    "brand_impersonation",
    "brand_distance",
    "insecure_scheme",
    # path and query shape
    "path_length",
    "query_params",
    "path_entropy",
    # network-flow / beacon evidence
    "beacon_regularity",
    "beacon_interval_log",
    "beacon_count_log",
    "unique_dst_ports",
    "suspicious_port_hit",
    "flow_completed",
    "packets_log",
    "bytes_log",
    "duration_log",
    "bytes_per_packet",
    "ja3_seen",
    "suspicious_sni",
)

FEATURE_COUNT = len(FEATURES)
_INDEX = {name: position for position, name in enumerate(FEATURES)}

# Column groups, so each extractor can zero-fill exactly what it did not
# measure instead of relying on a fragile "everything except" filter.
_EVIDENCE = ("url_score", "rule_hits", "cti_hit", "cti_confidence",
             "cti_sources", "cti_age_log", "cti_verdict_severity")
_LEXICAL = ("host_length", "label_count", "digit_ratio", "hyphen_ratio",
            "host_entropy", "longest_label", "suspicious_tld", "punycode",
            "ip_literal_host", "url_shortener", "brand_impersonation",
            "brand_distance", "insecure_scheme", "path_length", "query_params",
            "path_entropy")
_FLOW = ("beacon_regularity", "beacon_interval_log", "beacon_count_log",
         "unique_dst_ports", "suspicious_port_hit", "flow_completed",
         "packets_log", "bytes_log", "duration_log", "bytes_per_packet",
         "ja3_seen", "suspicious_sni")

# Verdict strings mapped to an ordered severity, so a model can weight a
# corroborated "malicious" above a lone "suspicious".
_VERDICT_SEVERITY = {
    "malicious": 3,
    "phishing": 3,
    "suspicious": 2,
    "informational": 1,
    "unknown": 0,
    "safe": 0,
}


def _ratio(count, total):
    return (count / total) if total else 0.0


def _is_ip_host(host):
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3
                                   and 0 <= int(p) <= 255 for p in parts)


def _cti_features(cti_hit):
    """Columns describing a CTI match, or zeros when there is no match."""
    if not cti_hit:
        return {"cti_hit": 0.0, "cti_confidence": 0.0, "cti_sources": 0.0,
                "cti_age_log": 0.0, "cti_verdict_severity": 0.0}
    age = cti_hit.get("age_seconds")
    return {
        "cti_hit": 1.0,
        "cti_confidence": float(cti_hit.get("confidence") or 0),
        "cti_sources": float(len(cti_hit.get("sources") or ())),
        "cti_age_log": log1p_scaled(age) / 10.0 if age else 0.0,
        "cti_verdict_severity": float(
            _VERDICT_SEVERITY.get(cti_hit.get("verdict"), 0)),
    }


def _brand_distance(domain):
    """Edit distance from the closest impersonated brand; lower is worse."""
    if not domain:
        return 0.0
    return float(min((_levenshtein(domain, brand) for brand in BRANDS),
                     default=0))


def url_features(url, cti=None, blocklist=None, verdict=None):
    """Feature dict for a single URL.

    ``cti`` is an :class:`~nightwatch.cti.store.IndicatorStore` (or anything
    exposing ``lookup``); ``blocklist`` is the legacy indicator set. The
    existing :func:`~nightwatch.phishing.detector.check_url` rules are reused
    rather than reimplemented, so the model and the human-readable verdict can
    never drift apart.
    """
    result = check_url(url, blocklist=blocklist, cti=cti)
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    labels = [l for l in host.split(".") if l] or [""]
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""

    features = {name: 0.0 for name in _FLOW}
    features.update({
        "url_score": float(result["score"]),
        "rule_hits": float(len(result["flags"])),
        "host_length": float(len(host)),
        "label_count": float(len(labels)),
        "digit_ratio": _ratio(sum(c.isdigit() for c in host), len(host)),
        "hyphen_ratio": _ratio(host.count("-"), len(host)),
        "host_entropy": entropy(host),
        "longest_label": float(max((len(l) for l in labels), default=0)),
        "suspicious_tld": float(tld in SUSPICIOUS_TLDS),
        "punycode": float("xn--" in host),
        "ip_literal_host": float(_is_ip_host(host)),
        "url_shortener": float(bool(result["shortened"])),
        "brand_impersonation": float(bool(result["brand_target"])),
        "brand_distance": _brand_distance(domain),
        "insecure_scheme": float(parsed.scheme == "http"),
        "path_length": float(len(parsed.path or "")),
        "query_params": float(len((parsed.query or "").split("&"))
                              if parsed.query else 0),
        "path_entropy": entropy(parsed.path or ""),
    })
    features.update(_cti_features(result.get("cti")))
    if verdict is not None:
        features["cti_verdict_severity"] = float(
            _VERDICT_SEVERITY.get(verdict, 0))
    return features


def flow_features(analysis, flow=None, beacon=None):
    """Feature dict for network evidence from :func:`analyze_pcap`.

    ``analysis`` is the pcap summary. ``flow`` and ``beacon`` optionally pin
    the row to one specific flow or beacon, which is how an operator scores a
    single conversation rather than the whole capture. Columns the caller did
    not supply are zero-filled, so a row is always complete.
    """
    analysis = analysis or {}
    beacons = analysis.get("beacons") or []
    chosen = beacon or (beacons[0] if beacons else None)
    connections = analysis.get("unique_connections") or 0
    completed = analysis.get("completed_connections") or 0
    suspicious_ports = set(analysis.get("suspicious_ports") or [])
    top_ports = analysis.get("top_destination_ports") or []

    packets = float((flow or {}).get("packets")
                    if flow else analysis.get("packets_parsed") or 0)
    if flow:
        total_bytes = float(flow.get("bytes") or 0)
        duration = float((flow.get("end") or 0) - (flow.get("start") or 0))
    else:
        total_bytes = 0.0
        duration = 0.0

    features = {name: 0.0 for name in _EVIDENCE + _LEXICAL}
    features.update({
        "beacon_count_log": log1p_scaled(len(beacons)),
        "beacon_regularity": _beacon_regularity(beacons),
        "beacon_interval_log": log1p_scaled(chosen.get("interval") or 0)
        if chosen else 0.0,
        "unique_dst_ports": float(len(top_ports)),
        "suspicious_port_hit": float(bool(suspicious_ports) or any(
            port in suspicious_ports for port, _ in top_ports)),
        "flow_completed": _ratio(completed, connections),
        "packets_log": log1p_scaled(packets),
        "bytes_log": log1p_scaled(total_bytes),
        "duration_log": log1p_scaled(duration),
        "bytes_per_packet": _ratio(total_bytes, packets),
        "ja3_seen": float(bool(analysis.get("tls_ja3"))),
        "suspicious_sni": float(_has_suspicious_sni(analysis)),
    })
    return features


def _beacon_regularity(beacons):
    """Strongest periodicity observed among detected beacons, 0 to 1.

    :func:`~nightwatch.network.analyzer.analyze_pcap` only emits a beacon when
    the mean absolute deviation of its inter-arrival intervals is under 30% of
    the median, so the regularity it reports is already a measure of how
    metronomic the traffic is. The most regular beacon wins.
    """
    if not beacons:
        return 0.0
    values = [b.get("regularity") for b in beacons
              if b.get("regularity") is not None]
    return float(max(values)) if values else 0.0


def _has_suspicious_sni(analysis):
    return any(sni.lower().endswith(t)
               for sni, _ in analysis.get("tls_sni") or []
               for t in SUSPICIOUS_TLDS)


def finding_features(finding):
    """Feature dict for a log or network finding dict.

    A finding is a small record (``label``, ``count``, ``detail``), so the
    signal is carried by which detector fired and how many events it saw,
    scaled by the CTI state of the host embedded in the detail string when one
    can be recognised.
    """
    features = {name: 0.0 for name in _EVIDENCE + _FLOW}
    label = str(finding.get("label") or "")
    features["rule_hits"] = float(len(finding.get("flags") or []) or 1)
    features["url_score"] = float(finding.get("count") or 0) / 10.0
    features["beacon_regularity"] = 1.0 if label in _BEACON_LABELS else 0.0
    features["beacon_count_log"] = log1p_scaled(finding.get("count") or 0)
    features["suspicious_port_hit"] = float(label == "sensitive-port-traffic")
    features["flow_completed"] = float(label in _SCAN_LABELS)
    features["cti_verdict_severity"] = float(_SEVERE_LABELS.get(
        str(finding.get("severity") or "").upper(), 0))
    return features


_BEACON_LABELS = {"possible-beacon"}
_SCAN_LABELS = {"syn-scan", "icmp-sweep"}
_SEVERE_LABELS = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def vectorize(features, names=FEATURES):
    """Project a feature dict onto the ordered numeric vector.

    Missing columns default to 0.0 rather than raising, so a partial record
    (a URL with no flow context, or a finding with no CTI) still produces a
    usable row instead of a crash.
    """
    return [float(features.get(name, 0.0)) for name in names]


def row(record, names=FEATURES):
    """Build a feature row from a URL string or a feature-ish record."""
    url = record.get("url") or record.get("value") or record.get("host") \
        if isinstance(record, dict) else record
    if isinstance(url, str) and url:
        return vectorize(url_features(url), names)
    if isinstance(record, dict):
        return vectorize({k: v for k, v in record.items() if k in _INDEX},
                         names)
    raise ValueError("row() needs a URL string or a feature dict")


def describe():
    """Human-readable feature list, for the CLI and documentation."""
    return [{"name": name, "index": position}
            for position, name in enumerate(FEATURES)]
