"""URL and email phishing detection using heuristic scoring and optional
local threat-intelligence blocklists.
"""

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "s.id", "lnkd.in",
    "tiny.cc", "t.ly", "tiny.pl", "dub.sh",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link",
    ".zip", ".mov", ".country", ".icu", ".monster",
}

KEYWORDS = {
    "login", "signin", "verify", "account", "secure", "bank", "update",
    "confirm", "password", "wallet", "invoice", "unlock", "suspend",
    "blocked", "recover",
}

BRANDS = {
    "paypal", "facebook", "instagram", "google", "gmail", "microsoft",
    "outlook", "apple", "icloud", "netflix", "amazon", "chase", "ebay",
    "whatsapp", "linkedin", "cryptocurrency",
}

URL_RE = re.compile(r"https?://[^\s<>\"'\]]+", re.I)
# Bare domains (used to catch links written without a scheme, common in mail).
BARE_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Unicode confusables that visually resemble ASCII letters (homoglyph attacks).
_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0491": "g", "\u04bb": "h", "\u04bb": "h", "\u04d9": "a", "\u04cf": "d",
    "\u0561": "a", "\u0565": "e", "\u0570": "h", "\u0578": "o", "\u057e": "x",
    "\u057e": "x", "\u0583": "c", "\u0585": "u", "\u0587": "p", "\u0581": "s",
    "\u13a5": "o", "\u13ac": "e", "\u14ab": "a", "\u14c0": "o", "\u14c7": "e",
    "\u1d00": "a", "\u1d07": "b", "\u1d0d": "o", "\u1d0f": "d", "\u1d18": "r",
    "\u1d1c": "t", "\u1d09": "g", "\u1d0b": "k", "\u1d0c": "m", "\u1d0e": "p",
    "\u1d04": "c", "\u1d05": "e", "\u1d06": "f", "\u1d1b": "s", "\u1d22": "x",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o", "\uff50": "p", "\uff53": "s",
    "\uff58": "x", "\uff49": "i", "\uff4a": "j", "\uff43": "c", "\uff59": "y",
}


def _normalize_confusables(text):
    """Map known Unicode confusables back to ASCII (best-effort)."""
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


def _has_confusable(host):
    return any(ch in _CONFUSABLES for ch in host)


def extract_urls(text):
    """Pull candidate URLs from free text.

    Handles standard ``http(s)://`` links plus common obfuscations seen in
    phishing: defanged URLs (``hxxp``, ``[.]``, ``(.)``, ``{.}``) and bare
    domains written without a scheme.
    """
    norm = (text.replace("[.]", ".")
                .replace("(.)", ".")
                .replace("{.}", ".")
                .replace("[@]", "@")
                .replace("hxxp", "http")
                .replace("hXXp", "http")
                .replace("HXXP", "http"))
    urls = list(URL_RE.findall(norm))
    for m in BARE_RE.findall(norm):
        # Skip bare domains that are just the host portion of a URL we
        # already extracted (otherwise every link is double counted).
        if any(m in u for u in urls):
            continue
        urls.append("http://" + m)
    seen = set()
    out = []
    for u in urls:
        u = u.strip(").,]'\"")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _root_domain(host):
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host.lower()
    return ".".join(parts[-2:])


def _domain_root(host):
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return parts[0]
    return parts[-2]


def load_blocklist(path):
    """Load a local threat-intel blocklist.

    Accepts either a JSON file of the form ``{"indicators": [...]}`` / a bare
    list, or a plain-text file with one indicator (domain, URL or keyword)
    per line. Returns a set of lower-cased indicators.
    """
    indicators = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read().strip()
    try:
        data = json.loads(text)
    except ValueError:
        for line in text.splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                indicators.add(line)
        return indicators
    if isinstance(data, dict):
        data = data.get("indicators", [])
    for item in data:
        item = str(item).strip().lower()
        if item:
            indicators.add(item)
    return indicators


def fetch_blocklist(url, timeout=5):
    """Download a blocklist from a URL (plain text or JSON). Best effort."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Nightwatch"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError):
        return set()
    try:
        data = json.loads(raw)
        items = data.get("indicators", []) if isinstance(data, dict) else data
        return {str(i).strip().lower() for i in items if i}
    except ValueError:
        return {ln.strip().lower() for ln in raw.splitlines()
                if ln.strip() and not ln.startswith("#")}


def check_intel(url, blocklist):
    """Return the first matching blocklist indicator for ``url``, else None.

    Indicators that look like a full URL or path (contain a slash or ``://``)
    are matched as substrings of the whole URL, while bare indicators (domains,
    keywords) are matched only against the host so a generic word such as
    ``login`` cannot flag every legitimate login page.
    """
    if not blocklist:
        return None
    raw = url if "://" in url else "http://" + url
    host = (urlparse(raw).hostname or "").lower()
    low = url.lower()
    for ind in blocklist:
        i = ind.lower()
        if ("/" in i) or ("://" in i):
            if i in low:
                return ind
        else:
            if i == host or host.endswith("." + i):
                return ind
    return None


def cti_score(hit):
    """Score contribution for a CTI match, in the same 0-100 scale as rules.

    A feed that reports 100% confidence and is corroborated by three
    independent sources saturates the score on its own; a single 50%-confidence
    mention contributes 35 points, below a punycode homograph.
    """
    confidence = max(0, min(100, int(hit.get("confidence") or 0)))
    sources = max(1, len(hit.get("sources") or ()))
    base = 20 + round(60 * confidence / 100.0)
    return base + 20 * (sources - 1)


def _cti_reason(hit):
    """One-line justification for a CTI match, for the flags list."""
    sources = list(hit.get("sources") or ())
    parts = [f"{hit['confidence']}% confidence"]
    parts.append("corroborated by " + ", ".join(sources) if len(sources) > 1
                 else f"from {sources[0]}" if sources else "unattributed")
    if hit.get("age_seconds") is not None:
        parts.append(f"first seen {hit['age_seconds']}s ago")
    return f"{hit['matched']} ({'; '.join(parts)})"


def check_url(url, blocklist=None, cti=None):
    """Score a single URL and return flags, score and verdict.

    ``blocklist`` is an optional set of indicators from :func:`load_blocklist`.
    ``cti`` is an optional :class:`nightwatch.cti.store.IndicatorStore`; when
    given, a CTI hit adds a confidence-scaled score instead of the flat +60
    used for a plain blocklist match, so a corroborated 90%-confidence feed
    hit outweighs a stale local list entry.
    """
    flags = []
    score = 0
    raw = url if "://" in url else "http://" + url
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    root = _root_domain(host)
    domain = _domain_root(host)

    cti_hit = cti.lookup(raw) if cti is not None else None
    if cti_hit is not None:
        flags.append("cti-match:" + cti_hit["matched"])
        score += cti_score(cti_hit)
    elif blocklist:
        hit = check_intel(url, blocklist)
        if hit:
            flags.append("blocklist-match:" + hit)
            score += 60

    if not host:
        flags.append("missing-host")
        return {"url": url, "host": None, "flags": flags, "score": 100,
                "verdict": "phishing", "shortened": False, "brand_target": None}

    if IP_RE.match(host):
        flags.append("ip-literal-host")
        score += 40
    elif ":" in host:
        flags.append("ipv6-literal-host")
        score += 40

    if "@" in raw:
        flags.append("credentials-in-url")
        score += 30

    if any(s in host or host.endswith("." + s) for s in SHORTENERS):
        flags.append("url-shortener")
        score += 40
        shortened = True
    else:
        shortened = False

    if "xn--" in host:
        flags.append("punycode-homograph")
        score += 40

    ascii_host = _normalize_confusables(host)
    homoglyph = False
    if ascii_host != host:
        flags.append("unicode-homoglyph")
        score += 40
        host = ascii_host
        root = _root_domain(host)
        domain = _domain_root(host)
        homoglyph = True

    tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append("suspicious-tld")
        score += 25

    matched_keywords = [k for k in KEYWORDS if k in domain]
    if matched_keywords:
        flags.append("keyword-in-domain:" + ",".join(matched_keywords))
        score += min(40, 20 * len(matched_keywords))

    brand_target = None
    for brand in BRANDS:
        if domain == brand and not homoglyph:
            continue
        if brand in domain:
            brand_target = brand
            break
    if not brand_target:
        for brand in BRANDS:
            if domain == brand and not homoglyph:
                continue
            if len(brand) >= 5 and _levenshtein(domain, brand) <= 2:
                brand_target = brand
                break
    if brand_target:
        flags.append("brand-impersonation:" + brand_target)
        score += 45

    if "-" in domain:
        flags.append("hyphenated-domain")
        score += 15

    if host.count(".") >= 4:
        flags.append("many-subdomains")
        score += 20

    if len(host) > 40:
        flags.append("very-long-host")
        score += 10

    if re.search(r"\d", domain):
        flags.append("digits-in-domain")
        score += 10

    if parsed.scheme == "http" and matched_keywords:
        flags.append("insecure-http")
        score += 10

    if score >= 70:
        verdict = "phishing"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if cti_hit is not None:
        flags.append("cti-reason:" + _cti_reason(cti_hit))

    return {
        "url": url,
        "host": host,
        "flags": flags,
        "score": score,
        "verdict": verdict,
        "shortened": shortened,
        "brand_target": brand_target,
        "cti": ({
            "matched": cti_hit["matched"],
            "type": cti_hit["type"],
            "sources": list(cti_hit["sources"]),
            "confidence": cti_hit["confidence"],
            "age_seconds": cti_hit["age_seconds"],
        } if cti_hit is not None else None),
    }


def check_email(text, blocklist=None, cti=None):
    """Extract URLs from an email body and check each one."""
    urls = extract_urls(text)
    results = [check_url(u, blocklist=blocklist, cti=cti) for u in urls]
    verdicts = [r["verdict"] for r in results]
    if "phishing" in verdicts:
        overall = "phishing"
    elif "suspicious" in verdicts:
        overall = "suspicious"
    else:
        overall = "safe"
    return {"urls_checked": len(results), "overall_verdict": overall,
            "results": results}


def check_file(path, blocklist=None, cti=None):
    """Read a text file (email body, link list) and check all URLs in it."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return check_email(f.read(), blocklist=blocklist, cti=cti)


class _NoFollowRedirects(urllib.request.HTTPRedirectHandler):
    """Capture redirects manually instead of following them silently."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_url(url, timeout=5, max_redirects=5, total_timeout=20):
    """Live verification: DNS resolution and redirect chain following.

    Returns a dict with resolution info, the redirect chain and the final
    destination so the user can compare what the link really leads to. A hard
    ``total_timeout`` bounds the whole operation so it can never hang a caller
    (e.g. the web API) indefinitely.
    """
    raw = url if "://" in url else "http://" + url
    host = urlparse(raw).hostname
    info = {
        "url": url,
        "resolves": False,
        "ips": [],
        "redirects": [],
        "redirect_count": 0,
        "final_url": None,
        "cross_domain_redirect": False,
        "error": None,
    }
    start = time.time()
    try:
        ips = sorted({addr[4][0] for addr in socket.getaddrinfo(host, None)})
        info["resolves"] = True
        info["ips"] = ips
    except (socket.gaierror, OSError):
        info["error"] = "domain does not resolve"
        return info

    opener = urllib.request.build_opener(_NoFollowRedirects)
    original_host = (urlparse(raw).hostname or "").lower()
    current = raw
    seen = set()
    for _ in range(max_redirects + 1):
        if time.time() - start > total_timeout:
            info["error"] = "verification timed out"
            break
        seen.add(current)
        try:
            req = urllib.request.Request(
                current, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=timeout) as resp:
                info["final_url"] = resp.geturl()
                info["status_code"] = resp.status
                break
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location")
                if not location:
                    info["error"] = f"redirect without location (HTTP {e.code})"
                    break
                current = urllib.parse.urljoin(current, location)
                info["redirects"].append(current)
                info["redirect_count"] = len(info["redirects"])
                if current in seen:
                    info["error"] = "redirect loop detected"
                    break
            else:
                info["error"] = f"HTTP {e.code}"
                info["status_code"] = e.code
                info["final_url"] = current
                break
        except urllib.error.URLError as e:
            info["error"] = str(e.reason)
            info["final_url"] = current
            break
    if info["final_url"] is None:
        info["final_url"] = current
    final_host = (urlparse(info["final_url"]).hostname or "").lower()
    info["cross_domain_redirect"] = bool(
        info["redirects"] and final_host != original_host)
    return info
