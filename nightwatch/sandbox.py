"""Static malware-sample analysis.

Performs *safe* inspection only — hashing, file-type identification via magic
bytes, and printable-string heuristics. Samples are never executed or opened
by any interpreter, so this can run on untrusted binaries.
"""

import hashlib
import re

MAGIC = [
    (b"MZ", "PE / Windows executable"),
    (b"\x7fELF", "ELF / Linux executable"),
    (b"PK\x03\x04", "ZIP / Office / APK archive"),
    (b"%PDF", "PDF document"),
    (b"\xfe\xed\xfa\xce", "Mach-O (macOS)"),
    (b"\xca\xfe\xba\xbe", "Mach-O (macOS)"),
    (b"#!/", "Script (shebang)"),
    (b"\x4d\x5a", "DOS / PE"),
]

SUSPICIOUS = [
    "powershell", "cmd.exe", "/bin/sh", "/bin/bash", "wget ", "curl ",
    "certutil", "regsvr32", "rundll32", "schtasks", "crontab", "nc.exe",
    "netcat", "base64", "iex", "invoke-webrequest", "downloadstring",
    "mimikatz", "psexec", "CreateRemoteThread", "VirtualAlloc", "WinExec",
    "urlmon", "advapi32", "HKEY_", "SOFTWARE\\Microsoft", "encrypt",
    "ransom", "backdoor", "trojan", "keylogger", "botnet", ".onion",
]


def _filetype(data):
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    return "unknown"


def _strings(data, min_len=4):
    text = data.decode("latin-1", "ignore")
    return re.findall(r"[\x20-\x7e]{%d,}" % min_len, text)


def analyze_sample(data, filename=""):
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("sample must be bytes")
    data = bytes(data)
    hashes = {h: hashlib.new(h, data).hexdigest() for h in ("md5", "sha1", "sha256")}
    ftype = _filetype(data[:8])
    strings = _strings(data)
    low = "\n".join(strings).lower()
    hits = {}
    for s in SUSPICIOUS:
        if s in low:
            hits[s] = hits.get(s, 0) + 1
    score = min(100, len(hits) * 12)
    verdict = "suspicious" if score >= 30 else ("benign" if score == 0 else "unknown")
    return {
        "filename": filename,
        "size": len(data),
        "file_type": ftype,
        "hashes": hashes,
        "string_count": len(strings),
        "suspicious_strings": dict(sorted(hits.items(), key=lambda x: -x[1])[:20]),
        "risk_score": score,
        "verdict": verdict,
    }
