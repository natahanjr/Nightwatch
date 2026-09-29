"""Cloud / IAM security-posture analysis from policy or config text.

Scans an IAM policy, Terraform/HCL, or CSV export for common misconfigurations:
wildcard principals, over-permissive actions, public exposure, missing MFA,
weak cryptography and plaintext secrets. Fully offline.
"""

import json
import re

WEAK_CRYPTO = re.compile(r"\b(md5|sha1|sha-1|des|3des|rc4|rc2|md4)\b", re.I)
SECRET = re.compile(r"(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"']?[^\s\"']{4,}", re.I)


def _text_findings(text):
    findings = []
    low = text
    if '"*"' in low and "Principal" in low:
        findings.append("Wildcard principal \"*\"")
    if "0.0.0.0/0" in low:
        findings.append("Open ingress 0.0.0.0/0")
    if "public-read" in low or "public-write" in low:
        findings.append("Public storage ACL")
    if '"HTTP"' in low or "Protocol=HTTP" in low:
        findings.append("Plaintext HTTP listener (no TLS)")
    if "aws:MultiFactorAuthPresent" not in low and ("iam" in low or "policy" in low):
        findings.append("No MFA condition enforced")
    if WEAK_CRYPTO.search(low):
        findings.append("Weak cryptography (md5/sha1/des/rc4)")
    if SECRET.search(low):
        findings.append("Possible plaintext secret/credential")
    return findings


def _json_findings(doc):
    findings = []

    def walk(o):
        if isinstance(o, dict):
            effect = str(o.get("Effect", "")).lower()
            action = o.get("Action")
            principal = o.get("Principal")
            if effect == "allow" and (action == "*" or action == ["*"] or "*" in (action if isinstance(action, list) else [])):
                findings.append("Allow \"*\" action (IAM)")
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                findings.append("Wildcard principal (IAM)")
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(doc)
    return findings


def analyze_posture(text, filename=""):
    text = text or ""
    findings = _text_findings(text)
    try:
        findings += _json_findings(json.loads(text))
    except (ValueError, TypeError):
        pass
    findings = sorted(set(findings))
    return {
        "filename": filename,
        "findings": findings,
        "risk": "high" if findings else "low",
    }
