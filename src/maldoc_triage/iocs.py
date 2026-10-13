"""Indicator-of-compromise extraction from raw bytes/text.

Everything here is read-only pattern matching. No network lookups are performed;
"IOC" simply means "artifact worth recording", not a confirmed-bad indicator.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# http/https/ftp URLs. Deliberately permissive on the path, strict-ish on scheme.
_URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>)\]}\\]+",
    re.IGNORECASE,
)

# UNC paths (\\host\share) - common in template-injection lures.
_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"'<>)\]}]+")

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Bare domains with a TLD of 2+ alpha chars. We filter out obvious noise later.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Common file-name noise that the domain regex would otherwise capture.
_FILENAME_TLDS = {
    "exe", "dll", "bin", "xml", "rels", "png", "jpg", "jpeg", "gif", "bmp",
    "emf", "wmf", "css", "js", "json", "txt", "tmp", "dat", "config", "html",
    "htm", "vbs", "ps1", "bat", "cmd", "doc", "docx", "docm", "xls", "xlsx",
    "xlsm", "ppt", "pptx", "pptm", "rtf", "pdf", "zip", "rar", "gz",
}


# Hosts that appear in virtually every Office/OOXML or XML file as namespace
# declarations and schema references. They are not meaningful IOCs, so we drop
# them to keep triage output focused on attacker-controlled infrastructure.
_BENIGN_HOSTS = (
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "www.w3.org",
    "w3.org",
    "schemas.xmlsoap.org",
    "www.iso.org",
    "ns.adobe.com",
    "openoffice.org",
    "docs.oasis-open.org",
)


def _is_benign_url(url: str) -> bool:
    low = url.lower()
    return any(host in low for host in _BENIGN_HOSTS)


def _strip_trailing_punct(value: str) -> str:
    return value.rstrip(".,;:!?)\"'")


def extract_urls(text: str) -> List[str]:
    found = [_strip_trailing_punct(m.group(0)) for m in _URL_RE.finditer(text)]
    found += [m.group(0) for m in _UNC_RE.finditer(text)]
    return _dedupe(u for u in found if not _is_benign_url(u))


def extract_ipv4(text: str) -> List[str]:
    return _dedupe(m.group(0) for m in _IPV4_RE.finditer(text))


def extract_domains(text: str) -> List[str]:
    domains: List[str] = []
    for match in _DOMAIN_RE.finditer(text):
        candidate = match.group(0).lower()
        tld = candidate.rsplit(".", 1)[-1]
        if tld in _FILENAME_TLDS:
            continue
        # Skip things that are clearly a version string or purely numeric host.
        if candidate.replace(".", "").isdigit():
            continue
        if _is_benign_url(candidate):
            continue
        domains.append(candidate)
    return _dedupe(domains)


def _dedupe(items: Iterable[str]) -> List[str]:
    """Order-preserving de-duplication."""
    seen = set()
    out: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def extract_all(data: bytes) -> Dict[str, List[str]]:
    """Extract every IOC class from raw bytes.

    The bytes are decoded leniently as both latin-1 (captures single-byte text)
    and as UTF-16LE (captures wide strings common in OLE/Office payloads).
    """
    texts: List[str] = []
    try:
        texts.append(data.decode("latin-1", errors="ignore"))
    except Exception:
        pass
    try:
        texts.append(data.decode("utf-16-le", errors="ignore"))
    except Exception:
        pass

    urls: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    for text in texts:
        urls += extract_urls(text)
        ips += extract_ipv4(text)
        domains += extract_domains(text)

    urls = _dedupe(urls)
    ips = _dedupe(ips)

    # Domains that already appear inside a captured URL are redundant noise.
    url_blob = " ".join(urls).lower()
    domains = _dedupe(d for d in domains if d not in url_blob)

    result: Dict[str, List[str]] = {}
    if urls:
        result["urls"] = urls
    if ips:
        result["ipv4"] = ips
    if domains:
        result["domains"] = domains
    return result
