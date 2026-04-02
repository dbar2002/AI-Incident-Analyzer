"""
IOC Extractor — Regex-based Indicator of Compromise extraction.

Extracts network indicators from raw log/alert text before AI analysis.
This runs deterministically so you always get consistent IOC extraction
regardless of AI model behavior.
"""

import re
from app.models.ioc import IOC, IOCCollection


# --- Regex patterns for common IOC types ---

# IPv4 addresses (avoids matching version numbers like 1.2.3)
_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# Domains — handles defanged notation like example[.]com
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:[a-zA-Z]{2,63})\b'
    r'|'
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\[\.\])'
    r'+(?:[a-zA-Z]{2,63})\b'
)

# URLs — handles defanged hxxp(s)
_URL_RE = re.compile(
    r'(?:https?://|hxxps?://|hXXps?://)'
    r'[^\s<>\"\'\)]+',
    re.IGNORECASE
)

# Email addresses
_EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# MD5 (32 hex chars)
_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')

# SHA1 (40 hex chars)
_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')

# SHA256 (64 hex chars)
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Filenames with suspicious extensions
_FILENAME_RE = re.compile(
    r'\b[\w\-\.]+\.(?:exe|dll|bat|ps1|vbs|js|scr|cmd|msi|jar|py|sh|'
    r'pdf\.exe|doc\.exe|docm|xlsm|hta|wsf|lnk)\b',
    re.IGNORECASE
)

# CVE IDs
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# Known private/internal IP ranges to flag but not discard
_PRIVATE_IP_RE = re.compile(
    r'^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)'
)


def _dedupe_preserving_order(items: list[str]) -> list[str]:
    """Remove duplicates while preserving first-seen order."""
    seen = set()
    result = []
    for item in items:
        normalized = item.lower().strip()
        if normalized not in seen:
            seen.add(normalized)
            result.append(item.strip())
    return result


def _classify_ip(ip: str) -> str:
    """Return context string for an IP address."""
    if _PRIVATE_IP_RE.match(ip):
        return "Internal/private IP address"
    return "External IP address"


def extract_iocs(text: str) -> IOCCollection:
    """
    Extract all IOCs from raw text.

    Returns an IOCCollection with categorized, deduplicated indicators.
    """
    collection = IOCCollection()

    # --- Extract URLs first (so we can avoid double-counting domains from URLs) ---
    raw_urls = _dedupe_preserving_order(_URL_RE.findall(text))
    url_domains = set()
    for url in raw_urls:
        collection.urls.append(IOC(type="url", value=url, context="URL found in log data"))
        # Extract domain from URL to avoid duplicate domain entries
        domain_match = re.search(r'://([^/:\s]+)', url)
        if domain_match:
            url_domains.add(domain_match.group(1).lower().replace('[.]', '.'))

    # --- Hashes (extract before IPs to avoid hex strings matching IP patterns) ---
    # SHA256 first (longest), then SHA1, then MD5 — avoid substrings matching shorter patterns
    sha256_matches = _dedupe_preserving_order(_SHA256_RE.findall(text))
    sha256_set = set(h.lower() for h in sha256_matches)
    for h in sha256_matches:
        collection.hashes.append(IOC(type="hash_sha256", value=h, context="SHA256 hash"))

    sha1_matches = _dedupe_preserving_order(_SHA1_RE.findall(text))
    for h in sha1_matches:
        # Skip if this is a substring of a SHA256
        if not any(h.lower() in s for s in sha256_set):
            collection.hashes.append(IOC(type="hash_sha1", value=h, context="SHA1 hash"))

    sha1_set = set(h.lower() for h in sha1_matches)
    md5_matches = _dedupe_preserving_order(_MD5_RE.findall(text))
    for h in md5_matches:
        if not any(h.lower() in s for s in sha256_set) and not any(h.lower() in s for s in sha1_set):
            collection.hashes.append(IOC(type="hash_md5", value=h, context="MD5 hash"))

    # --- IP addresses ---
    raw_ips = _dedupe_preserving_order(_IP_RE.findall(text))
    for ip in raw_ips:
        collection.ip_addresses.append(
            IOC(type="ip", value=ip, context=_classify_ip(ip))
        )

    # --- Domains (skip those already captured from URLs) ---
    raw_domains = _dedupe_preserving_order(_DOMAIN_RE.findall(text))
    for domain in raw_domains:
        clean = domain.replace('[.]', '.')
        if clean.lower() not in url_domains:
            # Skip common false positives
            if not _is_noise_domain(clean):
                collection.domains.append(
                    IOC(type="domain", value=domain, context="Domain found in log data")
                )

    # --- Email addresses ---
    raw_emails = _dedupe_preserving_order(_EMAIL_RE.findall(text))
    for email in raw_emails:
        collection.emails.append(IOC(type="email", value=email, context="Email address found in log data"))

    # --- Filenames ---
    raw_filenames = _dedupe_preserving_order(_FILENAME_RE.findall(text))
    for fname in raw_filenames:
        collection.filenames.append(
            IOC(type="filename", value=fname, context="Suspicious filename detected")
        )

    # --- CVEs ---
    raw_cves = _dedupe_preserving_order(_CVE_RE.findall(text))
    for cve in raw_cves:
        collection.cves.append(IOC(type="cve", value=cve.upper(), context="CVE reference"))

    return collection


def _is_noise_domain(domain: str) -> bool:
    """Filter out domains that are almost certainly false positives."""
    noise = {
        "schema.org", "www.w3.org", "w3.org", "xmlns.com",
        "purl.org", "example.com", "localhost.localdomain",
    }
    # Also skip if it looks like a file extension pattern (e.g., "file.exe")
    if domain.count('.') == 1 and len(domain.split('.')[0]) <= 3:
        return True
    return domain.lower() in noise
