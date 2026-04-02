"""
Severity scoring — deterministic severity assessment based on IOC signals.

Provides a baseline severity that complements the AI classification.
"""

from app.models.ioc import IOCCollection


# Weights for severity calculation
_WEIGHTS = {
    "external_ips": 2,
    "hashes": 3,
    "urls": 2,
    "suspicious_filenames": 4,
    "cves": 3,
    "emails": 1,
    "domains": 1,
}

# Keyword signals that bump severity
_CRITICAL_KEYWORDS = [
    "ransomware", "encrypt", "exfiltrat", "c2", "command and control",
    "lateral movement", "privilege escalation", "zero-day", "0day",
    "rootkit", "backdoor", "data breach", "credential dump",
]

_HIGH_KEYWORDS = [
    "malware", "trojan", "exploit", "phishing", "brute force",
    "unauthorized access", "suspicious", "blocked", "quarantine",
    "payload", "dropper", "reverse shell", "webshell",
]


def calculate_severity_score(iocs: IOCCollection, raw_text: str) -> dict:
    """
    Calculate a deterministic severity score from IOCs and keyword signals.

    Returns:
        dict with 'score' (0-100), 'level' (str), and 'signals' (list of reasons)
    """
    score = 0
    signals = []
    text_lower = raw_text.lower()

    # IOC-based scoring
    ext_ip_count = sum(1 for ioc in iocs.ip_addresses if ioc.context != "Internal/private IP address")
    if ext_ip_count > 0:
        score += ext_ip_count * _WEIGHTS["external_ips"]
        signals.append(f"{ext_ip_count} external IP(s) detected")

    if iocs.hashes:
        score += len(iocs.hashes) * _WEIGHTS["hashes"]
        signals.append(f"{len(iocs.hashes)} file hash(es) found")

    if iocs.urls:
        score += len(iocs.urls) * _WEIGHTS["urls"]
        signals.append(f"{len(iocs.urls)} URL(s) detected")

    if iocs.filenames:
        score += len(iocs.filenames) * _WEIGHTS["suspicious_filenames"]
        signals.append(f"{len(iocs.filenames)} suspicious filename(s)")

    if iocs.cves:
        score += len(iocs.cves) * _WEIGHTS["cves"]
        signals.append(f"{len(iocs.cves)} CVE reference(s)")

    # Keyword-based scoring
    for kw in _CRITICAL_KEYWORDS:
        if kw in text_lower:
            score += 15
            signals.append(f"Critical keyword detected: '{kw}'")

    for kw in _HIGH_KEYWORDS:
        if kw in text_lower:
            score += 8
            signals.append(f"High-risk keyword detected: '{kw}'")

    # Clamp to 0-100
    score = min(score, 100)

    # Map to severity level
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "INFORMATIONAL"

    return {
        "score": score,
        "level": level,
        "signals": signals,
    }
