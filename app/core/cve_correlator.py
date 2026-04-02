"""
CVE-IOC Correlator — Links extracted CVEs to related IOCs.

When a CVE is found, this module examines the affected products,
attack vector, and vulnerability details to identify which IOCs
in the incident are likely connected to the exploitation of that CVE.
"""

import re
import logging
from typing import Optional
from app.models.cve import CVEDetail
from app.models.ioc import IOC, IOCCollection
from app.models.correlation import Correlation, CorrelationResult

logger = logging.getLogger(__name__)


# Product name → filename/process patterns that indicate that product
_PRODUCT_SIGNATURES = {
    "outlook": [
        r"outlook\.exe", r"OUTLOOK\.EXE",
    ],
    "word": [
        r"winword\.exe", r"WINWORD\.EXE", r"\.docm?\b", r"\.docx?\b",
    ],
    "excel": [
        r"excel\.exe", r"EXCEL\.EXE", r"\.xlsm?\b", r"\.xlsx?\b",
    ],
    "powerpoint": [
        r"powerpnt\.exe", r"POWERPNT\.EXE", r"\.pptm?\b",
    ],
    "powershell": [
        r"powershell\.exe", r"pwsh\.exe", r"\.ps1\b",
    ],
    "cmd": [
        r"cmd\.exe",
    ],
    "adobe": [
        r"acrobat", r"acrord32\.exe", r"reader\.exe",
    ],
    "java": [
        r"java\.exe", r"javaw\.exe", r"\.jar\b",
    ],
    "apache": [
        r"httpd", r"apache2?",
    ],
    "nginx": [
        r"nginx",
    ],
    "sshd": [
        r"sshd", r"ssh\b",
    ],
    "chrome": [
        r"chrome\.exe",
    ],
    "firefox": [
        r"firefox\.exe",
    ],
    "windows": [
        r"svchost\.exe", r"explorer\.exe", r"lsass\.exe",
        r"csrss\.exe", r"wscript\.exe", r"cscript\.exe",
        r"mshta\.exe", r"regsvr32\.exe", r"rundll32\.exe",
    ],
}


def _match_product_to_iocs(
    product_name: str,
    iocs: IOCCollection,
    raw_logs: str,
) -> list[tuple[str, str, str]]:
    """
    Check if a CVE's affected product matches any IOCs or log content.

    Returns list of (ioc_type, ioc_value, reason) tuples.
    """
    matches = []
    product_lower = product_name.lower()

    # Check filenames against known product signatures
    for product_key, patterns in _PRODUCT_SIGNATURES.items():
        if product_key in product_lower:
            for ioc in iocs.filenames:
                for pattern in patterns:
                    if re.search(pattern, ioc.value, re.IGNORECASE):
                        matches.append((
                            "filename",
                            ioc.value,
                            f"File '{ioc.value}' is associated with {product_name}"
                        ))
                        break

            # Also check if the product appears in the raw logs near IOCs
            for pattern in patterns:
                if re.search(pattern, raw_logs, re.IGNORECASE):
                    # Found the product in logs — now correlate with nearby network IOCs
                    for ioc in iocs.urls:
                        matches.append((
                            "url",
                            ioc.value,
                            f"{product_name} activity detected in logs alongside this URL"
                        ))
                    break

    return matches


def _correlate_network_vector(
    cve: CVEDetail,
    iocs: IOCCollection,
) -> list[tuple[str, str, str]]:
    """If CVE has NETWORK attack vector, correlate with external IPs and URLs."""
    matches = []

    if cve.attack_vector and cve.attack_vector.upper() == "NETWORK":
        for ioc in iocs.ip_addresses:
            if ioc.context != "Internal/private IP address":
                matches.append((
                    "ip",
                    ioc.value,
                    f"{cve.cve_id} uses NETWORK attack vector — external IP may be exploitation source"
                ))

        for ioc in iocs.urls:
            matches.append((
                "url",
                ioc.value,
                f"{cve.cve_id} uses NETWORK attack vector — URL may deliver exploit payload"
            ))

        for ioc in iocs.domains:
            matches.append((
                "domain",
                ioc.value,
                f"{cve.cve_id} uses NETWORK attack vector — domain may be involved in exploitation"
            ))

    return matches


def _correlate_exploit_artifacts(
    cve: CVEDetail,
    iocs: IOCCollection,
    raw_logs: str,
) -> list[tuple[str, str, str]]:
    """Correlate known exploit patterns with IOC artifacts."""
    matches = []

    # If CVE is known exploited, all hashes are suspicious
    if cve.known_exploited:
        for ioc in iocs.hashes:
            matches.append((
                "hash",
                ioc.value,
                f"{cve.cve_id} is a known exploited vulnerability — file hash may be exploit payload"
            ))

        for ioc in iocs.filenames:
            matches.append((
                "filename",
                ioc.value,
                f"{cve.cve_id} is actively exploited — file may be related to exploitation"
            ))

    return matches


def correlate_cves_to_iocs(
    cve_details: list[CVEDetail],
    iocs: IOCCollection,
    raw_logs: str,
) -> CorrelationResult:
    """
    Run CVE-IOC correlation across all enriched CVEs.

    Examines affected products, attack vectors, and exploit status
    to find connections between CVEs and the IOCs in the incident.
    """
    all_correlations = []
    seen = set()  # dedupe by (cve_id, ioc_value)

    for cve in cve_details:
        # Product-based correlation
        for product in cve.affected_products:
            for ioc_type, ioc_value, reason in _match_product_to_iocs(product, iocs, raw_logs):
                key = (cve.cve_id, ioc_value)
                if key not in seen:
                    seen.add(key)
                    all_correlations.append(Correlation(
                        cve_id=cve.cve_id,
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        reason=reason,
                        confidence="HIGH",
                    ))

        # Network vector correlation
        for ioc_type, ioc_value, reason in _correlate_network_vector(cve, iocs):
            key = (cve.cve_id, ioc_value)
            if key not in seen:
                seen.add(key)
                all_correlations.append(Correlation(
                    cve_id=cve.cve_id,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    reason=reason,
                    confidence="MEDIUM",
                ))

        # Exploit artifact correlation
        for ioc_type, ioc_value, reason in _correlate_exploit_artifacts(cve, iocs, raw_logs):
            key = (cve.cve_id, ioc_value)
            if key not in seen:
                seen.add(key)
                all_correlations.append(Correlation(
                    cve_id=cve.cve_id,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    reason=reason,
                    confidence="HIGH",
                ))

    # Build summary
    if all_correlations:
        cve_ids = list(set(c.cve_id for c in all_correlations))
        high_count = sum(1 for c in all_correlations if c.confidence == "HIGH")
        summary = (
            f"Found {len(all_correlations)} correlation(s) linking "
            f"{len(cve_ids)} CVE(s) to extracted IOCs. "
            f"{high_count} high-confidence link(s) detected."
        )
    else:
        summary = "No direct correlations found between CVEs and extracted IOCs."

    logger.info(f"CVE-IOC correlation: {len(all_correlations)} links found")

    return CorrelationResult(
        correlations=all_correlations,
        summary=summary,
    )
