"""
CVE Lookup Service — Fetches vulnerability details from NIST NVD.

When a CVE is found in incident logs, this service pulls:
- Description of the vulnerability
- CVSS score and severity rating
- Affected products (CPE matches)
- Whether it's in CISA's Known Exploited Vulnerabilities catalog
- Published/modified dates
- References and links
"""

import logging
import httpx
from typing import Optional
from app.models.cve import CVEDetail

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15.0


def _parse_cvss_v31(metrics: dict) -> dict:
    """Extract CVSS v3.1 data from NVD metrics."""
    result = {}
    cvss_list = metrics.get("cvssMetricV31", [])
    if not cvss_list:
        # Fall back to v3.0
        cvss_list = metrics.get("cvssMetricV30", [])
    if not cvss_list:
        return result

    # Use the primary (NVD) score if available
    primary = None
    for entry in cvss_list:
        if entry.get("type") == "Primary":
            primary = entry
            break
    if not primary:
        primary = cvss_list[0]

    cvss_data = primary.get("cvssData", {})
    result["cvss_score"] = cvss_data.get("baseScore")
    result["cvss_severity"] = cvss_data.get("baseSeverity")
    result["cvss_vector"] = cvss_data.get("vectorString")
    result["attack_vector"] = cvss_data.get("attackVector")
    result["attack_complexity"] = cvss_data.get("attackComplexity")
    result["privileges_required"] = cvss_data.get("privilegesRequired")
    result["user_interaction"] = cvss_data.get("userInteraction")
    result["known_exploited"] = primary.get("exploitabilityScore", 0) > 3.5

    return result


def _parse_cvss_v2(metrics: dict) -> dict:
    """Fallback: extract CVSS v2 data."""
    result = {}
    cvss_list = metrics.get("cvssMetricV2", [])
    if not cvss_list:
        return result

    primary = cvss_list[0]
    cvss_data = primary.get("cvssData", {})
    result["cvss_score"] = cvss_data.get("baseScore")
    result["cvss_vector"] = cvss_data.get("vectorString")

    # Map v2 score to severity label
    score = result.get("cvss_score", 0)
    if score >= 9.0:
        result["cvss_severity"] = "CRITICAL"
    elif score >= 7.0:
        result["cvss_severity"] = "HIGH"
    elif score >= 4.0:
        result["cvss_severity"] = "MEDIUM"
    else:
        result["cvss_severity"] = "LOW"

    result["attack_vector"] = cvss_data.get("accessVector")
    result["attack_complexity"] = cvss_data.get("accessComplexity")

    return result


def _extract_affected_products(configurations: list) -> list[str]:
    """Extract affected product names from CPE configurations."""
    products = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    cpe_uri = cpe_match.get("criteria", "")
                    # Parse CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                        entry = f"{vendor} {product}"
                        if version:
                            entry += f" {version}"
                        if entry not in products:
                            products.append(entry)
    return products[:10]  # cap at 10 to keep it manageable


async def lookup_cve(cve_id: str) -> Optional[CVEDetail]:
    """
    Look up a CVE by ID from the NIST NVD API.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-21413")

    Returns:
        CVEDetail with enriched data, or None if lookup fails
    """
    url = f"{NVD_API_BASE}?cveId={cve_id}"

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url)

        if resp.status_code == 404:
            logger.warning(f"CVE not found: {cve_id}")
            return None

        if resp.status_code == 403:
            logger.warning(f"NVD API rate limited while looking up {cve_id}")
            return CVEDetail(
                cve_id=cve_id,
                description="Rate limited by NVD API — try again in a few seconds.",
            )

        if resp.status_code != 200:
            logger.error(f"NVD API returned {resp.status_code} for {cve_id}")
            return None

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get("cve", {})

        # Description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS scores — try v3.1 first, fall back to v2
        metrics = cve_data.get("metrics", {})
        cvss_info = _parse_cvss_v31(metrics)
        if not cvss_info:
            cvss_info = _parse_cvss_v2(metrics)

        # Affected products
        configurations = cve_data.get("configurations", [])
        affected_products = _extract_affected_products(configurations)

        # References
        references = []
        for ref in cve_data.get("references", [])[:8]:
            references.append(ref.get("url", ""))

        # Weaknesses (CWEs)
        weaknesses = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val and cwe_val not in weaknesses:
                    weaknesses.append(cwe_val)

        # Dates
        published = cve_data.get("published", "")[:10]
        modified = cve_data.get("lastModified", "")[:10]

        # Check CISA KEV flag
        known_exploited = cvss_info.get("known_exploited", False)
        # Also check if any reference mentions CISA or "exploited in the wild"
        for ref in cve_data.get("references", []):
            tags = ref.get("tags", [])
            if "Exploit" in tags:
                known_exploited = True
                break

        cve_detail = CVEDetail(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_info.get("cvss_score"),
            cvss_severity=cvss_info.get("cvss_severity"),
            cvss_vector=cvss_info.get("cvss_vector"),
            attack_vector=cvss_info.get("attack_vector"),
            attack_complexity=cvss_info.get("attack_complexity"),
            privileges_required=cvss_info.get("privileges_required"),
            user_interaction=cvss_info.get("user_interaction"),
            affected_products=affected_products,
            published_date=published,
            last_modified=modified,
            references=references,
            weaknesses=weaknesses,
            known_exploited=known_exploited,
        )

        logger.info(
            f"CVE lookup: {cve_id} — CVSS {cve_detail.cvss_score} "
            f"({cve_detail.cvss_severity}), {len(affected_products)} products"
        )
        return cve_detail

    except httpx.TimeoutException:
        logger.error(f"Timeout looking up {cve_id}")
        return CVEDetail(
            cve_id=cve_id,
            description="NVD API request timed out.",
        )
    except Exception as e:
        logger.exception(f"CVE lookup failed for {cve_id}: {e}")
        return None


async def lookup_cves(cve_ids: list[str]) -> list[CVEDetail]:
    """
    Look up multiple CVEs. Returns results for all that succeed.
    """
    results = []
    for cve_id in cve_ids:
        detail = await lookup_cve(cve_id)
        if detail:
            results.append(detail)
    return results
