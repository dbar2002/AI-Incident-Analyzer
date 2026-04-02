"""
AI Analyzer Service — Claude API integration for incident classification.

Sends preprocessed log data + extracted IOCs to Claude for intelligent
classification, MITRE ATT&CK mapping, and summary generation.
"""

import json
import logging
from anthropic import Anthropic
from app.config import settings
from app.models.incident import IncidentClassification
from app.models.ioc import IOCCollection

logger = logging.getLogger(__name__)

# System prompt that defines the AI's role and output format
_SYSTEM_PROMPT = """You are an expert Security Incident Response analyst with 15+ years of experience.
You are given raw security log/alert data along with pre-extracted IOCs (Indicators of Compromise).

Your job is to analyze the data and provide a structured incident classification.

You MUST respond with valid JSON only — no markdown, no explanation, no preamble.

JSON schema:
{
    "incident_type": "string — one of: Phishing, Malware, Brute Force, Data Exfiltration, Insider Threat, Denial of Service, Web Application Attack, Credential Compromise, Lateral Movement, Ransomware, Supply Chain, Reconnaissance, Other",
    "severity": "string — one of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
    "confidence": "float 0.0-1.0 — your confidence in this classification",
    "summary": "string — 2-3 sentence summary of the incident in plain English",
    "attack_vector": "string — how the attack was initiated or delivered",
    "affected_assets": ["list of affected systems, users, or accounts"],
    "mitre_tactics": ["list of MITRE ATT&CK tactic IDs, e.g. TA0001"],
    "mitre_techniques": ["list of MITRE ATT&CK technique IDs, e.g. T1566.001"]
}

Guidelines:
- Base your classification on the actual evidence in the logs, not assumptions
- If the data is ambiguous, state that in the summary and lower your confidence
- Map to specific MITRE ATT&CK tactics and techniques — be precise, not generic
- The severity should reflect potential business impact
- List ALL affected assets you can identify from the data
"""


def _build_analysis_prompt(raw_logs: str, iocs: IOCCollection, log_metadata: dict) -> str:
    """Build the user prompt with all preprocessed context."""
    ioc_summary = []
    if iocs.ip_addresses:
        ioc_summary.append(f"IP Addresses: {', '.join(i.value for i in iocs.ip_addresses)}")
    if iocs.domains:
        ioc_summary.append(f"Domains: {', '.join(i.value for i in iocs.domains)}")
    if iocs.hashes:
        ioc_summary.append(f"Hashes: {', '.join(i.value for i in iocs.hashes)}")
    if iocs.urls:
        ioc_summary.append(f"URLs: {', '.join(i.value for i in iocs.urls)}")
    if iocs.emails:
        ioc_summary.append(f"Emails: {', '.join(i.value for i in iocs.emails)}")
    if iocs.filenames:
        ioc_summary.append(f"Filenames: {', '.join(i.value for i in iocs.filenames)}")
    if iocs.cves:
        ioc_summary.append(f"CVEs: {', '.join(i.value for i in iocs.cves)}")

    prompt = f"""Analyze the following security incident data.

--- LOG METADATA ---
Format: {log_metadata.get('log_format', 'unknown')}
Source System: {log_metadata.get('source_system', 'unknown')}
Lines: {log_metadata.get('line_count', 'unknown')}
Timestamps found: {', '.join(log_metadata.get('timestamps', [])[:10]) or 'none'}

--- PRE-EXTRACTED IOCs ({iocs.total_count} total) ---
{chr(10).join(ioc_summary) if ioc_summary else 'No IOCs extracted'}

--- RAW LOG DATA ---
{raw_logs[:8000]}
"""
    return prompt


async def classify_incident(
    raw_logs: str,
    iocs: IOCCollection,
    log_metadata: dict,
) -> IncidentClassification:
    """
    Send preprocessed data to Claude for AI-powered classification.

    Args:
        raw_logs: Original raw log/alert text
        iocs: Pre-extracted IOC collection
        log_metadata: Parsed log metadata (format, timestamps, source)

    Returns:
        IncidentClassification with AI-generated analysis
    """
    if not settings.is_api_configured:
        logger.warning("Anthropic API key not configured — returning mock classification")
        return _mock_classification(raw_logs, iocs)

    client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    prompt = _build_analysis_prompt(raw_logs, iocs, log_metadata)

    try:
        response = client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=settings.AI_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        # Extract text response
        raw_response = response.content[0].text.strip()

        # Clean any markdown fencing the model might add
        if raw_response.startswith("```"):
            raw_response = raw_response.split("\n", 1)[1]
            if raw_response.endswith("```"):
                raw_response = raw_response[:-3]
            raw_response = raw_response.strip()

        data = json.loads(raw_response)
        return IncidentClassification(**data)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response as JSON: {e}")
        logger.debug(f"Raw response: {raw_response}")
        return _mock_classification(raw_logs, iocs)
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return _mock_classification(raw_logs, iocs)


def _mock_classification(raw_logs: str, iocs: IOCCollection) -> IncidentClassification:
    """
    Fallback classification when AI is unavailable.
    Uses simple heuristics so the app still functions for demos.
    """
    text_lower = raw_logs.lower()

    # Simple keyword-based classification
    if any(kw in text_lower for kw in ["phish", "spoof", "spoofed email"]):
        incident_type = "Phishing"
    elif any(kw in text_lower for kw in ["brute force", "failed login", "authentication failure"]):
        incident_type = "Brute Force"
    elif any(kw in text_lower for kw in ["malware", "trojan", "virus", "ransomware"]):
        incident_type = "Malware"
    elif any(kw in text_lower for kw in ["exfiltrat", "data leak", "upload"]):
        incident_type = "Data Exfiltration"
    else:
        incident_type = "Unknown"

    return IncidentClassification(
        incident_type=incident_type,
        severity="MEDIUM",
        confidence=0.3,
        summary=f"[MOCK — API key not configured] Heuristic classification based on keyword analysis. "
                f"Detected {iocs.total_count} IOCs. Configure your Anthropic API key for AI-powered analysis.",
        attack_vector="Unable to determine without AI analysis",
        affected_assets=[],
        mitre_tactics=[],
        mitre_techniques=[],
    )
