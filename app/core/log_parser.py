"""
Log Parser — Normalize raw security logs into structured format.

Handles common log formats (syslog, CEF, key-value, free-text alerts)
and extracts metadata before AI analysis.
"""

import re
from datetime import datetime
from typing import Optional


class ParsedLog:
    """Structured representation of parsed log data."""

    def __init__(self):
        self.raw_text: str = ""
        self.timestamps: list[str] = []
        self.source_system: Optional[str] = None
        self.log_format: str = "unknown"
        self.line_count: int = 0
        self.char_count: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamps": self.timestamps,
            "source_system": self.source_system,
            "log_format": self.log_format,
            "line_count": self.line_count,
            "char_count": self.char_count,
        }


# Timestamp patterns commonly seen in security logs
_TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-04-01T08:23:17Z
    re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})'),
    # Syslog: Apr  1 08:23:17
    re.compile(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),
    # Common: 2026-04-01 08:23:17
    re.compile(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'),
    # US format: 04/01/2026 08:23:17
    re.compile(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}'),
    # Epoch (10 or 13 digit)
    re.compile(r'\b1[6-7]\d{8}(?:\d{3})?\b'),
]

# Source system identifiers
_SOURCE_PATTERNS = {
    "Splunk": re.compile(r'splunk', re.I),
    "Proofpoint": re.compile(r'proofpoint', re.I),
    "CrowdStrike": re.compile(r'crowdstrike|falcon', re.I),
    "Palo Alto": re.compile(r'palo\s*alto|pan-os|panorama', re.I),
    "Suricata": re.compile(r'suricata', re.I),
    "Snort": re.compile(r'snort', re.I),
    "Windows Event Log": re.compile(r'EventID|Security-Auditing|Microsoft-Windows', re.I),
    "Syslog": re.compile(r'syslog|rsyslog|syslog-ng', re.I),
    "AWS CloudTrail": re.compile(r'cloudtrail|aws', re.I),
    "Azure Sentinel": re.compile(r'sentinel|azure.*security', re.I),
    "QRadar": re.compile(r'qradar', re.I),
}


def detect_log_format(text: str) -> str:
    """Detect the format of the log data."""
    first_lines = text.strip().split('\n')[:5]
    sample = '\n'.join(first_lines)

    # CEF format: CEF:0|vendor|product|...
    if re.search(r'CEF:\d\|', sample):
        return "CEF"

    # LEEF format
    if re.search(r'LEEF:\d', sample):
        return "LEEF"

    # JSON logs
    if sample.strip().startswith('{') or sample.strip().startswith('['):
        return "JSON"

    # Syslog (starts with priority or timestamp)
    if re.match(r'<\d+>', sample) or re.match(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)', sample):
        return "syslog"

    # Key-value pairs (common in security alerts)
    kv_count = len(re.findall(r'\w+\s*[:=]\s*\S+', sample))
    if kv_count > 3:
        return "key-value"

    # Windows Event XML
    if re.search(r'<Event\s', sample) or re.search(r'EventID', sample):
        return "windows_event"

    return "free-text"


def extract_timestamps(text: str) -> list[str]:
    """Extract all timestamps found in the log data."""
    timestamps = []
    for pattern in _TIMESTAMP_PATTERNS:
        matches = pattern.findall(text)
        timestamps.extend(matches)
    # Deduplicate preserving order
    seen = set()
    unique = []
    for ts in timestamps:
        if ts not in seen:
            seen.add(ts)
            unique.append(ts)
    return unique


def detect_source_system(text: str) -> Optional[str]:
    """Identify the source security system/tool."""
    for name, pattern in _SOURCE_PATTERNS.items():
        if pattern.search(text):
            return name
    return None


def parse_logs(raw_text: str) -> ParsedLog:
    """
    Parse raw log/alert text into structured metadata.

    This doesn't replace AI analysis — it extracts deterministic metadata
    that helps the AI provide better classification.
    """
    parsed = ParsedLog()
    parsed.raw_text = raw_text
    parsed.line_count = len(raw_text.strip().split('\n'))
    parsed.char_count = len(raw_text)
    parsed.log_format = detect_log_format(raw_text)
    parsed.timestamps = extract_timestamps(raw_text)
    parsed.source_system = detect_source_system(raw_text)
    return parsed
