"""CVE detail data model."""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional


class CVEDetail(BaseModel):
    """Enriched CVE data from NVD."""
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None       # CRITICAL, HIGH, MEDIUM, LOW
    cvss_vector: Optional[str] = None          # full CVSS vector string
    attack_vector: Optional[str] = None        # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity: Optional[str] = None    # LOW, HIGH
    privileges_required: Optional[str] = None  # NONE, LOW, HIGH
    user_interaction: Optional[str] = None     # NONE, REQUIRED
    affected_products: list[str] = []
    published_date: Optional[str] = None
    last_modified: Optional[str] = None
    references: list[str] = []
    weaknesses: list[str] = []                 # CWE IDs
    known_exploited: bool = False              # in CISA KEV
    exploit_maturity: Optional[str] = None
