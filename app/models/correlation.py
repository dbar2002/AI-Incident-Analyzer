"""CVE-IOC correlation data models."""

from __future__ import annotations
from pydantic import BaseModel


class Correlation(BaseModel):
    """A single CVE-to-IOC correlation."""
    cve_id: str
    ioc_type: str           # ip, domain, url, filename, hash, email
    ioc_value: str
    reason: str             # why these are linked
    confidence: str         # HIGH, MEDIUM, LOW


class CorrelationResult(BaseModel):
    """Full correlation output."""
    correlations: list[Correlation] = []
    summary: str = ""

    @property
    def count(self) -> int:
        return len(self.correlations)
