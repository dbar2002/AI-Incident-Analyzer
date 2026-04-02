"""Indicator of Compromise (IOC) data models."""

from __future__ import annotations
from pydantic import BaseModel


class IOC(BaseModel):
    """Single indicator of compromise."""
    type: str       # ip, domain, hash_md5, hash_sha1, hash_sha256, email, url, filename, cve
    value: str      # the actual indicator value
    context: str    # where in the log it was found / why it matters


class IOCCollection(BaseModel):
    """Grouped collection of extracted IOCs."""
    ip_addresses: list[IOC] = []
    domains: list[IOC] = []
    hashes: list[IOC] = []
    emails: list[IOC] = []
    urls: list[IOC] = []
    filenames: list[IOC] = []
    cves: list[IOC] = []

    @property
    def total_count(self) -> int:
        return (
            len(self.ip_addresses) + len(self.domains) + len(self.hashes)
            + len(self.emails) + len(self.urls) + len(self.filenames)
            + len(self.cves)
        )
