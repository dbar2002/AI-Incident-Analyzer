"""Incident data models."""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from .ioc import IOCCollection
from .cve import CVEDetail
from .correlation import CorrelationResult
from .timeline import Timeline, ResponsePlaybook


class AnalysisRequest(BaseModel):
    """Incoming request to analyze raw log/alert data."""
    raw_logs: str
    context: Optional[str] = None  # optional analyst notes


class IncidentClassification(BaseModel):
    """AI-generated incident classification."""
    incident_type: str          # e.g. "Phishing", "Brute Force", "Malware", "Data Exfiltration"
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: float           # 0.0 - 1.0
    summary: str                # 2-3 sentence summary of what happened
    attack_vector: str          # how the attack was delivered
    affected_assets: list[str]  # systems, users, or accounts impacted
    mitre_tactics: list[str]    # MITRE ATT&CK tactic IDs (e.g. TA0001)
    mitre_techniques: list[str] # MITRE ATT&CK technique IDs (e.g. T1566.001)


class AnalysisResponse(BaseModel):
    """Full analysis result returned to the client."""
    id: str
    timestamp: str
    classification: IncidentClassification
    iocs: IOCCollection
    cve_details: list[CVEDetail] = []
    cve_correlations: Optional[CorrelationResult] = None
    timeline: Optional[Timeline] = None
    playbook: Optional[ResponsePlaybook] = None
    raw_input: str
    analysis_duration_ms: int
