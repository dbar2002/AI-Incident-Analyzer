"""Timeline and response playbook data models."""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional


class TimelineEvent(BaseModel):
    """Single event in the incident timeline."""
    timestamp: str              # original timestamp from logs, or "Unknown"
    description: str            # what happened
    actor: Optional[str] = None # who/what performed the action
    target: Optional[str] = None  # what was acted upon
    event_type: str             # reconnaissance, delivery, exploitation, installation, c2, action, detection, containment
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW, INFO


class Timeline(BaseModel):
    """Ordered sequence of events reconstructed from logs."""
    events: list[TimelineEvent] = []
    narrative: str = ""         # AI-generated narrative of the attack flow


class PlaybookStep(BaseModel):
    """Single response action in the playbook."""
    phase: str                  # NIST 800-61 phase: Preparation, Detection & Analysis, Containment, Eradication, Recovery, Post-Incident
    action: str                 # what to do
    priority: str               # IMMEDIATE, SHORT_TERM, LONG_TERM
    details: str                # how to do it
    responsible: str            # suggested role (SOC Analyst, IR Lead, System Admin, etc.)


class ResponsePlaybook(BaseModel):
    """NIST 800-61 mapped response recommendations."""
    incident_type: str
    steps: list[PlaybookStep] = []
    containment_strategy: str = ""
    eradication_notes: str = ""
    recovery_notes: str = ""
