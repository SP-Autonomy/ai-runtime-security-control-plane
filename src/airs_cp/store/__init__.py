"""
Evidence Store Module

Provides data persistence for security events, detections,
actions, taint tracking, and explanations.
"""

from airs_cp.store.database import EvidenceStore, get_store
from airs_cp.store.models import (
    Action,
    ActionType,
    Detection,
    DetectorType,
    Event,
    EventType,
    Explanation,
    ExplanationType,
    SecurityResult,
    Session,
    Severity,
    TaintEdge,
    TaintLabel,
    TaintSensitivity,
    TaintSourceType,
)

__all__ = [
    # Database
    "EvidenceStore",
    "get_store",
    # Models
    "Session",
    "Event",
    "EventType",
    "Detection",
    "DetectorType",
    "Severity",
    "Action",
    "ActionType",
    "TaintLabel",
    "TaintEdge",
    "TaintSourceType",
    "TaintSensitivity",
    "Explanation",
    "ExplanationType",
    "SecurityResult",
]
