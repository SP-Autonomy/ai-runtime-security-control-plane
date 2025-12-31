"""
Security Module

Provides security detection and taint tracking capabilities:
- PII detection and masking
- Injection detection (pattern + ML)
- Taint tracking for data provenance
"""

from airs_cp.security.detectors import (
    PIIDetector,
    PIIMatch,
    get_pii_detector,
    InjectionDetector,
    InjectionMatch,
    get_injection_detector,
)
from airs_cp.security.taint import (
    TaintEngine,
    TaintedData,
    get_taint_engine,
)

__all__ = [
    # PII Detection
    "PIIDetector",
    "PIIMatch",
    "get_pii_detector",
    # Injection Detection
    "InjectionDetector",
    "InjectionMatch",
    "get_injection_detector",
    # Taint Tracking
    "TaintEngine",
    "TaintedData",
    "get_taint_engine",
]
