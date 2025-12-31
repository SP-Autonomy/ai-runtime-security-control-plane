"""
PII Detector

Detects and optionally masks Personally Identifiable Information
in text using pattern matching.
"""

import re
from dataclasses import dataclass
from typing import Any, Optional

from airs_cp.store.models import Detection, DetectorType, Severity


@dataclass
class PIIMatch:
    """A detected PII match."""
    pattern_name: str
    match: str
    start: int
    end: int
    masked: str
    confidence: float = 1.0


# PII patterns with their masks
PII_PATTERNS = {
    "ssn": {
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "mask": "***-**-****",
        "description": "Social Security Number",
        "severity": Severity.HIGH,
    },
    "ssn_no_dash": {
        "pattern": r"\b\d{9}\b",
        "mask": "*********",
        "description": "SSN without dashes",
        "severity": Severity.HIGH,
        "min_confidence": 0.7,  # Lower confidence - could be other 9-digit numbers
    },
    "credit_card": {
        "pattern": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "mask": "****-****-****-****",
        "description": "Credit Card Number",
        "severity": Severity.HIGH,
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "mask": "[REDACTED EMAIL]",
        "description": "Email Address",
        "severity": Severity.MEDIUM,
    },
    "phone_us": {
        "pattern": r"\b(?:\+1[- ]?)?\(?[0-9]{3}\)?[- ]?[0-9]{3}[- ]?[0-9]{4}\b",
        "mask": "[REDACTED PHONE]",
        "description": "US Phone Number",
        "severity": Severity.MEDIUM,
    },
    "phone_intl": {
        "pattern": r"\b\+[0-9]{1,3}[- ]?[0-9]{4,14}\b",
        "mask": "[REDACTED PHONE]",
        "description": "International Phone Number",
        "severity": Severity.MEDIUM,
    },
    "ip_address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "mask": "[REDACTED IP]",
        "description": "IP Address",
        "severity": Severity.LOW,
    },
    "date_of_birth": {
        "pattern": r"\b(?:DOB|Date of Birth|Birthday)[:\s]*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        "mask": "[REDACTED DOB]",
        "description": "Date of Birth",
        "severity": Severity.MEDIUM,
    },
    "passport": {
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "mask": "[REDACTED PASSPORT]",
        "description": "Passport Number",
        "severity": Severity.HIGH,
        "min_confidence": 0.6,  # Lower confidence - format varies by country
    },
    "drivers_license": {
        "pattern": r"\b(?:DL|License)[:\s#]*[A-Z0-9]{5,15}\b",
        "mask": "[REDACTED LICENSE]",
        "description": "Driver's License",
        "severity": Severity.HIGH,
    },
    "api_key": {
        "pattern": r"\b(?:sk|pk|api)[_-]?(?:live|test)?[_-]?[A-Za-z0-9]{20,}\b",
        "mask": "[REDACTED API KEY]",
        "description": "API Key",
        "severity": Severity.CRITICAL,
    },
    "aws_key": {
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "mask": "[REDACTED AWS KEY]",
        "description": "AWS Access Key",
        "severity": Severity.CRITICAL,
    },
}


class PIIDetector:
    """
    Detector for Personally Identifiable Information.
    
    Uses regular expressions to identify PII patterns
    and can optionally mask detected information.
    """
    
    def __init__(
        self,
        patterns: Optional[dict[str, dict]] = None,
        enabled_patterns: Optional[list[str]] = None,
    ):
        """
        Initialize the PII detector.
        
        Args:
            patterns: Custom patterns to use (defaults to PII_PATTERNS).
            enabled_patterns: List of pattern names to enable (all if None).
        """
        self.patterns = patterns or PII_PATTERNS
        self.enabled_patterns = enabled_patterns or list(self.patterns.keys())
        
        # Compile patterns
        self._compiled: dict[str, re.Pattern] = {}
        for name, config in self.patterns.items():
            if name in self.enabled_patterns:
                self._compiled[name] = re.compile(
                    config["pattern"],
                    re.IGNORECASE if config.get("case_insensitive", True) else 0
                )
    
    def detect(self, text: str) -> list[PIIMatch]:
        """
        Detect PII in text.
        
        Args:
            text: Text to analyze.
            
        Returns:
            List of PIIMatch objects.
        """
        matches = []
        
        for name, pattern in self._compiled.items():
            config = self.patterns[name]
            confidence = config.get("min_confidence", 1.0)
            
            for match in pattern.finditer(text):
                matches.append(PIIMatch(
                    pattern_name=name,
                    match=match.group(),
                    start=match.start(),
                    end=match.end(),
                    masked=config["mask"],
                    confidence=confidence,
                ))
        
        # Sort by position
        matches.sort(key=lambda m: m.start)
        
        return matches
    
    def mask(self, text: str, matches: Optional[list[PIIMatch]] = None) -> str:
        """
        Mask PII in text.
        
        Args:
            text: Text to mask.
            matches: Pre-computed matches (will detect if None).
            
        Returns:
            Text with PII masked.
        """
        if matches is None:
            matches = self.detect(text)
        
        if not matches:
            return text
        
        # Apply masks in reverse order to preserve positions
        result = text
        for match in reversed(matches):
            result = result[:match.start] + match.masked + result[match.end:]
        
        return result
    
    def analyze(self, text: str) -> dict[str, Any]:
        """
        Analyze text for PII and return detailed results.
        
        Args:
            text: Text to analyze.
            
        Returns:
            Analysis results with matches and statistics.
        """
        matches = self.detect(text)
        masked_text = self.mask(text, matches)
        
        # Group by pattern
        by_pattern: dict[str, list[PIIMatch]] = {}
        for match in matches:
            if match.pattern_name not in by_pattern:
                by_pattern[match.pattern_name] = []
            by_pattern[match.pattern_name].append(match)
        
        # Determine max severity
        max_severity = Severity.LOW
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for match in matches:
            pattern_severity = self.patterns[match.pattern_name].get("severity", Severity.LOW)
            if severity_order.index(pattern_severity) > severity_order.index(max_severity):
                max_severity = pattern_severity
        
        return {
            "has_pii": len(matches) > 0,
            "match_count": len(matches),
            "max_severity": max_severity.value,
            "matches": [
                {
                    "pattern": m.pattern_name,
                    "location": f"char {m.start}-{m.end}",
                    "confidence": m.confidence,
                }
                for m in matches
            ],
            "by_pattern": {
                name: len(matches)
                for name, matches in by_pattern.items()
            },
            "masked_text": masked_text,
            "original_length": len(text),
            "masked_length": len(masked_text),
        }
    
    def to_detection(
        self,
        text: str,
        event_id: str,
    ) -> Optional[Detection]:
        """
        Create a Detection object from PII analysis.
        
        Args:
            text: Text that was analyzed.
            event_id: ID of the associated event.
            
        Returns:
            Detection object or None if no PII found.
        """
        analysis = self.analyze(text)
        
        if not analysis["has_pii"]:
            return None
        
        return Detection(
            event_id=event_id,
            detector_type=DetectorType.DLP,
            detector_name="pii_detector",
            severity=Severity(analysis["max_severity"]),
            confidence=max(m["confidence"] for m in analysis["matches"]),
            signals=analysis["matches"],
            metadata={
                "match_count": analysis["match_count"],
                "patterns": analysis["by_pattern"],
            },
        )


# Default detector instance
_detector: Optional[PIIDetector] = None


def get_pii_detector() -> PIIDetector:
    """Get the global PII detector instance."""
    global _detector
    if _detector is None:
        _detector = PIIDetector()
    return _detector
