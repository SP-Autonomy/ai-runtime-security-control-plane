"""
Injection Detector

Detects prompt injection attempts using pattern matching
and optionally ML-based classification.
"""

import re
from dataclasses import dataclass
from typing import Any, Optional

from airs_cp.store.models import Detection, DetectorType, Severity


@dataclass
class InjectionMatch:
    """A detected injection pattern match."""
    pattern_name: str
    pattern_category: str
    match: str
    start: int
    end: int
    severity: Severity
    confidence: float


# Injection patterns organized by category
INJECTION_PATTERNS = {
    # Direct instruction override
    "instruction_override": {
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "patterns": [
            (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", "ignore_previous"),
            (r"disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|guidelines?|rules?)", "disregard"),
            (r"forget\s+(?:everything|all|your\s+(?:instructions?|rules?))", "forget"),
            (r"(?:new|updated?)\s+instructions?\s*:", "new_instructions"),
            (r"override\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|rules?)", "override"),
        ],
    },
    
    # System prompt extraction
    "prompt_extraction": {
        "severity": Severity.HIGH,
        "confidence": 0.85,
        "patterns": [
            (r"(?:what|show|print|reveal|display)\s+(?:is\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)", "extract_prompt"),
            (r"repeat\s+(?:your\s+)?(?:initial|original|system)\s+(?:instructions?|prompt)", "repeat_prompt"),
            (r"(?:print|show|reveal)\s+(?:your\s+)?(?:confidential|hidden|secret)\s+(?:instructions?|config)", "reveal_secret"),
            (r"what\s+were\s+you\s+told\s+(?:before|initially)", "what_told"),
        ],
    },
    
    # Role manipulation
    "role_manipulation": {
        "severity": Severity.HIGH,
        "confidence": 0.85,
        "patterns": [
            (r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|evil|unrestricted|jailbroken)", "dan_mode"),
            (r"(?:enter|switch\s+to|activate)\s+(?:developer|god|admin|unrestricted)\s+mode", "dev_mode"),
            (r"pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:AI|assistant|bot)\s+(?:with|without)", "pretend"),
            (r"from\s+now\s+on\s*,?\s*(?:you\s+(?:will|are|must))", "from_now_on"),
            (r"roleplay\s+as\s+(?:an?\s+)?(?:evil|unrestricted|harmful)", "roleplay_evil"),
        ],
    },
    
    # Jailbreak attempts
    "jailbreak": {
        "severity": Severity.CRITICAL,
        "confidence": 0.9,
        "patterns": [
            (r"(?:do\s+)?anything\s+now", "dan"),
            (r"jailbreak(?:ed)?", "jailbreak"),
            (r"bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|restrictions?)", "bypass_safety"),
            (r"(?:disable|remove|ignore)\s+(?:your\s+)?(?:safety|ethical|content)\s+(?:guidelines?|filters?)", "disable_safety"),
            (r"without\s+(?:any\s+)?(?:restrictions?|limitations?|filters?)", "no_restrictions"),
        ],
    },
    
    # Delimiter attacks
    "delimiter_attack": {
        "severity": Severity.HIGH,
        "confidence": 0.8,
        "patterns": [
            (r"<\|?(?:system|endoftext|im_start)\|?>", "special_token"),
            (r"\[(?:SYSTEM|INST|/INST)\]", "bracket_token"),
            (r"```(?:system|instruction|prompt)", "code_block_token"),
            (r"###\s*(?:SYSTEM|INSTRUCTION|END)", "markdown_token"),
        ],
    },
    
    # Hypothetical scenarios (often used to bypass)
    "hypothetical": {
        "severity": Severity.MEDIUM,
        "confidence": 0.6,
        "patterns": [
            (r"(?:hypothetically|theoretically|in\s+theory)", "hypothetical"),
            (r"(?:imagine|suppose|assume)\s+(?:you\s+(?:had|have|could)|there\s+were\s+no)", "imagine"),
            (r"for\s+(?:educational|research|academic)\s+purposes?\s+only", "educational"),
            (r"in\s+(?:an?\s+)?(?:alternate|parallel|fictional)\s+(?:universe|world|scenario)", "alternate_universe"),
        ],
    },
    
    # Obfuscation attempts
    "obfuscation": {
        "severity": Severity.MEDIUM,
        "confidence": 0.7,
        "patterns": [
            (r"[iI1l][gG][nN][oO0][rR][eE3]", "leet_ignore"),
            (r"(?:i\.g\.n\.o\.r\.e|d\.i\.s\.r\.e\.g\.a\.r\.d)", "dotted"),
            (r"(?:i_g_n_o_r_e|d_i_s_r_e_g_a_r_d)", "underscored"),
        ],
    },
}


class InjectionDetector:
    """
    Detector for prompt injection attempts.
    
    Uses pattern matching with optional ML-based classification
    for enhanced detection.
    """
    
    def __init__(
        self,
        patterns: Optional[dict[str, dict]] = None,
        enabled_categories: Optional[list[str]] = None,
        use_ml: bool = False,
    ):
        """
        Initialize the injection detector.
        
        Args:
            patterns: Custom patterns (defaults to INJECTION_PATTERNS).
            enabled_categories: Categories to enable (all if None).
            use_ml: Whether to use ML classifier for enhanced detection.
        """
        self.patterns = patterns or INJECTION_PATTERNS
        self.enabled_categories = enabled_categories or list(self.patterns.keys())
        self.use_ml = use_ml
        
        # Compile patterns
        self._compiled: dict[str, list[tuple[re.Pattern, str, float, Severity]]] = {}
        for category, config in self.patterns.items():
            if category in self.enabled_categories:
                self._compiled[category] = []
                for pattern, name in config["patterns"]:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self._compiled[category].append((
                        compiled,
                        name,
                        config["confidence"],
                        config["severity"],
                    ))
    
    def detect(self, text: str) -> list[InjectionMatch]:
        """
        Detect injection patterns in text.
        
        Args:
            text: Text to analyze.
            
        Returns:
            List of InjectionMatch objects.
        """
        matches = []
        
        for category, patterns in self._compiled.items():
            for pattern, name, confidence, severity in patterns:
                for match in pattern.finditer(text):
                    matches.append(InjectionMatch(
                        pattern_name=name,
                        pattern_category=category,
                        match=match.group(),
                        start=match.start(),
                        end=match.end(),
                        severity=severity,
                        confidence=confidence,
                    ))
        
        # Sort by position
        matches.sort(key=lambda m: m.start)
        
        return matches
    
    def analyze(self, text: str) -> dict[str, Any]:
        """
        Analyze text for injection attempts.
        
        Args:
            text: Text to analyze.
            
        Returns:
            Analysis results with matches and risk assessment.
        """
        # Pattern-based detection
        matches = self.detect(text)
        
        # ML-based detection if enabled
        ml_result = None
        if self.use_ml:
            try:
                from airs_cp.ml.classifier import get_injection_classifier
                classifier = get_injection_classifier()
                if classifier:
                    ml_result = classifier.predict(text)
            except Exception:
                pass
        
        # Calculate combined score
        pattern_score = 0.0
        if matches:
            # Weight by severity and confidence
            severity_weights = {
                Severity.LOW: 0.25,
                Severity.MEDIUM: 0.5,
                Severity.HIGH: 0.75,
                Severity.CRITICAL: 1.0,
            }
            for match in matches:
                pattern_score += severity_weights[match.severity] * match.confidence
            pattern_score = min(1.0, pattern_score)
        
        ml_score = ml_result["probability_injection"] if ml_result else 0.0
        
        # Combined score (weighted average)
        if ml_result:
            combined_score = 0.4 * pattern_score + 0.6 * ml_score
        else:
            combined_score = pattern_score
        
        # Determine if injection
        is_injection = combined_score >= 0.5 or any(
            m.severity in [Severity.HIGH, Severity.CRITICAL] and m.confidence >= 0.8
            for m in matches
        )
        
        # Max severity
        max_severity = Severity.LOW
        if matches:
            severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            for match in matches:
                if severity_order.index(match.severity) > severity_order.index(max_severity):
                    max_severity = match.severity
        
        # Group by category
        by_category: dict[str, list] = {}
        for match in matches:
            if match.pattern_category not in by_category:
                by_category[match.pattern_category] = []
            by_category[match.pattern_category].append({
                "pattern": match.pattern_name,
                "match": match.match[:50] + "..." if len(match.match) > 50 else match.match,
                "location": f"char {match.start}-{match.end}",
            })
        
        return {
            "is_injection": is_injection,
            "combined_score": combined_score,
            "pattern_score": pattern_score,
            "ml_score": ml_score,
            "max_severity": max_severity.value,
            "match_count": len(matches),
            "categories_matched": list(by_category.keys()),
            "matches": [
                {
                    "category": m.pattern_category,
                    "pattern": m.pattern_name,
                    "severity": m.severity.value,
                    "confidence": m.confidence,
                    "location": f"char {m.start}-{m.end}",
                }
                for m in matches
            ],
            "by_category": by_category,
            "ml_result": ml_result,
        }
    
    def to_detection(
        self,
        text: str,
        event_id: str,
    ) -> Optional[Detection]:
        """
        Create a Detection object from injection analysis.
        
        Args:
            text: Text that was analyzed.
            event_id: ID of the associated event.
            
        Returns:
            Detection object or None if no injection detected.
        """
        analysis = self.analyze(text)
        
        if not analysis["is_injection"]:
            return None
        
        return Detection(
            event_id=event_id,
            detector_type=DetectorType.INJECTION,
            detector_name="injection_detector",
            severity=Severity(analysis["max_severity"]),
            confidence=analysis["combined_score"],
            signals=analysis["matches"],
            raw_score=analysis["combined_score"],
            threshold=0.5,
            metadata={
                "pattern_score": analysis["pattern_score"],
                "ml_score": analysis["ml_score"],
                "categories": analysis["categories_matched"],
            },
        )


# Default detector instance
_detector: Optional[InjectionDetector] = None


def get_injection_detector(use_ml: bool = False) -> InjectionDetector:
    """Get the global injection detector instance."""
    global _detector
    if _detector is None or _detector.use_ml != use_ml:
        _detector = InjectionDetector(use_ml=use_ml)
    return _detector
