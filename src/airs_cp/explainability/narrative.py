"""
LLM Narrative Generator

Generates human-readable explanations for security decisions
using local LLM (via Ollama or other providers).
"""

import json
from typing import Any, Optional

from airs_cp.store.models import (
    Detection,
    Action,
    Explanation,
    ExplanationType,
    Severity,
)


# Narrative generation prompt template
NARRATIVE_PROMPT = """You are a security analyst. Generate a clear, factual explanation of this security decision.

Context:
- Session: {session_id}
- Event Type: {event_type}
- Detection: {detector_name} ({detector_type})
- Severity: {severity}
- Confidence: {confidence:.1%}
- Action Taken: {action_type}

Detection Signals:
{signals}

Requirements:
1. State what was detected in one sentence
2. Explain why it triggered an alert in 1-2 sentences
3. Describe the action taken in one sentence
4. Provide one recommendation if applicable

Keep the explanation concise (2-3 short paragraphs). Use professional but accessible language."""


class NarrativeGenerator:
    """
    Generates human-readable narratives for security decisions.
    
    Uses local LLM for complex explanations and template-based
    generation for simpler cases.
    """
    
    def __init__(
        self,
        use_llm: bool = True,
        model: str = "llama3.2:1b",
        gateway_url: str = "http://localhost:8080",
    ):
        """
        Initialize the narrative generator.
        
        Args:
            use_llm: Whether to use LLM for generation.
            model: Model to use for LLM generation.
            gateway_url: URL of the AIRS-CP gateway (for LLM calls).
        """
        self.use_llm = use_llm
        self.model = model
        self.gateway_url = gateway_url
    
    def generate(
        self,
        detection: Detection,
        action: Optional[Action] = None,
        session_id: str = "unknown",
        use_llm: Optional[bool] = None,
    ) -> dict[str, Any]:
        """
        Generate a narrative explanation for a security decision.
        
        Args:
            detection: The detection that triggered the alert.
            action: The action taken (if any).
            session_id: Session identifier for context.
            use_llm: Override LLM usage setting.
            
        Returns:
            Narrative explanation with summary and details.
        """
        should_use_llm = use_llm if use_llm is not None else self.use_llm
        
        if should_use_llm and detection.severity in [Severity.HIGH, Severity.CRITICAL]:
            try:
                return self._generate_llm_narrative(detection, action, session_id)
            except Exception:
                pass
        
        return self._generate_template_narrative(detection, action, session_id)
    
    def _generate_template_narrative(
        self,
        detection: Detection,
        action: Optional[Action],
        session_id: str,
    ) -> dict[str, Any]:
        """Generate narrative using templates (fast, no LLM required)."""
        
        # Detection type descriptions
        detector_descriptions = {
            "pii_detector": "Personally Identifiable Information (PII)",
            "injection_detector": "a prompt injection attempt",
            "anomaly_detector": "anomalous request patterns",
        }
        
        # Severity descriptions
        severity_descriptions = {
            Severity.LOW: "minor security concern",
            Severity.MEDIUM: "moderate security risk",
            Severity.HIGH: "significant security threat",
            Severity.CRITICAL: "critical security violation",
        }
        
        # Action descriptions
        action_descriptions = {
            "allow": "The request was allowed to proceed",
            "block": "The request was blocked",
            "sanitize": "Sensitive content was masked/redacted",
            "quarantine": "The session was quarantined for review",
            "throttle": "Rate limiting was applied",
        }
        
        # Build summary
        what_detected = detector_descriptions.get(
            detection.detector_name,
            detection.detector_name.replace("_", " ")
        )
        
        severity_desc = severity_descriptions.get(
            detection.severity,
            detection.severity.value
        )
        
        summary = f"This request triggered a {severity_desc} alert. "
        summary += f"The {detection.detector_name} detected {what_detected} "
        summary += f"with {detection.confidence:.0%} confidence. "
        
        if action:
            action_desc = action_descriptions.get(
                action.action_type.value,
                action.action_type.value
            )
            summary += f"{action_desc}."
        
        # Build signals description
        signals_list = []
        for signal in detection.signals[:3]:  # Top 3 signals
            if isinstance(signal, dict):
                sig_desc = signal.get("pattern", signal.get("name", str(signal)))
                signals_list.append(f"• {sig_desc}")
        
        # Recommendations
        recommendations = []
        if detection.severity in [Severity.HIGH, Severity.CRITICAL]:
            recommendations.append("Review the source of this request")
        if detection.detector_name == "pii_detector":
            recommendations.append("Verify no sensitive data was exposed")
        if detection.detector_name == "injection_detector":
            recommendations.append("Monitor for repeated attempts from this session")
        
        return {
            "type": "narrative",
            "method": "template",
            "summary": summary,
            "severity": detection.severity.value,
            "signals": signals_list,
            "recommendations": recommendations,
            "metadata": {
                "session_id": session_id,
                "detector": detection.detector_name,
                "confidence": detection.confidence,
            },
        }
    
    def _generate_llm_narrative(
        self,
        detection: Detection,
        action: Optional[Action],
        session_id: str,
    ) -> dict[str, Any]:
        """Generate narrative using LLM (slower, more detailed)."""
        
        # Format signals for prompt
        signals_text = ""
        for i, signal in enumerate(detection.signals[:5], 1):
            if isinstance(signal, dict):
                signals_text += f"{i}. {json.dumps(signal)}\n"
            else:
                signals_text += f"{i}. {signal}\n"
        
        # Build prompt
        prompt = NARRATIVE_PROMPT.format(
            session_id=session_id,
            event_type="request",
            detector_name=detection.detector_name,
            detector_type=detection.detector_type.value,
            severity=detection.severity.value,
            confidence=detection.confidence,
            action_type=action.action_type.value if action else "none",
            signals=signals_text or "No specific signals recorded",
        )
        
        # Call LLM via gateway
        try:
            import httpx
            
            response = httpx.post(
                f"{self.gateway_url}/v1/chat/completions",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 300,
                    "temperature": 0.3,  # Lower temperature for factual output
                },
                timeout=30,
            )
            
            if response.status_code == 200:
                data = response.json()
                llm_response = data["choices"][0]["message"]["content"]
                
                return {
                    "type": "narrative",
                    "method": "llm",
                    "model": self.model,
                    "summary": llm_response,
                    "severity": detection.severity.value,
                    "recommendations": self._extract_recommendations(llm_response),
                    "metadata": {
                        "session_id": session_id,
                        "detector": detection.detector_name,
                        "confidence": detection.confidence,
                    },
                }
        except Exception:
            pass
        
        # Fallback to template
        return self._generate_template_narrative(detection, action, session_id)
    
    def _extract_recommendations(self, text: str) -> list[str]:
        """Extract recommendations from LLM response."""
        recommendations = []
        
        # Look for recommendation patterns
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if any(kw in line.lower() for kw in ["recommend", "suggest", "should", "consider"]):
                # Clean up the line
                clean = line.lstrip("•-*123456789. ")
                if clean and len(clean) > 10:
                    recommendations.append(clean)
        
        return recommendations[:3]  # Max 3 recommendations
    
    def to_explanation(
        self,
        narrative_result: dict[str, Any],
        detection_id: Optional[str] = None,
        action_id: Optional[str] = None,
    ) -> Explanation:
        """
        Create Explanation object from narrative result.
        
        Args:
            narrative_result: Result from generate method.
            detection_id: Associated detection ID.
            action_id: Associated action ID.
            
        Returns:
            Explanation object.
        """
        return Explanation(
            detection_id=detection_id,
            action_id=action_id,
            explanation_type=ExplanationType.NARRATIVE,
            content=narrative_result,
        )


# Global generator instance
_generator: Optional[NarrativeGenerator] = None


def get_narrative_generator(
    use_llm: bool = True,
    model: str = "llama3.2:1b",
) -> NarrativeGenerator:
    """Get the global narrative generator instance."""
    global _generator
    if _generator is None:
        _generator = NarrativeGenerator(use_llm=use_llm, model=model)
    return _generator
