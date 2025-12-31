"""
Behavioral Analyzer

Analyzes agent behavior patterns to detect:
- Unexpected tool selections
- Unusual tool sequences
- Deviation from typical patterns
- Potential security concerns

Uses ML-based anomaly detection (IsolationForest) for real-time scoring.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import json

from airs_cp.observability.registry import get_registry, AgentDefinition, ToolDefinition
from airs_cp.observability.tracker import ToolInvocation, InvocationStatus


class DeviationType(str, Enum):
    """Types of behavioral deviations."""
    UNEXPECTED_TOOL = "unexpected_tool"  # Tool not in agent's allowed list
    UNUSUAL_SEQUENCE = "unusual_sequence"  # Tool order doesn't match pattern
    HIGH_RISK_TOOL = "high_risk_tool"  # Using tool above risk tolerance
    EXCESSIVE_CALLS = "excessive_calls"  # Too many tool calls
    UNEXPECTED_ARGS = "unexpected_args"  # Arguments don't match expected
    SENSITIVITY_VIOLATION = "sensitivity_violation"  # Data sensitivity mismatch
    TIMING_ANOMALY = "timing_anomaly"  # Unusual response time
    UNAUTHORIZED_EXTERNAL = "unauthorized_external"  # Unexpected external access
    ML_ANOMALY = "ml_anomaly"  # ML-detected anomaly


@dataclass
class DeviationAlert:
    """Alert for detected behavioral deviation."""
    
    id: str = field(default_factory=lambda: f"dev_{datetime.utcnow().timestamp():.0f}")
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Context
    session_id: str = ""
    agent_id: str = ""
    tool_id: str = ""
    invocation_id: str = ""
    
    # Deviation details
    deviation_type: DeviationType = DeviationType.UNEXPECTED_TOOL
    severity: str = "medium"  # low, medium, high, critical
    score: float = 0.5  # 0.0 to 1.0
    
    # Explanation
    description: str = ""
    expected_behavior: str = ""
    actual_behavior: str = ""
    reasoning: str = ""  # Why this is concerning
    
    # Recommendations
    recommendations: list[str] = field(default_factory=list)
    
    # Related data
    related_invocations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "invocation_id": self.invocation_id,
            "deviation_type": self.deviation_type.value,
            "severity": self.severity,
            "score": self.score,
            "description": self.description,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "reasoning": self.reasoning,
            "recommendations": self.recommendations,
            "related_invocations": self.related_invocations,
            "metadata": self.metadata,
        }


class BehaviorAnalyzer:
    """
    Analyzes agent behavior and detects deviations.
    
    Uses:
    - Agent definitions for expected behavior
    - Tool definitions for risk assessment
    - ML-based anomaly detection (IsolationForest) for real-time scoring
    - Historical patterns for anomaly detection
    """
    
    def __init__(self, use_ml: bool = True):
        """
        Initialize the behavior analyzer.
        
        Args:
            use_ml: Whether to use ML-based anomaly detection (default True)
        """
        self._alerts: list[DeviationAlert] = []
        self._agent_patterns: dict[str, list[str]] = {}  # agent_id -> [tool sequences]
        self._tool_stats: dict[str, dict] = {}  # tool_id -> stats
        self._use_ml = use_ml
        self._ml_detector = None
        
        # Try to load ML detector
        if use_ml:
            self._load_ml_detector()
    
    def _load_ml_detector(self) -> bool:
        """Load or train the ML anomaly detector."""
        try:
            from airs_cp.ml.anomaly import get_anomaly_detector, AnomalyDetector, set_anomaly_detector
            from pathlib import Path
            
            model_path = Path("./models/anomaly_detector.pkl")
            
            # Try to load existing model
            if model_path.exists():
                self._ml_detector = AnomalyDetector.load(str(model_path))
                return True
            
            # Auto-train if model doesn't exist
            from airs_cp.ml.training import generate_normal_data
            import sys
            
            print("[AIRS-CP] ML model not found, auto-training...", file=sys.stderr)
            
            # Generate training data
            normal_data = generate_normal_data(500)
            
            # Train detector
            self._ml_detector = AnomalyDetector(contamination=0.1)
            self._ml_detector.fit(normal_data)
            
            # Save for future use
            model_path.parent.mkdir(parents=True, exist_ok=True)
            self._ml_detector.save(str(model_path))
            set_anomaly_detector(self._ml_detector)
            
            print("[AIRS-CP] ML model trained and saved", file=sys.stderr)
            return True
            
        except Exception as e:
            import sys
            print(f"[AIRS-CP] ML detector not available: {e}", file=sys.stderr)
            self._ml_detector = None
            return False
    
    def get_ml_anomaly_score(self, text: str) -> Optional[dict]:
        """
        Get ML-based anomaly score for text.
        
        Returns dict with is_anomaly, anomaly_score, features, etc.
        Returns None if ML not available.
        """
        if not self._ml_detector:
            return None
        
        try:
            return self._ml_detector.predict(text)
        except Exception:
            return None
    
    def analyze_invocation(
        self,
        invocation: ToolInvocation,
        session_history: list[ToolInvocation] = None
    ) -> list[DeviationAlert]:
        """
        Analyze a tool invocation for deviations.
        
        Returns list of alerts (may be empty if behavior is normal).
        """
        alerts = []
        registry = get_registry()
        
        agent = registry.get_agent(invocation.agent_id) if invocation.agent_id else None
        tool = registry.get_tool(invocation.tool_id) if invocation.tool_id else None
        
        # Check 1: Unexpected tool selection
        if agent and invocation.tool_id:
            alert = self._check_tool_allowed(agent, invocation)
            if alert:
                alerts.append(alert)
        
        # Check 2: High risk tool usage
        if agent and tool:
            alert = self._check_risk_level(agent, tool, invocation)
            if alert:
                alerts.append(alert)
        
        # Check 3: Unusual sequence (if we have history)
        if session_history and agent:
            alert = self._check_sequence(agent, invocation, session_history)
            if alert:
                alerts.append(alert)
        
        # Check 4: Excessive calls
        if session_history and agent:
            alert = self._check_call_count(agent, invocation, session_history)
            if alert:
                alerts.append(alert)
        
        # Check 5: Unexpected arguments
        if tool and invocation.input_args:
            alert = self._check_arguments(tool, invocation)
            if alert:
                alerts.append(alert)
        
        # Check 6: ML-based anomaly detection on reasoning/intent
        if self._use_ml and self._ml_detector:
            alert = self._check_ml_anomaly(invocation)
            if alert:
                alerts.append(alert)
        
        # Store alerts
        self._alerts.extend(alerts)
        
        # Update invocation with deviation info
        if alerts:
            max_score = max(a.score for a in alerts)
            invocation.was_expected = max_score < 0.5
            invocation.deviation_score = max_score
            invocation.deviation_reasons = [a.description for a in alerts]
        
        return alerts
    
    def _check_ml_anomaly(self, invocation: ToolInvocation) -> Optional[DeviationAlert]:
        """Check for ML-detected anomalies in reasoning or intent.
        
        Uses both:
        - IsolationForest for general anomaly detection
        - Injection classifier for specific injection detection (97.8% accuracy)
        
        Pre-filters text to only run ML on suspicious content to reduce false positives.
        """
        # Analyze the reasoning and intent
        text_to_analyze = f"{invocation.reasoning or ''} {invocation.user_intent or ''}"
        if not text_to_analyze.strip():
            return None
        
        # Pre-filter: Only run ML if text contains suspicious patterns
        # This reduces false positives on normal business text
        suspicious_indicators = [
            "ignore", "disregard", "forget", "override", "bypass",
            "system", "prompt", "instruction", "restriction", "filter",
            "dan", "jailbreak", "roleplay", "pretend", "hypothetically",
            "admin", "sudo", "root", "confidential", "secret",
            "exfiltrate", "leak", "steal", "extract",
        ]
        
        text_lower = text_to_analyze.lower()
        has_suspicious_pattern = any(indicator in text_lower for indicator in suspicious_indicators)
        
        # Skip ML analysis for clearly benign text
        if not has_suspicious_pattern and len(text_to_analyze) < 200:
            return None
        
        anomaly_score = 0.0
        is_anomaly = False
        detection_type = "unknown"
        metadata = {}
        
        # Check 1: IsolationForest anomaly detection
        if self._ml_detector:
            try:
                ml_result = self._ml_detector.predict(text_to_analyze)
                anomaly_score = max(anomaly_score, ml_result["anomaly_score"])
                if ml_result["is_anomaly"] and ml_result["anomaly_score"] >= 0.7:
                    is_anomaly = True
                    detection_type = "isolation_forest"
                metadata["isolation_forest"] = {
                    "score": ml_result["anomaly_score"],
                    "raw_score": ml_result["raw_score"],
                    "threshold": ml_result["threshold"],
                }
            except Exception:
                pass
        
        # Check 2: Injection classifier (97.8% accuracy!)
        try:
            from airs_cp.ml.classifier import get_injection_classifier
            from pathlib import Path
            
            classifier = get_injection_classifier()
            if not classifier:
                # Try to load from file
                classifier_path = Path("./models/injection_classifier.pkl")
                if classifier_path.exists():
                    from airs_cp.ml.classifier import InjectionClassifier, set_injection_classifier
                    classifier = InjectionClassifier.load(str(classifier_path))
                    set_injection_classifier(classifier)
            
            if classifier:
                injection_result = classifier.predict(text_to_analyze)
                injection_prob = injection_result["probability_injection"]
                
                metadata["injection_classifier"] = {
                    "is_injection": injection_result["is_injection"],
                    "probability": injection_prob,
                    "confidence": injection_result.get("confidence", 0),
                }
                
                # Only use injection probability if it's a confident detection (>70%)
                # This reduces false positives on normal business text
                if injection_prob > 0.7 and injection_prob > anomaly_score:
                    anomaly_score = injection_prob
                    if injection_result["is_injection"]:
                        is_anomaly = True
                        detection_type = "injection_classifier"
        except Exception as e:
            pass
        
        # Generate alert if anomaly detected
        # Use higher threshold (0.7) to reduce false positives on normal text
        if is_anomaly and anomaly_score >= 0.7:
            # Determine severity based on score
            if anomaly_score >= 0.9:
                severity = "critical"
            elif anomaly_score >= 0.8:
                severity = "high"
            elif anomaly_score >= 0.6:
                severity = "medium"
            else:
                severity = "low"
            
            # Create description based on detection type
            if detection_type == "injection_classifier":
                description = f"ML detected potential injection attack (probability: {anomaly_score:.0%})"
                reasoning = ("Injection classifier detected patterns consistent with prompt injection "
                           "or jailbreak attempts. The model has 97.8% accuracy on test data.")
            else:
                description = f"ML detected anomalous behavior (score: {anomaly_score:.0%})"
                reasoning = ("IsolationForest model detected this request deviates significantly "
                           "from normal patterns. This could indicate unusual agent behavior.")
            
            return DeviationAlert(
                session_id=invocation.session_id,
                agent_id=invocation.agent_id,
                tool_id=invocation.tool_id,
                invocation_id=invocation.id,
                deviation_type=DeviationType.ML_ANOMALY,
                severity=severity,
                score=anomaly_score,
                description=description,
                expected_behavior="Normal request patterns based on training data",
                actual_behavior=f"Anomaly in: {text_to_analyze[:80]}...",
                reasoning=reasoning,
                recommendations=[
                    "Review the user's original input for potential attacks",
                    "Check if the agent's reasoning makes sense",
                    "Block or flag for human review",
                ],
                metadata=metadata,
            )
        
        return None
    
    def _check_tool_allowed(
        self, 
        agent: AgentDefinition, 
        invocation: ToolInvocation
    ) -> Optional[DeviationAlert]:
        """Check if tool is in agent's allowed list."""
        if not agent.allowed_tools:
            return None  # No restrictions
        
        if invocation.tool_id in agent.allowed_tools:
            return None  # Tool is allowed
        
        return DeviationAlert(
            session_id=invocation.session_id,
            agent_id=invocation.agent_id,
            tool_id=invocation.tool_id,
            invocation_id=invocation.id,
            deviation_type=DeviationType.UNEXPECTED_TOOL,
            severity="high",
            score=0.8,
            description=f"Agent '{agent.name}' called unauthorized tool '{invocation.tool_id}'",
            expected_behavior=f"Agent should only use: {', '.join(agent.allowed_tools)}",
            actual_behavior=f"Attempted to use: {invocation.tool_id}",
            reasoning=f"Tool '{invocation.tool_id}' is not in the agent's approved tool list. "
                     f"This could indicate prompt injection or misconfiguration.",
            recommendations=[
                f"Review if '{invocation.tool_id}' should be added to agent's allowed tools",
                "Check for potential prompt injection in the user input",
                "Verify agent configuration is correct",
            ],
        )
    
    def _check_risk_level(
        self,
        agent: AgentDefinition,
        tool: ToolDefinition,
        invocation: ToolInvocation
    ) -> Optional[DeviationAlert]:
        """Check if tool risk exceeds agent's tolerance."""
        from airs_cp.observability.registry import RiskLevel
        
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        tool_risk_idx = risk_order.index(tool.risk_level)
        agent_tolerance_idx = risk_order.index(agent.risk_tolerance)
        
        if tool_risk_idx <= agent_tolerance_idx:
            return None  # Within tolerance
        
        severity = "medium" if tool_risk_idx - agent_tolerance_idx == 1 else "high"
        score = 0.5 + (tool_risk_idx - agent_tolerance_idx) * 0.15
        
        return DeviationAlert(
            session_id=invocation.session_id,
            agent_id=invocation.agent_id,
            tool_id=invocation.tool_id,
            invocation_id=invocation.id,
            deviation_type=DeviationType.HIGH_RISK_TOOL,
            severity=severity,
            score=min(score, 1.0),
            description=f"Tool risk ({tool.risk_level.value}) exceeds agent tolerance ({agent.risk_tolerance.value})",
            expected_behavior=f"Agent should use tools with risk <= {agent.risk_tolerance.value}",
            actual_behavior=f"Using tool with {tool.risk_level.value} risk",
            reasoning="High-risk tool usage may indicate the agent is being manipulated "
                     "or the task requires elevated privileges.",
            recommendations=[
                "Consider if this tool call is necessary",
                "Add approval workflow for high-risk operations",
                "Review agent's risk tolerance settings",
            ],
        )
    
    def _check_sequence(
        self,
        agent: AgentDefinition,
        invocation: ToolInvocation,
        history: list[ToolInvocation]
    ) -> Optional[DeviationAlert]:
        """Check if tool sequence matches expected patterns."""
        if not agent.typical_tool_sequence:
            return None  # No expected sequence defined
        
        # Build current sequence
        session_tools = [h.tool_id for h in history if h.session_id == invocation.session_id]
        session_tools.append(invocation.tool_id)
        
        # Check against expected patterns
        expected = agent.typical_tool_sequence
        
        # Simple check: is current sequence a prefix of expected?
        if len(session_tools) <= len(expected):
            if session_tools == expected[:len(session_tools)]:
                return None  # Matches expected
        
        # Calculate deviation
        matching = sum(1 for a, b in zip(session_tools, expected) if a == b)
        deviation = 1 - (matching / max(len(session_tools), len(expected)))
        
        if deviation < 0.3:
            return None  # Close enough
        
        return DeviationAlert(
            session_id=invocation.session_id,
            agent_id=invocation.agent_id,
            tool_id=invocation.tool_id,
            invocation_id=invocation.id,
            deviation_type=DeviationType.UNUSUAL_SEQUENCE,
            severity="medium" if deviation < 0.6 else "high",
            score=deviation,
            description=f"Tool sequence deviates {deviation:.0%} from expected pattern",
            expected_behavior=f"Expected sequence: {' → '.join(expected)}",
            actual_behavior=f"Actual sequence: {' → '.join(session_tools)}",
            reasoning="Unusual tool sequences may indicate the agent is confused, "
                     "being manipulated, or handling an edge case.",
            recommendations=[
                "Review the user's original request",
                "Check if the agent's reasoning makes sense",
                "Consider if the expected sequence needs updating",
            ],
        )
    
    def _check_call_count(
        self,
        agent: AgentDefinition,
        invocation: ToolInvocation,
        history: list[ToolInvocation]
    ) -> Optional[DeviationAlert]:
        """Check if tool call count exceeds limits."""
        session_calls = [h for h in history if h.session_id == invocation.session_id]
        call_count = len(session_calls) + 1
        
        if call_count <= agent.max_tool_calls_per_request:
            return None  # Within limit
        
        excess = call_count - agent.max_tool_calls_per_request
        score = min(0.5 + excess * 0.1, 1.0)
        
        return DeviationAlert(
            session_id=invocation.session_id,
            agent_id=invocation.agent_id,
            tool_id=invocation.tool_id,
            invocation_id=invocation.id,
            deviation_type=DeviationType.EXCESSIVE_CALLS,
            severity="medium" if excess <= 2 else "high",
            score=score,
            description=f"Exceeded max tool calls: {call_count}/{agent.max_tool_calls_per_request}",
            expected_behavior=f"Max {agent.max_tool_calls_per_request} tool calls per request",
            actual_behavior=f"Already made {call_count} calls",
            reasoning="Excessive tool calls may indicate the agent is stuck in a loop, "
                     "being manipulated, or the task is too complex.",
            recommendations=[
                "Check if the agent is making progress",
                "Review for potential infinite loops",
                "Consider increasing limit if task legitimately requires more calls",
            ],
        )
    
    def _check_arguments(
        self,
        tool: ToolDefinition,
        invocation: ToolInvocation
    ) -> Optional[DeviationAlert]:
        """Check if arguments match expected schema."""
        if not tool.expected_args:
            return None  # No expected args defined
        
        provided_args = set(invocation.input_args.keys())
        expected_args = set(tool.expected_args)
        
        missing = expected_args - provided_args
        unexpected = provided_args - expected_args
        
        if not missing and not unexpected:
            return None  # Args match
        
        issues = []
        if missing:
            issues.append(f"missing: {', '.join(missing)}")
        if unexpected:
            issues.append(f"unexpected: {', '.join(unexpected)}")
        
        score = (len(missing) + len(unexpected)) / (len(expected_args) + 1)
        
        return DeviationAlert(
            session_id=invocation.session_id,
            agent_id=invocation.agent_id,
            tool_id=invocation.tool_id,
            invocation_id=invocation.id,
            deviation_type=DeviationType.UNEXPECTED_ARGS,
            severity="low" if score < 0.3 else "medium",
            score=min(score, 1.0),
            description=f"Argument mismatch: {'; '.join(issues)}",
            expected_behavior=f"Expected args: {', '.join(tool.expected_args)}",
            actual_behavior=f"Provided args: {', '.join(provided_args)}",
            reasoning="Argument mismatches may cause tool failures or unexpected behavior.",
            recommendations=[
                "Verify tool definition matches actual API",
                "Check agent's understanding of tool requirements",
            ],
        )
    
    def get_alerts(
        self, 
        session_id: str = None,
        min_severity: str = None,
        limit: int = 100
    ) -> list[DeviationAlert]:
        """Get deviation alerts, optionally filtered."""
        alerts = self._alerts[-limit:]
        
        if session_id:
            alerts = [a for a in alerts if a.session_id == session_id]
        
        if min_severity:
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            min_level = severity_order.get(min_severity, 0)
            alerts = [a for a in alerts if severity_order.get(a.severity, 0) >= min_level]
        
        return alerts
    
    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics."""
        if not self._alerts:
            return {"total": 0, "by_type": {}, "by_severity": {}}
        
        by_type = {}
        by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for alert in self._alerts:
            by_type[alert.deviation_type.value] = by_type.get(alert.deviation_type.value, 0) + 1
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        
        return {
            "total": len(self._alerts),
            "by_type": by_type,
            "by_severity": by_severity,
            "avg_score": sum(a.score for a in self._alerts) / len(self._alerts),
        }
    
    def explain_decision(
        self,
        invocation: ToolInvocation,
        agent: AgentDefinition = None,
        tool: ToolDefinition = None
    ) -> dict[str, Any]:
        """
        Generate explanation for why a tool was selected.
        
        Useful for understanding agent behavior.
        """
        registry = get_registry()
        
        if not agent and invocation.agent_id:
            agent = registry.get_agent(invocation.agent_id)
        if not tool and invocation.tool_id:
            tool = registry.get_tool(invocation.tool_id)
        
        explanation = {
            "invocation_id": invocation.id,
            "tool": invocation.tool_id,
            "agent": invocation.agent_id,
            "reasoning": invocation.reasoning or "No reasoning provided",
            "user_intent": invocation.user_intent or "Unknown",
            "expected_outcome": invocation.expected_outcome or "Unknown",
            "analysis": {},
        }
        
        if agent:
            explanation["analysis"]["agent_purpose"] = agent.purpose
            explanation["analysis"]["tool_allowed"] = (
                not agent.allowed_tools or invocation.tool_id in agent.allowed_tools
            )
            explanation["analysis"]["within_risk_tolerance"] = True
            if tool:
                from airs_cp.observability.registry import RiskLevel
                risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
                explanation["analysis"]["within_risk_tolerance"] = (
                    risk_order.index(tool.risk_level) <= risk_order.index(agent.risk_tolerance)
                )
        
        if tool:
            explanation["analysis"]["tool_description"] = tool.description
            explanation["analysis"]["tool_risk"] = tool.risk_level.value
            explanation["analysis"]["requires_approval"] = tool.requires_approval
            explanation["analysis"]["can_access_external"] = tool.can_access_external
        
        if invocation.deviation_score > 0:
            explanation["deviations"] = {
                "score": invocation.deviation_score,
                "reasons": invocation.deviation_reasons,
                "was_expected": invocation.was_expected,
            }
        
        return explanation
