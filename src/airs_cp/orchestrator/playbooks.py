"""
Playbook Definitions

Defines automated response playbooks for security events.
Playbooks specify triggers, conditions, and actions to execute.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from airs_cp.store.models import ActionType, Severity


class TriggerOperator(str, Enum):
    """Operators for condition evaluation."""
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    REGEX = "regex"
    IN = "in"


@dataclass
class PlaybookTrigger:
    """Trigger condition for a playbook."""
    detector: str
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    
    def matches(self, detection: dict[str, Any]) -> bool:
        """Check if detection matches this trigger."""
        if detection.get("detector_name") != self.detector:
            return False
        
        # Check severity
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        det_severity = Severity(detection.get("severity", "low"))
        if severity_order.index(det_severity) < severity_order.index(self.severity):
            return False
        
        # Check confidence
        if detection.get("confidence", 0) < self.confidence:
            return False
        
        return True


@dataclass
class PlaybookCondition:
    """Additional condition for playbook execution."""
    field: str
    operator: TriggerOperator
    value: Any
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Evaluate condition against context."""
        # Navigate nested fields (e.g., "session.violation_count")
        actual_value = context
        for part in self.field.split("."):
            if isinstance(actual_value, dict):
                actual_value = actual_value.get(part)
            else:
                return False
        
        if actual_value is None:
            return False
        
        if self.operator == TriggerOperator.EQ:
            return actual_value == self.value
        elif self.operator == TriggerOperator.NE:
            return actual_value != self.value
        elif self.operator == TriggerOperator.GT:
            return actual_value > self.value
        elif self.operator == TriggerOperator.GTE:
            return actual_value >= self.value
        elif self.operator == TriggerOperator.LT:
            return actual_value < self.value
        elif self.operator == TriggerOperator.LTE:
            return actual_value <= self.value
        elif self.operator == TriggerOperator.CONTAINS:
            return self.value in actual_value
        elif self.operator == TriggerOperator.IN:
            return actual_value in self.value
        
        return False


@dataclass
class PlaybookAction:
    """Action to execute in a playbook."""
    action_type: str  # block, sanitize, log, alert, quarantine, throttle, taint
    params: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.action_type,
            "params": self.params,
        }


@dataclass
class Playbook:
    """
    Security playbook definition.
    
    Playbooks define automated responses to security events.
    """
    id: str
    name: str
    description: str
    enabled: bool = True
    triggers: list[PlaybookTrigger] = field(default_factory=list)
    conditions: list[PlaybookCondition] = field(default_factory=list)
    actions: list[PlaybookAction] = field(default_factory=list)
    observe_action: str = "log"  # Action type in observe mode
    enforce_action: str = "block"  # Action type in enforce mode
    
    def matches(
        self,
        detection: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """
        Check if this playbook should be triggered.
        
        Args:
            detection: Detection data.
            context: Additional context (session, history, etc.).
            
        Returns:
            True if playbook should execute.
        """
        if not self.enabled:
            return False
        
        # Check if any trigger matches
        trigger_match = any(t.matches(detection) for t in self.triggers)
        if not trigger_match:
            return False
        
        # Check all conditions
        if self.conditions:
            all_conditions = all(c.evaluate(context) for c in self.conditions)
            if not all_conditions:
                return False
        
        return True
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "triggers": [
                {"detector": t.detector, "severity": t.severity.value, "confidence": t.confidence}
                for t in self.triggers
            ],
            "conditions": [
                {"field": c.field, "operator": c.operator.value, "value": c.value}
                for c in self.conditions
            ],
            "actions": [a.to_dict() for a in self.actions],
        }


# ============================================================================
# Standard Playbooks
# ============================================================================

STANDARD_PLAYBOOKS = {
    "pii_leak_prevention": Playbook(
        id="pii_leak_prevention",
        name="PII Leak Prevention",
        description="Detect and sanitize PII in prompts and responses",
        triggers=[
            PlaybookTrigger(detector="pii_detector", severity=Severity.MEDIUM, confidence=0.8),
        ],
        actions=[
            PlaybookAction("sanitize", {
                "patterns": {
                    "ssn": "***-**-****",
                    "credit_card": "****-****-****-****",
                    "email": "[REDACTED EMAIL]",
                    "phone": "[REDACTED PHONE]",
                },
            }),
            PlaybookAction("log", {"level": "warning", "include_original": False}),
            PlaybookAction("alert", {"channel": "security_team", "template": "pii_detected"}),
        ],
        observe_action="log",
        enforce_action="sanitize",
    ),
    
    "injection_block": Playbook(
        id="injection_block",
        name="Prompt Injection Block",
        description="Block detected prompt injection attempts",
        triggers=[
            PlaybookTrigger(detector="injection_detector", severity=Severity.HIGH, confidence=0.9),
        ],
        actions=[
            PlaybookAction("block", {"message": "Request blocked due to security policy", "code": 403}),
            PlaybookAction("log", {"level": "error", "include_original": True}),
            PlaybookAction("alert", {"channel": "security_team", "template": "injection_attempt", "priority": "high"}),
            PlaybookAction("increment_counter", {"counter": "session_violations", "max": 3, "on_exceed": "quarantine_session"}),
        ],
        observe_action="log",
        enforce_action="block",
    ),
    
    "session_quarantine": Playbook(
        id="session_quarantine",
        name="Session Quarantine",
        description="Quarantine sessions with repeated violations",
        triggers=[
            PlaybookTrigger(detector="session_monitor", severity=Severity.CRITICAL, confidence=0.95),
        ],
        conditions=[
            PlaybookCondition("session.violation_count", TriggerOperator.GT, 3),
        ],
        actions=[
            PlaybookAction("quarantine", {"duration": 3600, "message": "Session temporarily suspended"}),
            PlaybookAction("log", {"level": "critical", "include_session_history": True}),
            PlaybookAction("alert", {"channel": "security_team", "template": "session_quarantined", "priority": "critical"}),
        ],
        observe_action="log",
        enforce_action="quarantine",
    ),
    
    "tool_misuse": Playbook(
        id="tool_misuse",
        name="Tool Misuse Prevention",
        description="Prevent unauthorized tool usage by agents",
        triggers=[
            PlaybookTrigger(detector="policy_engine", severity=Severity.HIGH),
        ],
        conditions=[
            PlaybookCondition("policy.decision", TriggerOperator.EQ, "deny"),
        ],
        actions=[
            PlaybookAction("block", {"message": "Tool execution not authorized", "code": 403}),
            PlaybookAction("log", {"level": "warning", "include_tool_request": True}),
            PlaybookAction("taint", {"label": "unauthorized_tool_attempt", "propagate": True}),
        ],
        observe_action="log",
        enforce_action="block",
    ),
    
    "rate_limit": Playbook(
        id="rate_limit",
        name="Rate Limiting",
        description="Throttle excessive requests",
        triggers=[
            PlaybookTrigger(detector="rate_monitor", severity=Severity.MEDIUM),
        ],
        conditions=[
            PlaybookCondition("session.request_count_1min", TriggerOperator.GT, 60),
        ],
        actions=[
            PlaybookAction("throttle", {"delay_ms": 1000, "max_delay_ms": 10000, "backoff": "exponential"}),
            PlaybookAction("log", {"level": "warning"}),
            PlaybookAction("respond", {"status": 429, "message": "Rate limit exceeded", "headers": {"Retry-After": "60"}}),
        ],
        observe_action="log",
        enforce_action="throttle",
    ),
    
    "anomaly_alert": Playbook(
        id="anomaly_alert",
        name="Anomaly Alert",
        description="Alert on anomalous request patterns",
        triggers=[
            PlaybookTrigger(detector="anomaly_detector", severity=Severity.MEDIUM, confidence=0.7),
        ],
        actions=[
            PlaybookAction("log", {"level": "warning", "include_features": True}),
            PlaybookAction("alert", {"channel": "security_team", "template": "anomaly_detected"}),
            PlaybookAction("taint", {"label": "anomalous", "propagate": True}),
        ],
        observe_action="log",
        enforce_action="log",  # Anomalies don't block by default
    ),
}


def get_playbook(playbook_id: str) -> Optional[Playbook]:
    """Get a playbook by ID."""
    return STANDARD_PLAYBOOKS.get(playbook_id)


def get_all_playbooks() -> dict[str, Playbook]:
    """Get all standard playbooks."""
    return STANDARD_PLAYBOOKS.copy()


def get_enabled_playbooks() -> list[Playbook]:
    """Get all enabled playbooks."""
    return [p for p in STANDARD_PLAYBOOKS.values() if p.enabled]
