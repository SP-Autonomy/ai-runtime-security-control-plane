"""
Data Models for Evidence Store

Defines the data structures used throughout AIRS-CP for
events, detections, actions, taint tracking, and explanations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import json
import uuid


class EventType(str, Enum):
    """Types of security events."""
    REQUEST = "request"
    RESPONSE = "response"
    DETECTION = "detection"
    ACTION = "action"


class Severity(str, Enum):
    """Detection severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectorType(str, Enum):
    """Types of security detectors."""
    DLP = "dlp"
    INJECTION = "injection"
    ANOMALY = "anomaly"
    POLICY = "policy"


class ActionType(str, Enum):
    """Types of enforcement actions."""
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    THROTTLE = "throttle"


class TaintSourceType(str, Enum):
    """Types of taint sources."""
    USER_INPUT = "user_input"
    RAG_DOC = "rag_doc"
    TOOL_OUTPUT = "tool_output"
    MODEL_RESPONSE = "model_response"
    SYSTEM_PROMPT = "system_prompt"


class TaintSensitivity(str, Enum):
    """Taint sensitivity levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ExplanationType(str, Enum):
    """Types of explanations."""
    SHAP = "shap"
    RULE = "rule"
    POLICY = "policy"
    NARRATIVE = "narrative"


def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix."""
    uid = str(uuid.uuid4())[:8]
    return f"{prefix}_{uid}" if prefix else uid


def now_iso() -> str:
    """Get current timestamp in ISO 8601 format."""
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class Session:
    """Represents an interaction session."""
    id: str = field(default_factory=lambda: generate_id("sess"))
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    user_id: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "active"  # active|closed|quarantined
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "user_id": self.user_id,
            "tags": json.dumps(self.tags),
            "metadata": json.dumps(self.metadata),
            "status": self.status,
        }


@dataclass
class Event:
    """Represents a security-relevant event."""
    id: str = field(default_factory=lambda: generate_id("evt"))
    session_id: str = ""
    timestamp: str = field(default_factory=now_iso)
    event_type: EventType = EventType.REQUEST
    direction: Optional[str] = None  # inbound|outbound
    content: Optional[str] = None  # Redacted content
    content_hash: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    latency_ms: Optional[int] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value if isinstance(self.event_type, Enum) else self.event_type,
            "direction": self.direction,
            "content": self.content,
            "content_hash": self.content_hash,
            "provider": self.provider,
            "model": self.model,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "latency_ms": self.latency_ms,
            "metadata": json.dumps(self.metadata),
        }


@dataclass
class Detection:
    """Represents a security detection."""
    id: str = field(default_factory=lambda: generate_id("det"))
    event_id: str = ""
    timestamp: str = field(default_factory=now_iso)
    detector_type: DetectorType = DetectorType.DLP
    detector_name: str = ""
    severity: Severity = Severity.LOW
    confidence: float = 0.0
    signals: list[dict[str, Any]] = field(default_factory=list)
    raw_score: Optional[float] = None
    threshold: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "detector_type": self.detector_type.value if isinstance(self.detector_type, Enum) else self.detector_type,
            "detector_name": self.detector_name,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "confidence": self.confidence,
            "signals": json.dumps(self.signals),
            "raw_score": self.raw_score,
            "threshold": self.threshold,
            "metadata": json.dumps(self.metadata),
        }


@dataclass
class Action:
    """Represents an enforcement action."""
    id: str = field(default_factory=lambda: generate_id("act"))
    detection_id: Optional[str] = None
    event_id: str = ""
    timestamp: str = field(default_factory=now_iso)
    action_type: ActionType = ActionType.ALLOW
    policy_id: Optional[str] = None
    playbook_id: Optional[str] = None
    original_content: Optional[str] = None
    modified_content: Optional[str] = None
    explanation: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "action_type": self.action_type.value if isinstance(self.action_type, Enum) else self.action_type,
            "policy_id": self.policy_id,
            "playbook_id": self.playbook_id,
            "original_content": self.original_content,
            "modified_content": self.modified_content,
            "explanation": self.explanation,
            "metadata": json.dumps(self.metadata),
        }


@dataclass
class TaintLabel:
    """Represents a taint label for data provenance."""
    id: str = field(default_factory=lambda: generate_id("taint"))
    created_at: str = field(default_factory=now_iso)
    source_type: TaintSourceType = TaintSourceType.USER_INPUT
    source_id: str = ""
    sensitivity: TaintSensitivity = TaintSensitivity.PUBLIC
    label: str = ""  # e.g., "pii", "external", "confidential"
    content_hash: Optional[str] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "source_type": self.source_type.value if isinstance(self.source_type, Enum) else self.source_type,
            "source_id": self.source_id,
            "sensitivity": self.sensitivity.value if isinstance(self.sensitivity, Enum) else self.sensitivity,
            "label": self.label,
            "content_hash": self.content_hash,
            "confidence": self.confidence,
            "metadata": json.dumps(self.metadata),
        }
    
    def to_label_string(self) -> str:
        """Generate full taint label string."""
        return f"{self.source_type.value}:{self.source_id}:{self.sensitivity.value}:{self.created_at}"


@dataclass
class TaintEdge:
    """Represents data flow between tainted entities."""
    id: str = field(default_factory=lambda: generate_id("edge"))
    from_label_id: str = ""
    to_label_id: str = ""
    edge_type: str = "propagate"  # propagate|transform|sink
    operation: Optional[str] = None  # concatenate|summarize|tool_call
    timestamp: str = field(default_factory=now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "from_label_id": self.from_label_id,
            "to_label_id": self.to_label_id,
            "edge_type": self.edge_type,
            "operation": self.operation,
            "timestamp": self.timestamp,
            "metadata": json.dumps(self.metadata),
        }


@dataclass
class Explanation:
    """Represents a security decision explanation."""
    id: str = field(default_factory=lambda: generate_id("exp"))
    detection_id: Optional[str] = None
    action_id: Optional[str] = None
    timestamp: str = field(default_factory=now_iso)
    explanation_type: ExplanationType = ExplanationType.NARRATIVE
    content: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "action_id": self.action_id,
            "timestamp": self.timestamp,
            "explanation_type": self.explanation_type.value if isinstance(self.explanation_type, Enum) else self.explanation_type,
            "content": json.dumps(self.content),
            "metadata": json.dumps(self.metadata),
        }


@dataclass
class SecurityResult:
    """Result from security pipeline processing."""
    allowed: bool = True
    action: ActionType = ActionType.ALLOW
    detections: list[Detection] = field(default_factory=list)
    modified_content: Optional[str] = None
    explanation: Optional[str] = None
    latency_ms: float = 0.0
    
    @property
    def has_detections(self) -> bool:
        return len(self.detections) > 0
    
    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.detections:
            return None
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        max_sev = Severity.LOW
        for det in self.detections:
            if severity_order.index(det.severity) > severity_order.index(max_sev):
                max_sev = det.severity
        return max_sev
