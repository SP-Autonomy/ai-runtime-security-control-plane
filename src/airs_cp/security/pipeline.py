"""
Security Pipeline

Unified security processing pipeline that integrates:
- PII detection
- Injection detection (pattern + ML)
- Anomaly detection (ML)
- Taint tracking
- Playbook execution
- Explanation generation
"""

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from airs_cp.config import settings
from airs_cp.store.models import (
    ActionType,
    Detection,
    DetectorType,
    Event,
    EventType,
    SecurityResult,
    Severity,
)


@dataclass
class PipelineResult:
    """Result of security pipeline processing."""
    allowed: bool = True
    action: ActionType = ActionType.ALLOW
    detections: list[Detection] = field(default_factory=list)
    modified_content: Optional[str] = None
    blocked: bool = False
    block_message: Optional[str] = None
    block_code: int = 403
    explanations: list[dict[str, Any]] = field(default_factory=list)
    taint_labels: list[str] = field(default_factory=list)
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


class SecurityPipeline:
    """
    Unified security processing pipeline.
    
    Runs all security checks in order and aggregates results.
    Supports both deterministic (pattern-based) and ML-based detection.
    """
    
    def __init__(
        self,
        mode: str = "observe",
        pii_enabled: bool = True,
        injection_enabled: bool = True,
        anomaly_enabled: bool = True,
        taint_enabled: bool = True,
        ml_enabled: bool = True,
        store=None,
    ):
        """
        Initialize the security pipeline.
        
        Args:
            mode: Runtime mode (observe or enforce).
            pii_enabled: Enable PII detection.
            injection_enabled: Enable injection detection.
            anomaly_enabled: Enable anomaly detection.
            taint_enabled: Enable taint tracking.
            ml_enabled: Enable ML-based detection.
            store: Optional EvidenceStore for persistence.
        """
        self.mode = mode
        self.pii_enabled = pii_enabled
        self.injection_enabled = injection_enabled
        self.anomaly_enabled = anomaly_enabled
        self.taint_enabled = taint_enabled
        self.ml_enabled = ml_enabled
        self.store = store
        
        # Initialize detectors lazily
        self._pii_detector = None
        self._injection_detector = None
        self._anomaly_detector = None
        self._injection_classifier = None
        self._taint_engine = None
        self._executor = None
        self._shap_explainer = None
        self._narrative_generator = None
    
    @property
    def pii_detector(self):
        if self._pii_detector is None:
            from airs_cp.security.detectors.pii import get_pii_detector
            self._pii_detector = get_pii_detector()
        return self._pii_detector
    
    @property
    def injection_detector(self):
        if self._injection_detector is None:
            from airs_cp.security.detectors.injection import get_injection_detector
            self._injection_detector = get_injection_detector(use_ml=self.ml_enabled)
        return self._injection_detector
    
    @property
    def anomaly_detector(self):
        if self._anomaly_detector is None and self.ml_enabled:
            from airs_cp.ml.anomaly import get_anomaly_detector
            self._anomaly_detector = get_anomaly_detector(
                f"{settings.models_dir}/anomaly_detector.pkl"
            )
        return self._anomaly_detector
    
    @property
    def injection_classifier(self):
        if self._injection_classifier is None and self.ml_enabled:
            from airs_cp.ml.classifier import get_injection_classifier
            self._injection_classifier = get_injection_classifier(
                f"{settings.models_dir}/injection_classifier.pkl"
            )
        return self._injection_classifier
    
    @property
    def taint_engine(self):
        if self._taint_engine is None:
            from airs_cp.security.taint import get_taint_engine
            self._taint_engine = get_taint_engine(self.store)
        return self._taint_engine
    
    @property
    def executor(self):
        if self._executor is None:
            from airs_cp.orchestrator.executor import get_executor
            self._executor = get_executor()
        return self._executor
    
    @property
    def shap_explainer(self):
        if self._shap_explainer is None:
            from airs_cp.explainability.shap_explainer import get_shap_explainer
            self._shap_explainer = get_shap_explainer()
        return self._shap_explainer
    
    @property
    def narrative_generator(self):
        if self._narrative_generator is None:
            from airs_cp.explainability.narrative import get_narrative_generator
            self._narrative_generator = get_narrative_generator(
                use_llm=settings.llm_narratives_enabled,
                model=settings.narrative_model,
            )
        return self._narrative_generator
    
    def process(
        self,
        content: str,
        session_id: str = "unknown",
        event_id: str = "",
        direction: str = "inbound",
        generate_explanations: bool = True,
    ) -> PipelineResult:
        """
        Process content through the security pipeline.
        
        Args:
            content: Content to analyze.
            session_id: Session identifier.
            event_id: Event identifier.
            direction: Content direction (inbound/outbound).
            generate_explanations: Whether to generate explanations.
            
        Returns:
            PipelineResult with all detections and actions.
        """
        start_time = time.time()
        result = PipelineResult()
        detections = []
        
        # Generate event ID if not provided
        if not event_id:
            from airs_cp.store.models import generate_id
            event_id = generate_id("evt")
        
        # 1. PII Detection
        if self.pii_enabled:
            pii_detection = self._run_pii_detection(content, event_id)
            if pii_detection:
                detections.append(pii_detection)
        
        # 2. Injection Detection (pattern-based)
        if self.injection_enabled:
            injection_detection = self._run_injection_detection(content, event_id)
            if injection_detection:
                detections.append(injection_detection)
        
        # 3. Anomaly Detection (ML)
        if self.anomaly_enabled and self.ml_enabled and self.anomaly_detector:
            anomaly_detection = self._run_anomaly_detection(content, event_id)
            if anomaly_detection:
                detections.append(anomaly_detection)
        
        # 4. ML Injection Classification
        if self.injection_enabled and self.ml_enabled and self.injection_classifier:
            ml_detection = self._run_ml_injection_detection(content, event_id)
            if ml_detection:
                detections.append(ml_detection)
        
        result.detections = detections
        
        # 5. Execute playbooks if detections found
        if detections:
            from airs_cp.orchestrator.executor import ExecutionContext
            
            context = ExecutionContext(
                session_id=session_id,
                event_id=event_id,
                mode=self.mode,
                kill_switch=settings.kill_switch,
            )
            
            exec_result = self.executor.execute_all(detections, content, context)
            
            result.allowed = exec_result.allowed
            result.action = exec_result.action
            result.modified_content = exec_result.modified_content
            
            if not exec_result.allowed:
                result.blocked = True
                result.block_message = exec_result.explanation or "Request blocked"
        
        # 6. Taint tracking
        if self.taint_enabled and detections:
            taint_labels = self._apply_taint(content, detections, event_id)
            result.taint_labels = taint_labels
        
        # 7. Generate explanations
        if generate_explanations and detections and settings.explanations_enabled:
            explanations = self._generate_explanations(detections, content, session_id)
            result.explanations = explanations
        
        result.latency_ms = (time.time() - start_time) * 1000
        
        # 8. Persist event if store available
        if self.store:
            event = Event(
                id=event_id,
                session_id=session_id,
                event_type=EventType.REQUEST if direction == "inbound" else EventType.RESPONSE,
                direction=direction,
                content=content[:500] if content else None,
            )
            self.store.create_event(event)
            
            for detection in detections:
                self.store.create_detection(detection)
        
        return result
    
    def _run_pii_detection(self, content: str, event_id: str) -> Optional[Detection]:
        """Run PII detection."""
        try:
            detection = self.pii_detector.to_detection(content, event_id)
            return detection
        except Exception:
            return None
    
    def _run_injection_detection(self, content: str, event_id: str) -> Optional[Detection]:
        """Run pattern-based injection detection."""
        try:
            detection = self.injection_detector.to_detection(content, event_id)
            return detection
        except Exception:
            return None
    
    def _run_anomaly_detection(self, content: str, event_id: str) -> Optional[Detection]:
        """Run ML anomaly detection."""
        try:
            result = self.anomaly_detector.predict(content)
            
            if result["is_anomaly"]:
                return Detection(
                    event_id=event_id,
                    detector_type=DetectorType.ANOMALY,
                    detector_name="anomaly_detector",
                    severity=Severity.MEDIUM,
                    confidence=result["anomaly_score"],
                    signals=[{"feature": k, "value": v} for k, v in list(result["features"].items())[:5]],
                    raw_score=result["raw_score"],
                    threshold=result["threshold"],
                )
        except Exception:
            pass
        return None
    
    def _run_ml_injection_detection(self, content: str, event_id: str) -> Optional[Detection]:
        """Run ML injection classification."""
        try:
            result = self.injection_classifier.predict(content)
            
            if result["is_injection"] and result["confidence"] >= settings.injection_threshold:
                return Detection(
                    event_id=event_id,
                    detector_type=DetectorType.INJECTION,
                    detector_name="injection_classifier_ml",
                    severity=Severity.HIGH if result["confidence"] > 0.8 else Severity.MEDIUM,
                    confidence=result["confidence"],
                    signals=result["top_features"],
                    raw_score=result["probability_injection"],
                    threshold=settings.injection_threshold,
                )
        except Exception:
            pass
        return None
    
    def _apply_taint(
        self,
        content: str,
        detections: list[Detection],
        event_id: str,
    ) -> list[str]:
        """Apply taint labels based on detections."""
        from airs_cp.security.taint import TaintSourceType, TaintSensitivity
        
        labels = []
        
        for detection in detections:
            # Determine sensitivity based on severity
            sensitivity_map = {
                Severity.LOW: TaintSensitivity.INTERNAL,
                Severity.MEDIUM: TaintSensitivity.CONFIDENTIAL,
                Severity.HIGH: TaintSensitivity.RESTRICTED,
                Severity.CRITICAL: TaintSensitivity.RESTRICTED,
            }
            sensitivity = sensitivity_map.get(detection.severity, TaintSensitivity.INTERNAL)
            
            tainted = self.taint_engine.create_taint(
                content=content,
                source_type=TaintSourceType.USER_INPUT,
                source_id=event_id,
                sensitivity=sensitivity,
                label=f"detection:{detection.detector_name}",
            )
            
            if tainted.taints:
                labels.append(tainted.taints[0].label)
        
        return labels
    
    def _generate_explanations(
        self,
        detections: list[Detection],
        content: str,
        session_id: str,
    ) -> list[dict[str, Any]]:
        """Generate explanations for detections."""
        explanations = []
        
        for detection in detections:
            try:
                # Generate SHAP explanation for ML detections
                if detection.detector_name in ["anomaly_detector", "injection_classifier_ml"]:
                    if detection.detector_name == "injection_classifier_ml" and self.injection_classifier:
                        shap_exp = self.shap_explainer.explain_classifier(
                            self.injection_classifier, content
                        )
                        explanations.append(shap_exp)
                    elif detection.detector_name == "anomaly_detector" and self.anomaly_detector:
                        shap_exp = self.shap_explainer.explain_anomaly(
                            self.anomaly_detector, content
                        )
                        explanations.append(shap_exp)
                
                # Generate narrative for high severity detections
                if detection.severity in [Severity.HIGH, Severity.CRITICAL]:
                    narrative = self.narrative_generator.generate(
                        detection=detection,
                        session_id=session_id,
                        use_llm=False,  # Use template by default for speed
                    )
                    explanations.append(narrative)
                    
            except Exception:
                pass
        
        return explanations


# Global pipeline instance
_pipeline: Optional[SecurityPipeline] = None


def get_pipeline(
    mode: Optional[str] = None,
    store=None,
) -> SecurityPipeline:
    """Get the global security pipeline instance."""
    global _pipeline
    
    if _pipeline is None:
        _pipeline = SecurityPipeline(
            mode=mode or settings.get_effective_mode().value,
            pii_enabled=settings.pii_detection_enabled,
            injection_enabled=settings.injection_detection_enabled,
            anomaly_enabled=settings.ml_enabled,
            taint_enabled=settings.taint_tracking_enabled,
            ml_enabled=settings.ml_enabled,
            store=store,
        )
    
    return _pipeline


def process_content(
    content: str,
    session_id: str = "unknown",
    direction: str = "inbound",
) -> PipelineResult:
    """Convenience function to process content through the pipeline."""
    pipeline = get_pipeline()
    return pipeline.process(content, session_id=session_id, direction=direction)
