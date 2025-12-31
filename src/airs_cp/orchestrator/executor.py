"""
Playbook Executor

Executes playbook actions in response to security events.
Handles the full lifecycle from detection to response.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from airs_cp.store.models import (
    Action,
    ActionType,
    Detection,
    Severity,
    SecurityResult,
)
from airs_cp.orchestrator.playbooks import (
    Playbook,
    PlaybookAction,
    get_enabled_playbooks,
)


@dataclass
class ExecutionContext:
    """Context for playbook execution."""
    session_id: str = ""
    event_id: str = ""
    mode: str = "observe"  # observe|enforce
    kill_switch: bool = False
    session: dict[str, Any] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    
    @property
    def effective_mode(self) -> str:
        """Get effective mode considering kill switch."""
        if self.kill_switch:
            return "observe"
        return self.mode


@dataclass
class ExecutionResult:
    """Result of playbook execution."""
    playbook_id: str
    triggered: bool = False
    actions_executed: list[dict[str, Any]] = field(default_factory=list)
    final_action: ActionType = ActionType.ALLOW
    modified_content: Optional[str] = None
    blocked: bool = False
    block_message: Optional[str] = None
    block_code: int = 403
    latency_ms: float = 0.0


class PlaybookExecutor:
    """
    Executor for security playbooks.
    
    Evaluates detections against playbooks and executes
    appropriate response actions.
    """
    
    def __init__(self):
        """Initialize the executor."""
        self._action_handlers: dict[str, Callable] = {
            "allow": self._handle_allow,
            "block": self._handle_block,
            "sanitize": self._handle_sanitize,
            "quarantine": self._handle_quarantine,
            "throttle": self._handle_throttle,
            "log": self._handle_log,
            "alert": self._handle_alert,
            "taint": self._handle_taint,
            "respond": self._handle_respond,
            "increment_counter": self._handle_increment_counter,
        }
        self._logs: list[dict[str, Any]] = []
        self._alerts: list[dict[str, Any]] = []
    
    def execute(
        self,
        detection: Detection,
        content: str,
        context: ExecutionContext,
        playbooks: Optional[list[Playbook]] = None,
    ) -> ExecutionResult:
        """
        Execute playbooks for a detection.
        
        Args:
            detection: The security detection.
            content: The content being processed.
            context: Execution context.
            playbooks: Playbooks to evaluate (default: all enabled).
            
        Returns:
            ExecutionResult with actions taken.
        """
        start_time = time.time()
        
        if playbooks is None:
            playbooks = get_enabled_playbooks()
        
        result = ExecutionResult(playbook_id="none")
        
        # Convert detection to dict for matching
        det_dict = {
            "detector_name": detection.detector_name,
            "detector_type": detection.detector_type.value,
            "severity": detection.severity.value,
            "confidence": detection.confidence,
            "signals": detection.signals,
        }
        
        # Build context dict
        ctx_dict = {
            "session": context.session,
            "counters": context.counters,
        }
        
        # Find matching playbooks
        matching_playbooks = [
            pb for pb in playbooks
            if pb.matches(det_dict, ctx_dict)
        ]
        
        if not matching_playbooks:
            result.latency_ms = (time.time() - start_time) * 1000
            return result
        
        # Execute first matching playbook
        playbook = matching_playbooks[0]
        result.playbook_id = playbook.id
        result.triggered = True
        
        # Determine which actions to execute based on mode
        effective_mode = context.effective_mode
        
        # Execute actions
        modified_content = content
        for action in playbook.actions:
            # In observe mode, only execute logging actions
            if effective_mode == "observe":
                if action.action_type not in ["log", "alert", "taint"]:
                    # Record what would have happened
                    result.actions_executed.append({
                        "type": action.action_type,
                        "params": action.params,
                        "executed": False,
                        "reason": "observe_mode",
                    })
                    continue
            
            # Execute action
            handler = self._action_handlers.get(action.action_type)
            if handler:
                action_result = handler(action, modified_content, context, detection)
                result.actions_executed.append({
                    "type": action.action_type,
                    "params": action.params,
                    "executed": True,
                    "result": action_result,
                })
                
                # Update state based on action result
                if action.action_type == "block":
                    result.blocked = True
                    result.block_message = action.params.get("message", "Blocked")
                    result.block_code = action.params.get("code", 403)
                    result.final_action = ActionType.BLOCK
                    break  # Stop processing after block
                
                elif action.action_type == "sanitize":
                    modified_content = action_result.get("modified_content", modified_content)
                    result.modified_content = modified_content
                    result.final_action = ActionType.SANITIZE
                
                elif action.action_type == "quarantine":
                    result.final_action = ActionType.QUARANTINE
                
                elif action.action_type == "throttle":
                    result.final_action = ActionType.THROTTLE
        
        result.latency_ms = (time.time() - start_time) * 1000
        return result
    
    def execute_all(
        self,
        detections: list[Detection],
        content: str,
        context: ExecutionContext,
    ) -> SecurityResult:
        """
        Execute playbooks for multiple detections.
        
        Args:
            detections: List of security detections.
            content: The content being processed.
            context: Execution context.
            
        Returns:
            Combined SecurityResult.
        """
        start_time = time.time()
        
        if not detections:
            return SecurityResult(allowed=True, action=ActionType.ALLOW)
        
        # Sort detections by severity (process most severe first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        sorted_detections = sorted(
            detections,
            key=lambda d: severity_order.get(d.severity, 4)
        )
        
        modified_content = content
        final_action = ActionType.ALLOW
        blocked = False
        block_message = None
        
        for detection in sorted_detections:
            result = self.execute(detection, modified_content, context)
            
            if result.blocked:
                blocked = True
                block_message = result.block_message
                final_action = ActionType.BLOCK
                break
            
            if result.modified_content:
                modified_content = result.modified_content
                if final_action == ActionType.ALLOW:
                    final_action = result.final_action
        
        total_latency = (time.time() - start_time) * 1000
        
        return SecurityResult(
            allowed=not blocked,
            action=final_action,
            detections=sorted_detections,
            modified_content=modified_content if modified_content != content else None,
            explanation=block_message,
            latency_ms=total_latency,
        )
    
    # === Action Handlers ===
    
    def _handle_allow(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle allow action."""
        return {"status": "allowed"}
    
    def _handle_block(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle block action."""
        return {
            "status": "blocked",
            "message": action.params.get("message", "Request blocked"),
            "code": action.params.get("code", 403),
        }
    
    def _handle_sanitize(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle sanitize action."""
        from airs_cp.security.detectors.pii import get_pii_detector
        
        # Use PII detector to sanitize
        detector = get_pii_detector()
        sanitized = detector.mask(content)
        
        return {
            "status": "sanitized",
            "modified_content": sanitized,
            "original_length": len(content),
            "sanitized_length": len(sanitized),
        }
    
    def _handle_quarantine(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle quarantine action."""
        duration = action.params.get("duration", 3600)
        message = action.params.get("message", "Session quarantined")
        
        # Update session status
        context.session["status"] = "quarantined"
        context.session["quarantine_until"] = time.time() + duration
        
        return {
            "status": "quarantined",
            "duration": duration,
            "message": message,
        }
    
    def _handle_throttle(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle throttle action."""
        delay_ms = action.params.get("delay_ms", 1000)
        
        # In real implementation, this would add delay
        return {
            "status": "throttled",
            "delay_ms": delay_ms,
        }
    
    def _handle_log(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle log action."""
        level = action.params.get("level", "info")
        include_original = action.params.get("include_original", False)
        
        log_entry = {
            "level": level,
            "session_id": context.session_id,
            "event_id": context.event_id,
            "detection": detection.detector_name,
            "severity": detection.severity.value,
            "confidence": detection.confidence,
        }
        
        if include_original:
            log_entry["content_preview"] = content[:200] if len(content) > 200 else content
        
        self._logs.append(log_entry)
        
        return {"status": "logged", "level": level}
    
    def _handle_alert(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle alert action."""
        channel = action.params.get("channel", "default")
        template = action.params.get("template", "generic_alert")
        priority = action.params.get("priority", "normal")
        
        alert = {
            "channel": channel,
            "template": template,
            "priority": priority,
            "session_id": context.session_id,
            "detection": detection.detector_name,
            "severity": detection.severity.value,
        }
        
        self._alerts.append(alert)
        
        return {"status": "alerted", "channel": channel, "priority": priority}
    
    def _handle_taint(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle taint action."""
        label = action.params.get("label", "security_flagged")
        propagate = action.params.get("propagate", True)
        
        # In real implementation, this would add taint to the content
        return {
            "status": "tainted",
            "label": label,
            "propagate": propagate,
        }
    
    def _handle_respond(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle custom response action."""
        return {
            "status": action.params.get("status", 200),
            "message": action.params.get("message", ""),
            "headers": action.params.get("headers", {}),
        }
    
    def _handle_increment_counter(
        self,
        action: PlaybookAction,
        content: str,
        context: ExecutionContext,
        detection: Detection,
    ) -> dict[str, Any]:
        """Handle counter increment action."""
        counter = action.params.get("counter", "violations")
        max_value = action.params.get("max", 10)
        on_exceed = action.params.get("on_exceed", "alert")
        
        # Increment counter
        current = context.counters.get(counter, 0) + 1
        context.counters[counter] = current
        
        exceeded = current > max_value
        
        return {
            "status": "incremented",
            "counter": counter,
            "value": current,
            "max": max_value,
            "exceeded": exceeded,
            "on_exceed": on_exceed if exceeded else None,
        }
    
    def get_logs(self) -> list[dict[str, Any]]:
        """Get collected logs."""
        return self._logs.copy()
    
    def get_alerts(self) -> list[dict[str, Any]]:
        """Get collected alerts."""
        return self._alerts.copy()
    
    def clear_logs(self) -> None:
        """Clear collected logs."""
        self._logs.clear()
    
    def clear_alerts(self) -> None:
        """Clear collected alerts."""
        self._alerts.clear()


# Global executor instance
_executor: Optional[PlaybookExecutor] = None


def get_executor() -> PlaybookExecutor:
    """Get the global playbook executor instance."""
    global _executor
    if _executor is None:
        _executor = PlaybookExecutor()
    return _executor
