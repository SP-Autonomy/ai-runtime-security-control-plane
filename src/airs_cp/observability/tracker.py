"""
Invocation Tracker

Tracks all tool invocations by agents, including:
- What tool was called
- Why it was called (reasoning)
- Input/output
- Timing
- Success/failure
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import json
import uuid


class InvocationStatus(str, Enum):
    """Status of tool invocation."""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


@dataclass
class ToolInvocation:
    """Record of a single tool invocation."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    
    # Context
    session_id: str = ""
    agent_id: str = ""
    tool_id: str = ""
    
    # Timing
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    latency_ms: int = 0
    
    # Reasoning (Why was this tool called?)
    reasoning: str = ""  # LLM's explanation for calling this tool
    user_intent: str = ""  # What the user was trying to accomplish
    expected_outcome: str = ""  # What the agent expected to happen
    
    # Input/Output
    input_args: dict[str, Any] = field(default_factory=dict)
    input_context: str = ""  # Relevant context that informed the decision
    output_result: Any = None
    output_type: str = ""
    
    # Status
    status: InvocationStatus = InvocationStatus.PENDING
    error_message: str = ""
    
    # Security
    was_blocked: bool = False
    block_reason: str = ""
    required_approval: bool = False
    approved_by: str = ""
    
    # Behavioral analysis
    was_expected: bool = True  # Did this match expected behavior?
    deviation_score: float = 0.0  # 0.0 = normal, 1.0 = highly unusual
    deviation_reasons: list[str] = field(default_factory=list)
    
    # Chain position (for multi-tool sequences)
    chain_id: str = ""  # Groups related invocations
    chain_position: int = 0
    previous_tool: str = ""
    next_tool: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tool_id": self.tool_id,
            "timestamp": self.timestamp,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "latency_ms": self.latency_ms,
            "reasoning": self.reasoning,
            "user_intent": self.user_intent,
            "expected_outcome": self.expected_outcome,
            "input_args": self.input_args,
            "input_context": self.input_context[:500] if self.input_context else "",
            "output_result": str(self.output_result)[:500] if self.output_result else None,
            "output_type": self.output_type,
            "status": self.status.value,
            "error_message": self.error_message,
            "was_blocked": self.was_blocked,
            "block_reason": self.block_reason,
            "required_approval": self.required_approval,
            "approved_by": self.approved_by,
            "was_expected": self.was_expected,
            "deviation_score": self.deviation_score,
            "deviation_reasons": self.deviation_reasons,
            "chain_id": self.chain_id,
            "chain_position": self.chain_position,
            "previous_tool": self.previous_tool,
            "next_tool": self.next_tool,
        }


class InvocationTracker:
    """
    Tracks tool invocations across sessions.
    
    Provides:
    - Recording of all tool calls
    - Session-based grouping
    - Chain tracking for multi-tool sequences
    - Query capabilities for analysis
    """
    
    def __init__(self, max_history: int = 10000):
        self._invocations: list[ToolInvocation] = []
        self._by_session: dict[str, list[ToolInvocation]] = {}
        self._by_agent: dict[str, list[ToolInvocation]] = {}
        self._by_tool: dict[str, list[ToolInvocation]] = {}
        self._active_chains: dict[str, list[str]] = {}  # chain_id -> [invocation_ids]
        self._max_history = max_history
    
    def record(self, invocation: ToolInvocation, persist: bool = True) -> str:
        """
        Record a tool invocation.
        
        Args:
            invocation: The invocation to record
            persist: Whether to persist to database (default True)
        
        Returns:
            Invocation ID
        """
        # Add to main list (with size limit)
        self._invocations.append(invocation)
        if len(self._invocations) > self._max_history:
            removed = self._invocations.pop(0)
            self._cleanup_indexes(removed)
        
        # Index by session
        if invocation.session_id:
            if invocation.session_id not in self._by_session:
                self._by_session[invocation.session_id] = []
            self._by_session[invocation.session_id].append(invocation)
        
        # Index by agent
        if invocation.agent_id:
            if invocation.agent_id not in self._by_agent:
                self._by_agent[invocation.agent_id] = []
            self._by_agent[invocation.agent_id].append(invocation)
        
        # Index by tool
        if invocation.tool_id:
            if invocation.tool_id not in self._by_tool:
                self._by_tool[invocation.tool_id] = []
            self._by_tool[invocation.tool_id].append(invocation)
        
        # Track chain
        if invocation.chain_id:
            if invocation.chain_id not in self._active_chains:
                self._active_chains[invocation.chain_id] = []
            self._active_chains[invocation.chain_id].append(invocation.id)
        
        # Persist to database
        if persist:
            try:
                from airs_cp.store.database import get_store
                store = get_store()
                store.save_tool_invocation(
                    invocation_id=invocation.id,
                    tool_id=invocation.tool_id,
                    session_id=invocation.session_id,
                    agent_id=invocation.agent_id,
                    reasoning=invocation.reasoning,
                    user_intent=invocation.user_intent,
                    input_args=invocation.input_args,
                    status=invocation.status.value,
                    was_blocked=invocation.was_blocked,
                    block_reason=invocation.block_reason,
                    deviation_score=invocation.deviation_score,
                    deviation_reasons=invocation.deviation_reasons,
                )
            except Exception as e:
                # Log error for debugging
                import sys
                print(f"[AIRS-CP] Failed to persist invocation: {e}", file=sys.stderr)
        
        return invocation.id
    
    def _cleanup_indexes(self, invocation: ToolInvocation) -> None:
        """Remove invocation from indexes."""
        if invocation.session_id in self._by_session:
            self._by_session[invocation.session_id] = [
                i for i in self._by_session[invocation.session_id] 
                if i.id != invocation.id
            ]
        if invocation.agent_id in self._by_agent:
            self._by_agent[invocation.agent_id] = [
                i for i in self._by_agent[invocation.agent_id]
                if i.id != invocation.id
            ]
        if invocation.tool_id in self._by_tool:
            self._by_tool[invocation.tool_id] = [
                i for i in self._by_tool[invocation.tool_id]
                if i.id != invocation.id
            ]
    
    def update_status(
        self, 
        invocation_id: str, 
        status: InvocationStatus,
        result: Any = None,
        error: str = ""
    ) -> Optional[ToolInvocation]:
        """Update the status of an invocation."""
        for inv in reversed(self._invocations):
            if inv.id == invocation_id:
                inv.status = status
                inv.completed_at = datetime.utcnow().isoformat()
                if inv.started_at:
                    start = datetime.fromisoformat(inv.started_at.replace("Z", ""))
                    end = datetime.fromisoformat(inv.completed_at)
                    inv.latency_ms = int((end - start).total_seconds() * 1000)
                if result is not None:
                    inv.output_result = result
                    inv.output_type = type(result).__name__
                if error:
                    inv.error_message = error
                return inv
        return None
    
    def get_by_session(self, session_id: str) -> list[ToolInvocation]:
        """Get all invocations for a session."""
        return self._by_session.get(session_id, [])
    
    def get_by_agent(self, agent_id: str) -> list[ToolInvocation]:
        """Get all invocations by an agent."""
        return self._by_agent.get(agent_id, [])
    
    def get_by_tool(self, tool_id: str) -> list[ToolInvocation]:
        """Get all invocations of a tool."""
        return self._by_tool.get(tool_id, [])
    
    def get_chain(self, chain_id: str) -> list[ToolInvocation]:
        """Get all invocations in a chain."""
        inv_ids = self._active_chains.get(chain_id, [])
        return [i for i in self._invocations if i.id in inv_ids]
    
    def get_recent(self, limit: int = 50) -> list[ToolInvocation]:
        """Get most recent invocations."""
        return list(reversed(self._invocations[-limit:]))
    
    def get_deviations(self, min_score: float = 0.5) -> list[ToolInvocation]:
        """Get invocations with deviation scores above threshold."""
        return [i for i in self._invocations if i.deviation_score >= min_score]
    
    def get_blocked(self) -> list[ToolInvocation]:
        """Get all blocked invocations."""
        return [i for i in self._invocations if i.was_blocked]
    
    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics."""
        total = len(self._invocations)
        if total == 0:
            return {
                "total": 0,
                "success": 0,
                "failed": 0,
                "blocked": 0,
                "deviations": 0,
                "by_agent": {},
                "by_tool": {},
            }
        
        return {
            "total": total,
            "success": sum(1 for i in self._invocations if i.status == InvocationStatus.SUCCESS),
            "failed": sum(1 for i in self._invocations if i.status == InvocationStatus.FAILED),
            "blocked": sum(1 for i in self._invocations if i.was_blocked),
            "deviations": sum(1 for i in self._invocations if i.deviation_score > 0.5),
            "avg_latency_ms": sum(i.latency_ms for i in self._invocations) // total,
            "by_agent": {aid: len(invs) for aid, invs in self._by_agent.items()},
            "by_tool": {tid: len(invs) for tid, invs in self._by_tool.items()},
        }
    
    def export_session(self, session_id: str) -> str:
        """Export session invocations as JSON."""
        invocations = self.get_by_session(session_id)
        return json.dumps([i.to_dict() for i in invocations], indent=2)


# === Global Instance ===

_tracker: Optional[InvocationTracker] = None


def get_tracker() -> InvocationTracker:
    """Get the global tracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = InvocationTracker()
    return _tracker
