"""
Response Orchestrator Module

Provides automated response orchestration for security events:
- Playbook definitions and management
- Action execution engine
- Mode-aware enforcement (observe vs enforce)
"""

from airs_cp.orchestrator.playbooks import (
    Playbook,
    PlaybookAction,
    PlaybookCondition,
    PlaybookTrigger,
    TriggerOperator,
    get_playbook,
    get_all_playbooks,
    get_enabled_playbooks,
)
from airs_cp.orchestrator.executor import (
    ExecutionContext,
    ExecutionResult,
    PlaybookExecutor,
    get_executor,
)

__all__ = [
    # Playbooks
    "Playbook",
    "PlaybookAction",
    "PlaybookCondition",
    "PlaybookTrigger",
    "TriggerOperator",
    "get_playbook",
    "get_all_playbooks",
    "get_enabled_playbooks",
    # Executor
    "ExecutionContext",
    "ExecutionResult",
    "PlaybookExecutor",
    "get_executor",
]
