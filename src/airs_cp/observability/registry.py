"""
Agent and Tool Registry

Maintains inventory of all registered agents and tools,
their capabilities, restrictions, and expected behaviors.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import json


class ToolCategory(str, Enum):
    """Categories of tools."""
    DATA_RETRIEVAL = "data_retrieval"
    DATA_MODIFICATION = "data_modification"
    EXTERNAL_API = "external_api"
    INTERNAL_API = "internal_api"
    FILE_SYSTEM = "file_system"
    COMMUNICATION = "communication"
    COMPUTATION = "computation"


class RiskLevel(str, Enum):
    """Risk level of tools/agents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolDefinition:
    """Definition of a tool available to agents."""
    
    id: str
    name: str
    description: str
    category: ToolCategory
    risk_level: RiskLevel = RiskLevel.LOW
    
    # Constraints
    requires_approval: bool = False
    max_calls_per_session: Optional[int] = None
    allowed_data_sensitivity: list[str] = field(default_factory=lambda: ["public"])
    
    # Expected behavior
    expected_args: list[str] = field(default_factory=list)
    expected_return_type: str = "any"
    typical_latency_ms: int = 100
    
    # Security
    can_access_external: bool = False
    can_modify_data: bool = False
    pii_risk: bool = False
    
    # Metadata
    version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk_level": self.risk_level.value,
            "requires_approval": self.requires_approval,
            "max_calls_per_session": self.max_calls_per_session,
            "allowed_data_sensitivity": self.allowed_data_sensitivity,
            "expected_args": self.expected_args,
            "expected_return_type": self.expected_return_type,
            "typical_latency_ms": self.typical_latency_ms,
            "can_access_external": self.can_access_external,
            "can_modify_data": self.can_modify_data,
            "pii_risk": self.pii_risk,
            "version": self.version,
            "created_at": self.created_at,
            "tags": self.tags,
        }


@dataclass
class AgentDefinition:
    """Definition of an AI agent."""
    
    id: str
    name: str
    description: str
    purpose: str  # What is this agent designed to do?
    
    # Capabilities
    allowed_tools: list[str] = field(default_factory=list)
    max_tool_calls_per_request: int = 10
    can_chain_tools: bool = True
    
    # Behavior constraints
    allowed_topics: list[str] = field(default_factory=list)  # Empty = all topics
    forbidden_topics: list[str] = field(default_factory=list)
    risk_tolerance: RiskLevel = RiskLevel.MEDIUM
    
    # Expected patterns
    typical_tool_sequence: list[str] = field(default_factory=list)
    typical_response_time_ms: int = 5000
    
    # Security
    requires_authentication: bool = False
    allowed_user_roles: list[str] = field(default_factory=lambda: ["user"])
    
    # Metadata
    version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    owner: str = ""
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "purpose": self.purpose,
            "allowed_tools": self.allowed_tools,
            "max_tool_calls_per_request": self.max_tool_calls_per_request,
            "can_chain_tools": self.can_chain_tools,
            "allowed_topics": self.allowed_topics,
            "forbidden_topics": self.forbidden_topics,
            "risk_tolerance": self.risk_tolerance.value,
            "typical_tool_sequence": self.typical_tool_sequence,
            "typical_response_time_ms": self.typical_response_time_ms,
            "requires_authentication": self.requires_authentication,
            "allowed_user_roles": self.allowed_user_roles,
            "version": self.version,
            "created_at": self.created_at,
            "owner": self.owner,
            "tags": self.tags,
        }


class AgentRegistry:
    """
    Registry for agents and tools.
    
    Provides a central inventory of all AI agents and tools,
    their capabilities, and restrictions.
    """
    
    def __init__(self):
        self._agents: dict[str, AgentDefinition] = {}
        self._tools: dict[str, ToolDefinition] = {}
    
    # === Tool Management ===
    
    def register_tool(self, tool: ToolDefinition) -> None:
        """Register a tool."""
        self._tools[tool.id] = tool
    
    def get_tool(self, tool_id: str) -> Optional[ToolDefinition]:
        """Get a tool by ID."""
        return self._tools.get(tool_id)
    
    def list_tools(self, category: Optional[ToolCategory] = None) -> list[ToolDefinition]:
        """List all tools, optionally filtered by category."""
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools
    
    def remove_tool(self, tool_id: str) -> bool:
        """Remove a tool from registry."""
        if tool_id in self._tools:
            del self._tools[tool_id]
            return True
        return False
    
    # === Agent Management ===
    
    def register_agent(self, agent: AgentDefinition, persist: bool = True) -> None:
        """Register an agent."""
        self._agents[agent.id] = agent
        
        # Persist to database
        if persist:
            try:
                from airs_cp.store.database import get_store
                store = get_store()
                store.save_agent_registration(
                    agent_id=agent.id,
                    name=agent.name,
                    description=agent.description,
                    purpose=agent.purpose,
                    allowed_tools=agent.allowed_tools,
                    risk_tolerance=agent.risk_tolerance.value,
                    max_tool_calls=agent.max_tool_calls_per_request,
                    typical_tool_sequence=agent.typical_tool_sequence,
                )
            except Exception as e:
                # Log error for debugging
                import sys
                print(f"[AIRS-CP] Failed to persist agent: {e}", file=sys.stderr)
    
    def get_agent(self, agent_id: str) -> Optional[AgentDefinition]:
        """Get an agent by ID."""
        return self._agents.get(agent_id)
    
    def list_agents(self) -> list[AgentDefinition]:
        """List all registered agents."""
        return list(self._agents.values())
    
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent from registry."""
        if agent_id in self._agents:
            del self._agents[agent_id]
            return True
        return False
    
    # === Validation ===
    
    def validate_tool_call(
        self, 
        agent_id: str, 
        tool_id: str,
        data_sensitivity: str = "public"
    ) -> dict[str, Any]:
        """
        Validate if an agent can call a specific tool.
        
        Returns:
            {
                "allowed": bool,
                "reason": str,
                "warnings": list[str]
            }
        """
        result = {
            "allowed": True,
            "reason": "",
            "warnings": [],
        }
        
        agent = self.get_agent(agent_id)
        tool = self.get_tool(tool_id)
        
        if not agent:
            result["allowed"] = False
            result["reason"] = f"Agent '{agent_id}' not registered"
            return result
        
        if not tool:
            result["allowed"] = False
            result["reason"] = f"Tool '{tool_id}' not registered"
            return result
        
        # Check if tool is in agent's allowed list
        if agent.allowed_tools and tool_id not in agent.allowed_tools:
            result["allowed"] = False
            result["reason"] = f"Tool '{tool_id}' not in agent's allowed tools"
            return result
        
        # Check data sensitivity
        if data_sensitivity not in tool.allowed_data_sensitivity:
            result["allowed"] = False
            result["reason"] = f"Tool does not allow {data_sensitivity} data"
            return result
        
        # Check risk level
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        if risk_order.index(tool.risk_level) > risk_order.index(agent.risk_tolerance):
            result["warnings"].append(
                f"Tool risk ({tool.risk_level.value}) exceeds agent tolerance ({agent.risk_tolerance.value})"
            )
        
        # Check if approval required
        if tool.requires_approval:
            result["warnings"].append("Tool requires approval workflow")
        
        return result
    
    # === Export/Import ===
    
    def export_inventory(self) -> dict[str, Any]:
        """Export full inventory as dict."""
        return {
            "agents": {aid: a.to_dict() for aid, a in self._agents.items()},
            "tools": {tid: t.to_dict() for tid, t in self._tools.items()},
            "exported_at": datetime.utcnow().isoformat(),
        }
    
    def export_json(self) -> str:
        """Export inventory as JSON string."""
        return json.dumps(self.export_inventory(), indent=2)


# === Global Instance ===

_registry: Optional[AgentRegistry] = None


def get_registry() -> AgentRegistry:
    """Get the global registry instance."""
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
        _setup_default_tools(_registry)
    return _registry


def _setup_default_tools(registry: AgentRegistry) -> None:
    """Register default common tools."""
    
    # Web search
    registry.register_tool(ToolDefinition(
        id="search_web",
        name="Web Search",
        description="Search the web for information",
        category=ToolCategory.EXTERNAL_API,
        risk_level=RiskLevel.LOW,
        can_access_external=True,
        expected_args=["query"],
        tags=["search", "information"],
    ))
    
    # Send email
    registry.register_tool(ToolDefinition(
        id="send_email",
        name="Send Email",
        description="Send an email to a recipient",
        category=ToolCategory.COMMUNICATION,
        risk_level=RiskLevel.MEDIUM,
        requires_approval=True,
        can_access_external=True,
        pii_risk=True,
        expected_args=["to", "subject", "body"],
        tags=["email", "communication"],
    ))
    
    # Database query
    registry.register_tool(ToolDefinition(
        id="query_database",
        name="Query Database",
        description="Execute a database query",
        category=ToolCategory.DATA_RETRIEVAL,
        risk_level=RiskLevel.MEDIUM,
        allowed_data_sensitivity=["public", "internal", "confidential"],
        expected_args=["query"],
        tags=["database", "sql"],
    ))
    
    # File read
    registry.register_tool(ToolDefinition(
        id="read_file",
        name="Read File",
        description="Read contents of a file",
        category=ToolCategory.FILE_SYSTEM,
        risk_level=RiskLevel.LOW,
        expected_args=["path"],
        tags=["file", "read"],
    ))
    
    # File write
    registry.register_tool(ToolDefinition(
        id="write_file",
        name="Write File",
        description="Write contents to a file",
        category=ToolCategory.FILE_SYSTEM,
        risk_level=RiskLevel.HIGH,
        requires_approval=True,
        can_modify_data=True,
        expected_args=["path", "content"],
        tags=["file", "write"],
    ))
    
    # External API call
    registry.register_tool(ToolDefinition(
        id="call_api",
        name="Call External API",
        description="Make HTTP request to external API",
        category=ToolCategory.EXTERNAL_API,
        risk_level=RiskLevel.HIGH,
        requires_approval=True,
        can_access_external=True,
        pii_risk=True,
        expected_args=["url", "method", "data"],
        tags=["api", "http", "external"],
    ))
    
    # Create ticket
    registry.register_tool(ToolDefinition(
        id="create_ticket",
        name="Create Support Ticket",
        description="Create a support or bug ticket",
        category=ToolCategory.INTERNAL_API,
        risk_level=RiskLevel.LOW,
        expected_args=["title", "description"],
        tags=["ticket", "support"],
    ))
