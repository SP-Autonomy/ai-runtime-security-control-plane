"""Tests for observability module."""

import pytest
from airs_cp.observability.registry import (
    AgentRegistry,
    AgentDefinition,
    ToolDefinition,
    ToolCategory,
    RiskLevel,
    get_registry,
)
from airs_cp.observability.tracker import (
    InvocationTracker,
    ToolInvocation,
    InvocationStatus,
    get_tracker,
)
from airs_cp.observability.analyzer import (
    BehaviorAnalyzer,
    DeviationType,
)


class TestRegistry:
    """Test AgentRegistry."""
    
    def test_register_tool(self):
        registry = AgentRegistry()
        tool = ToolDefinition(
            id="test_tool",
            name="Test Tool",
            description="A test tool",
            category=ToolCategory.DATA_RETRIEVAL,
        )
        registry.register_tool(tool)
        
        assert registry.get_tool("test_tool") is not None
        assert registry.get_tool("test_tool").name == "Test Tool"
    
    def test_register_agent(self):
        registry = AgentRegistry()
        agent = AgentDefinition(
            id="test_agent",
            name="Test Agent",
            description="A test agent",
            purpose="Testing",
            allowed_tools=["search_web"],
        )
        registry.register_agent(agent)
        
        assert registry.get_agent("test_agent") is not None
        assert registry.get_agent("test_agent").name == "Test Agent"
    
    def test_validate_tool_call_allowed(self):
        registry = AgentRegistry()
        
        tool = ToolDefinition(
            id="allowed_tool",
            name="Allowed Tool",
            description="An allowed tool",
            category=ToolCategory.DATA_RETRIEVAL,
        )
        registry.register_tool(tool)
        
        agent = AgentDefinition(
            id="agent1",
            name="Agent 1",
            description="Test agent",
            purpose="Testing",
            allowed_tools=["allowed_tool"],
        )
        registry.register_agent(agent)
        
        result = registry.validate_tool_call("agent1", "allowed_tool")
        assert result["allowed"] is True
    
    def test_validate_tool_call_not_allowed(self):
        registry = AgentRegistry()
        
        tool = ToolDefinition(
            id="forbidden_tool",
            name="Forbidden Tool",
            description="A forbidden tool",
            category=ToolCategory.EXTERNAL_API,
        )
        registry.register_tool(tool)
        
        agent = AgentDefinition(
            id="agent2",
            name="Agent 2",
            description="Test agent",
            purpose="Testing",
            allowed_tools=["search_web"],  # Not forbidden_tool
        )
        registry.register_agent(agent)
        
        result = registry.validate_tool_call("agent2", "forbidden_tool")
        assert result["allowed"] is False
    
    def test_list_tools_by_category(self):
        registry = AgentRegistry()
        
        registry.register_tool(ToolDefinition(
            id="tool1", name="T1", description="", category=ToolCategory.DATA_RETRIEVAL
        ))
        registry.register_tool(ToolDefinition(
            id="tool2", name="T2", description="", category=ToolCategory.EXTERNAL_API
        ))
        registry.register_tool(ToolDefinition(
            id="tool3", name="T3", description="", category=ToolCategory.DATA_RETRIEVAL
        ))
        
        retrieval_tools = registry.list_tools(category=ToolCategory.DATA_RETRIEVAL)
        assert len(retrieval_tools) == 2
    
    def test_export_inventory(self):
        registry = AgentRegistry()
        
        registry.register_tool(ToolDefinition(
            id="export_tool", name="Export", description="", category=ToolCategory.DATA_RETRIEVAL
        ))
        registry.register_agent(AgentDefinition(
            id="export_agent", name="Export", description="", purpose=""
        ))
        
        inventory = registry.export_inventory()
        assert "agents" in inventory
        assert "tools" in inventory
        assert "export_tool" in inventory["tools"]
        assert "export_agent" in inventory["agents"]


class TestTracker:
    """Test InvocationTracker."""
    
    def test_record_invocation(self):
        tracker = InvocationTracker()
        
        inv = ToolInvocation(
            session_id="sess1",
            agent_id="agent1",
            tool_id="search_web",
            reasoning="User asked to search",
        )
        inv_id = tracker.record(inv)
        
        assert inv_id is not None
        assert len(tracker.get_by_session("sess1")) == 1
    
    def test_update_status(self):
        tracker = InvocationTracker()
        
        inv = ToolInvocation(
            session_id="sess2",
            agent_id="agent1",
            tool_id="search_web",
        )
        inv.started_at = inv.timestamp
        inv_id = tracker.record(inv)
        
        updated = tracker.update_status(inv_id, InvocationStatus.SUCCESS, result="Found results")
        
        assert updated is not None
        assert updated.status == InvocationStatus.SUCCESS
        assert updated.output_result == "Found results"
    
    def test_get_by_agent(self):
        tracker = InvocationTracker()
        
        tracker.record(ToolInvocation(session_id="s1", agent_id="agent_a", tool_id="t1"))
        tracker.record(ToolInvocation(session_id="s2", agent_id="agent_b", tool_id="t2"))
        tracker.record(ToolInvocation(session_id="s3", agent_id="agent_a", tool_id="t3"))
        
        agent_a_calls = tracker.get_by_agent("agent_a")
        assert len(agent_a_calls) == 2
    
    def test_get_by_tool(self):
        tracker = InvocationTracker()
        
        tracker.record(ToolInvocation(session_id="s1", agent_id="a1", tool_id="search_web"))
        tracker.record(ToolInvocation(session_id="s2", agent_id="a2", tool_id="send_email"))
        tracker.record(ToolInvocation(session_id="s3", agent_id="a3", tool_id="search_web"))
        
        search_calls = tracker.get_by_tool("search_web")
        assert len(search_calls) == 2
    
    def test_get_stats(self):
        tracker = InvocationTracker()
        
        inv1 = ToolInvocation(session_id="s1", agent_id="a1", tool_id="t1")
        inv1.status = InvocationStatus.SUCCESS
        inv1.latency_ms = 100
        tracker.record(inv1)
        
        inv2 = ToolInvocation(session_id="s2", agent_id="a1", tool_id="t2")
        inv2.status = InvocationStatus.FAILED
        inv2.latency_ms = 200
        tracker.record(inv2)
        
        stats = tracker.get_stats()
        assert stats["total"] == 2
        assert stats["success"] == 1
        assert stats["failed"] == 1
        assert stats["avg_latency_ms"] == 150


class TestAnalyzer:
    """Test BehaviorAnalyzer."""
    
    def test_detect_unexpected_tool(self):
        registry = get_registry()  # Use global registry
        
        # Register fresh agent for this test
        agent = AgentDefinition(
            id="restricted_agent_test1",
            name="Restricted Agent",
            description="Has limited tools",
            purpose="Testing",
            allowed_tools=["search_web"],
        )
        registry.register_agent(agent)
        
        registry.register_tool(ToolDefinition(
            id="forbidden_api_test1",
            name="Forbidden API",
            description="Should not be called",
            category=ToolCategory.EXTERNAL_API,
        ))
        
        analyzer = BehaviorAnalyzer()
        
        inv = ToolInvocation(
            session_id="s1",
            agent_id="restricted_agent_test1",
            tool_id="forbidden_api_test1",
        )
        
        alerts = analyzer.analyze_invocation(inv)
        
        assert len(alerts) >= 1
        unexpected_alerts = [a for a in alerts if a.deviation_type == DeviationType.UNEXPECTED_TOOL]
        assert len(unexpected_alerts) == 1
        assert unexpected_alerts[0].severity == "high"
    
    def test_detect_high_risk_tool(self):
        registry = get_registry()  # Use global registry
        
        agent = AgentDefinition(
            id="low_risk_agent_test2",
            name="Low Risk Agent",
            description="Only low risk tolerance",
            purpose="Testing",
            risk_tolerance=RiskLevel.LOW,
        )
        registry.register_agent(agent)
        
        registry.register_tool(ToolDefinition(
            id="high_risk_tool_test2",
            name="High Risk Tool",
            description="A high risk tool",
            category=ToolCategory.FILE_SYSTEM,
            risk_level=RiskLevel.HIGH,
        ))
        
        analyzer = BehaviorAnalyzer()
        
        inv = ToolInvocation(
            session_id="s2",
            agent_id="low_risk_agent_test2",
            tool_id="high_risk_tool_test2",
        )
        
        alerts = analyzer.analyze_invocation(inv)
        
        risk_alerts = [a for a in alerts if a.deviation_type == DeviationType.HIGH_RISK_TOOL]
        assert len(risk_alerts) == 1
    
    def test_detect_excessive_calls(self):
        registry = get_registry()  # Use global registry
        
        agent = AgentDefinition(
            id="limited_agent_test3",
            name="Limited Agent",
            description="Max 2 calls",
            purpose="Testing",
            max_tool_calls_per_request=2,
        )
        registry.register_agent(agent)
        
        analyzer = BehaviorAnalyzer()
        
        # Simulate history - same session
        history = [
            ToolInvocation(session_id="s3_test", agent_id="limited_agent_test3", tool_id="t1"),
            ToolInvocation(session_id="s3_test", agent_id="limited_agent_test3", tool_id="t2"),
        ]
        
        # Third call should trigger alert
        inv = ToolInvocation(
            session_id="s3_test",
            agent_id="limited_agent_test3",
            tool_id="t3",
        )
        
        alerts = analyzer.analyze_invocation(inv, session_history=history)
        
        excessive_alerts = [a for a in alerts if a.deviation_type == DeviationType.EXCESSIVE_CALLS]
        assert len(excessive_alerts) == 1
    
    def test_explain_decision(self):
        registry = get_registry()  # Use global with default tools
        
        registry.register_agent(AgentDefinition(
            id="explainer_agent",
            name="Explainer Agent",
            description="For testing explanations",
            purpose="Search and retrieve information",
            allowed_tools=["search_web"],
            risk_tolerance=RiskLevel.LOW,
        ))
        
        analyzer = BehaviorAnalyzer()
        
        inv = ToolInvocation(
            session_id="s4",
            agent_id="explainer_agent",
            tool_id="search_web",
            reasoning="User asked to find information about AI",
            user_intent="Research AI topics",
            expected_outcome="Return relevant search results",
        )
        
        explanation = analyzer.explain_decision(inv)
        
        assert explanation["tool"] == "search_web"
        assert explanation["reasoning"] == "User asked to find information about AI"
        assert "analysis" in explanation
        assert explanation["analysis"]["tool_allowed"] is True


class TestGlobalInstances:
    """Test global singleton instances."""
    
    def test_get_registry_returns_same_instance(self):
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2
    
    def test_get_tracker_returns_same_instance(self):
        t1 = get_tracker()
        t2 = get_tracker()
        assert t1 is t2
    
    def test_default_tools_registered(self):
        registry = get_registry()
        
        # Check some default tools exist
        assert registry.get_tool("search_web") is not None
        assert registry.get_tool("send_email") is not None
        assert registry.get_tool("query_database") is not None
