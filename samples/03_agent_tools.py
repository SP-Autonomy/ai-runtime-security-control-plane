#!/usr/bin/env python3
"""
Sample 3: Agentic AI Assistant (Tool Calling)

This simulates an AI agent that can call external tools/APIs.
AIRS-CP monitors tool calls to prevent:
- Sensitive data being sent to external services
- Malicious tool invocations
- Policy violations

USAGE:
    # Start AIRS-CP gateway first
    uvicorn airs_cp.gateway.app:app --port 8080
    
    # Then run this agent
    python samples/03_agent_tools.py

WHAT IT TESTS:
    - Tool call security monitoring
    - Taint propagation to tool arguments
    - Blocking sensitive data from external APIs
    - Policy-based tool restrictions
"""

import os
import sys
import json
from typing import Callable
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from openai import OpenAI
except ImportError:
    print("ERROR: Please install openai: pip install openai")
    sys.exit(1)

from airs_cp.security.taint import TaintEngine
from airs_cp.security.detectors.pii import get_pii_detector
from airs_cp.store.models import TaintSourceType, TaintSensitivity

# Import observability for agent/tool tracking
from airs_cp.observability import (
    get_registry, get_tracker, BehaviorAnalyzer,
    AgentDefinition, ToolDefinition, ToolInvocation,
)
from airs_cp.observability.registry import ToolCategory, RiskLevel
from airs_cp.observability.tracker import InvocationStatus


# Simulated tools the agent can use
@dataclass
class Tool:
    name: str
    description: str
    is_external: bool  # True = sends data outside organization
    requires_approval: bool


AVAILABLE_TOOLS = {
    "search_web": Tool(
        name="search_web",
        description="Search the web for information",
        is_external=True,
        requires_approval=False,
    ),
    "send_email": Tool(
        name="send_email",
        description="Send an email to a recipient",
        is_external=True,
        requires_approval=True,
    ),
    "query_database": Tool(
        name="query_database",
        description="Query internal database",
        is_external=False,
        requires_approval=False,
    ),
    "create_ticket": Tool(
        name="create_ticket",
        description="Create a support ticket",
        is_external=False,
        requires_approval=False,
    ),
    "call_external_api": Tool(
        name="call_external_api",
        description="Call an external third-party API",
        is_external=True,
        requires_approval=True,
    ),
}


class SecureAgentFramework:
    """Agent framework with AIRS-CP security."""
    
    AGENT_ID = "secure_tool_agent"
    
    def __init__(self, gateway_url: str = "http://localhost:8080"):
        self.client = OpenAI(
            base_url=f"{gateway_url}/v1",
            api_key=os.getenv("OPENAI_API_KEY", "not-needed-for-ollama"),
        )
        self.taint_engine = TaintEngine()
        self.pii_detector = get_pii_detector()
        self.model = os.getenv("AIRS_MODEL", "llama3.2:1b")
        
        # Initialize observability
        self.registry = get_registry()
        self.tracker = get_tracker()
        self.analyzer = BehaviorAnalyzer()
        self._register_agent()
    
    def _register_agent(self):
        """Register this agent and its tools with observability."""
        # Register tools based on AVAILABLE_TOOLS
        for tool_id, tool in AVAILABLE_TOOLS.items():
            self.registry.register_tool(ToolDefinition(
                id=tool_id,
                name=tool.name,
                description=tool.description,
                category=ToolCategory.EXTERNAL_API if tool.is_external else ToolCategory.INTERNAL_API,
                risk_level=RiskLevel.HIGH if tool.requires_approval else RiskLevel.MEDIUM if tool.is_external else RiskLevel.LOW,
                can_access_external=tool.is_external,
                requires_approval=tool.requires_approval,
            ))
        
        # Register agent
        self.registry.register_agent(AgentDefinition(
            id=self.AGENT_ID,
            name="Secure Tool Agent",
            description="AI agent with security-monitored tool calling",
            purpose="Execute tools safely with PII protection and taint tracking",
            allowed_tools=list(AVAILABLE_TOOLS.keys()),
            max_tool_calls_per_request=5,
            risk_tolerance=RiskLevel.MEDIUM,
            typical_tool_sequence=["search_web", "save_to_database"],
        ))
    
    def _track_tool_call(
        self,
        tool_id: str,
        reasoning: str,
        user_intent: str,
        args: dict,
        session_id: str,
        status: InvocationStatus = InvocationStatus.SUCCESS,
        blocked: bool = False,
        block_reason: str = ""
    ) -> ToolInvocation:
        """Track a tool invocation with reasoning."""
        invocation = ToolInvocation(
            session_id=session_id,
            agent_id=self.AGENT_ID,
            tool_id=tool_id,
            reasoning=reasoning,
            user_intent=user_intent,
            input_args=args,
            status=status,
            was_blocked=blocked,
            block_reason=block_reason,
        )
        
        # Analyze for deviations
        history = self.tracker.get_by_session(session_id)
        self.analyzer.analyze_invocation(invocation, session_history=history)
        
        # Record
        self.tracker.record(invocation)
        return invocation
    
    def execute_tool(self, tool_name: str, arguments: dict, context_taint, session_id: str = "", user_intent: str = "") -> dict:
        """Execute a tool with security checks."""
        
        tool = AVAILABLE_TOOLS.get(tool_name)
        if not tool:
            return {"error": f"Unknown tool: {tool_name}", "blocked": True}
        
        # Security Check 1: PII in arguments
        args_str = json.dumps(arguments)
        pii_result = self.pii_detector.analyze(args_str)
        
        if pii_result["has_pii"]:
            # Track blocked invocation
            self._track_tool_call(
                tool_id=tool_name,
                reasoning=f"Attempted to call {tool_name} but PII was detected in arguments",
                user_intent=user_intent,
                args=arguments,
                session_id=session_id,
                status=InvocationStatus.BLOCKED,
                blocked=True,
                block_reason="PII detected in arguments",
            )
            return {
                "error": f"PII detected in tool arguments: {list(pii_result['by_pattern'].keys())}",
                "blocked": True,
                "reason": "pii_leak_prevention",
            }
        
        # Security Check 2: Taint-based restrictions for external tools
        if tool.is_external and context_taint:
            sink_check = self.taint_engine.check_sink(context_taint, "external_api")
            
            if not sink_check["allowed"]:
                # Track blocked invocation
                self._track_tool_call(
                    tool_id=tool_name,
                    reasoning=f"Attempted to call external tool {tool_name} but taint policy blocked it",
                    user_intent=user_intent,
                    args=arguments,
                    session_id=session_id,
                    status=InvocationStatus.BLOCKED,
                    blocked=True,
                    block_reason=f"Taint policy: {context_taint.max_sensitivity.value} data cannot go to external API",
                )
                return {
                    "error": f"Cannot send {context_taint.max_sensitivity.value} data to external tool",
                    "blocked": True,
                    "reason": "taint_policy_violation",
                    "alerts": sink_check.get("alerts", []),
                }
        
        # Security Check 3: Approval required
        if tool.requires_approval:
            # Track invocation needing approval
            self._track_tool_call(
                tool_id=tool_name,
                reasoning=f"Tool {tool_name} requires manual approval before execution",
                user_intent=user_intent,
                args=arguments,
                session_id=session_id,
                status=InvocationStatus.PENDING,
            )
            return {
                "warning": f"Tool {tool_name} requires approval",
                "blocked": False,
                "requires_approval": True,
                "simulated_result": f"Simulated {tool_name} execution",
            }
        
        # Track successful invocation
        self._track_tool_call(
            tool_id=tool_name,
            reasoning=f"Executing {tool_name} - passed all security checks",
            user_intent=user_intent,
            args=arguments,
            session_id=session_id,
            status=InvocationStatus.SUCCESS,
        )
        
        # Execute tool (simulated)
        return {
            "blocked": False,
            "result": f"Simulated {tool_name} execution with args: {arguments}",
        }
    
    def process_request(self, user_input: str, user_id: str = "user_123") -> dict:
        """Process user request that may invoke tools."""
        
        # Create taint for user input
        input_taint = self.taint_engine.create_taint(
            content=user_input,
            source_type=TaintSourceType.USER_INPUT,
            source_id=user_id,
            sensitivity=TaintSensitivity.PUBLIC,
            label="user_request",
        )
        
        # Check for PII in user input
        pii_in_input = self.pii_detector.analyze(user_input)
        if pii_in_input["has_pii"]:
            input_taint = self.taint_engine.create_taint(
                content=user_input,
                source_type=TaintSourceType.USER_INPUT,
                source_id=user_id,
                sensitivity=TaintSensitivity.RESTRICTED,  # Upgrade sensitivity
                label="pii_content",
            )
        
        # Generate session ID for this request
        import uuid
        session_id = f"tools_{uuid.uuid4().hex[:8]}"
        
        # Simulate agent deciding to call tools based on user input
        # In real system, LLM would decide this
        tool_calls = self._simulate_tool_decisions(user_input)
        
        results = []
        any_blocked = False
        for tool_call in tool_calls:
            result = self.execute_tool(
                tool_call["name"],
                tool_call["arguments"],
                input_taint,
                session_id=session_id,
                user_intent=user_input[:100],
            )
            if result.get("blocked"):
                any_blocked = True
            results.append({
                "tool": tool_call["name"],
                "arguments": tool_call["arguments"],
                "result": result,
            })
        
        # If no tools were blocked, make an actual LLM call through gateway
        # This ensures dashboard sees the request
        llm_response = None
        if not any_blocked:
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant with access to tools."},
                        {"role": "user", "content": user_input}
                    ],
                )
                llm_response = response.choices[0].message.content[:100]
            except Exception as e:
                llm_response = f"[LLM call result: {str(e)[:50]}]"
        
        return {
            "user_input": user_input,
            "session_id": session_id,
            "input_sensitivity": input_taint.max_sensitivity.value,
            "pii_detected": pii_in_input["has_pii"],
            "tool_calls": results,
            "llm_response": llm_response,
        }
    
    def _simulate_tool_decisions(self, user_input: str) -> list:
        """Simulate agent deciding which tools to call."""
        # Simple keyword matching for demo
        tools = []
        
        if "search" in user_input.lower() or "find" in user_input.lower():
            tools.append({"name": "search_web", "arguments": {"query": user_input}})
        
        if "email" in user_input.lower() or "send" in user_input.lower():
            tools.append({"name": "send_email", "arguments": {"to": "test@example.com", "body": user_input}})
        
        if "database" in user_input.lower() or "query" in user_input.lower():
            tools.append({"name": "query_database", "arguments": {"query": user_input}})
        
        if "ticket" in user_input.lower():
            tools.append({"name": "create_ticket", "arguments": {"description": user_input}})
        
        if "api" in user_input.lower() or "external" in user_input.lower():
            tools.append({"name": "call_external_api", "arguments": {"data": user_input}})
        
        # Default to web search if nothing matches
        if not tools:
            tools.append({"name": "search_web", "arguments": {"query": user_input}})
        
        return tools


def main():
    print("=" * 60)
    print("  Agentic AI Assistant (Tool Calling)")
    print("  Testing AIRS-CP Tool Security")
    print("=" * 60)
    
    agent = SecureAgentFramework()
    
    # Test scenarios
    test_scenarios = [
        # Normal tool call - should succeed
        {
            "input": "Search the web for Python tutorials",
            "expected_blocked": False,
            "description": "Normal web search - should succeed",
        },
        # PII in tool arguments - should block
        {
            "input": "Send email with my SSN 123-45-6789 to support",
            "expected_blocked": True,
            "description": "PII in email - should block send_email",
        },
        # External API with sensitive context
        {
            "input": "Call external API with customer credit card 4111-1111-1111-1111",
            "expected_blocked": True,
            "description": "Sensitive data to external API - should block",
        },
        # Internal tool - should succeed even with some data
        {
            "input": "Query database for user john@example.com",
            "expected_blocked": False,
            "description": "Internal database query - allowed",
        },
        # Requires approval
        {
            "input": "Send email to notify the team",
            "expected_blocked": False,
            "description": "Email requires approval workflow",
        },
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n--- Test {i}: {scenario['description']} ---")
        print(f"Input: {scenario['input'][:60]}...")
        print(f"Expected blocked: {scenario['expected_blocked']}")
        print()
        
        result = agent.process_request(scenario["input"])
        
        print(f"Input sensitivity: {result['input_sensitivity']}")
        print(f"PII detected: {result['pii_detected']}")
        print()
        
        for tool_result in result["tool_calls"]:
            print(f"Tool: {tool_result['tool']}")
            print(f"Arguments: {json.dumps(tool_result['arguments'])[:60]}...")
            
            tr = tool_result["result"]
            if tr.get("blocked"):
                print(f"⛔ BLOCKED: {tr.get('error', 'Unknown reason')}")
                print(f"   Reason: {tr.get('reason', 'N/A')}")
            elif tr.get("requires_approval"):
                print(f"⚠️ REQUIRES APPROVAL: {tr.get('warning')}")
            else:
                print(f"✓ Executed: {tr.get('result', 'Success')[:50]}...")
            print()
        
        print("-" * 40)
    
    print("\n" + "=" * 60)
    print("  Agent Tests Complete!")
    print("  Tool calls are monitored for security violations")
    print("=" * 60)


if __name__ == "__main__":
    main()
