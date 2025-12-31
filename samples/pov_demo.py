#!/usr/bin/env python3
"""
POV Demo: Populate Dashboard with Realistic Agent Behavior

This script demonstrates the AIRS-CP agent observability capabilities by:
1. Registering multiple agents with their allowed tools
2. Simulating realistic tool invocations with reasoning
3. Introducing intentional behavioral deviations (non-deterministic)
4. Showing blocked actions and anomaly detection

Run this AFTER starting the gateway and dashboard to see data in the Agents tab.

USAGE:
    # Terminal 1: Start gateway
    AIRS_MODE=enforce uvicorn airs_cp.gateway.app:app --port 8080
    
    # Terminal 2: Start dashboard  
    uvicorn airs_cp.dashboard.app:app --port 8501
    
    # Terminal 3: Run this demo
    python samples/pov_demo.py
    
    # Then visit http://localhost:8501/dashboard/agents
"""

import os
import sys
import random
import time
import uuid
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from airs_cp.observability import (
    get_registry, get_tracker, BehaviorAnalyzer,
    AgentDefinition, ToolDefinition, ToolInvocation,
)
from airs_cp.observability.registry import ToolCategory, RiskLevel
from airs_cp.observability.tracker import InvocationStatus
from airs_cp.store.database import get_store


def setup_tools(registry):
    """Register enterprise tools."""
    tools = [
        # Customer Support Tools
        ToolDefinition(
            id="get_customer_data",
            name="Get Customer Data",
            description="Retrieve customer PII from database",
            category=ToolCategory.DATA_RETRIEVAL,
            risk_level=RiskLevel.MEDIUM,
            pii_risk=True,
            expected_args=["customer_id"],
        ),
        ToolDefinition(
            id="search_knowledge_base",
            name="Search Knowledge Base",
            description="Search internal KB articles",
            category=ToolCategory.DATA_RETRIEVAL,
            risk_level=RiskLevel.LOW,
            expected_args=["query"],
        ),
        ToolDefinition(
            id="create_support_ticket",
            name="Create Support Ticket",
            description="Create a new support ticket",
            category=ToolCategory.INTERNAL_API,
            risk_level=RiskLevel.LOW,
            expected_args=["customer_id", "issue"],
        ),
        ToolDefinition(
            id="generate_response",
            name="Generate LLM Response",
            description="Generate response via LLM gateway",
            category=ToolCategory.EXTERNAL_API,
            risk_level=RiskLevel.MEDIUM,
            can_access_external=True,
        ),
        # Finance Tools (high risk)
        ToolDefinition(
            id="process_refund",
            name="Process Refund",
            description="Process customer refund",
            category=ToolCategory.EXTERNAL_API,
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            expected_args=["customer_id", "amount"],
        ),
        ToolDefinition(
            id="update_billing",
            name="Update Billing Info",
            description="Update customer payment method",
            category=ToolCategory.INTERNAL_API,
            risk_level=RiskLevel.CRITICAL,
            pii_risk=True,
            requires_approval=True,
            expected_args=["customer_id", "payment_method"],
        ),
        # Analytics Tools
        ToolDefinition(
            id="run_analytics_query",
            name="Run Analytics Query",
            description="Execute analytics SQL query",
            category=ToolCategory.DATA_RETRIEVAL,
            risk_level=RiskLevel.MEDIUM,
            expected_args=["query"],
        ),
        # External Tools
        ToolDefinition(
            id="send_email",
            name="Send Email",
            description="Send email to customer",
            category=ToolCategory.COMMUNICATION,
            risk_level=RiskLevel.MEDIUM,
            can_access_external=True,
            pii_risk=True,
        ),
    ]
    
    for tool in tools:
        registry.register_tool(tool)
    
    return tools


def setup_agents(registry):
    """Register enterprise agents."""
    agents = [
        AgentDefinition(
            id="customer_support_agent",
            name="Customer Support Agent",
            description="Handles customer support queries",
            purpose="Answer questions, look up accounts, create tickets",
            allowed_tools=["get_customer_data", "search_knowledge_base", "create_support_ticket", "generate_response"],
            max_tool_calls_per_request=5,
            risk_tolerance=RiskLevel.MEDIUM,
            typical_tool_sequence=["get_customer_data", "search_knowledge_base", "generate_response"],
        ),
        AgentDefinition(
            id="billing_agent",
            name="Billing & Refunds Agent",
            description="Handles billing and refund requests",
            purpose="Process refunds, update billing, handle payment issues",
            allowed_tools=["get_customer_data", "process_refund", "update_billing", "send_email"],
            max_tool_calls_per_request=4,
            risk_tolerance=RiskLevel.HIGH,
            typical_tool_sequence=["get_customer_data", "process_refund", "send_email"],
        ),
        AgentDefinition(
            id="analytics_agent",
            name="Analytics Agent",
            description="Runs analytics queries and reports",
            purpose="Generate reports, run queries, analyze data",
            allowed_tools=["run_analytics_query", "search_knowledge_base"],
            max_tool_calls_per_request=3,
            risk_tolerance=RiskLevel.LOW,
            typical_tool_sequence=["run_analytics_query"],
        ),
    ]
    
    for agent in agents:
        registry.register_agent(agent)
    
    return agents


def simulate_customer_support_session(tracker, analyzer, session_num: int):
    """Simulate a customer support interaction."""
    session_id = f"support_{uuid.uuid4().hex[:8]}"
    agent_id = "customer_support_agent"
    
    queries = [
        "What is my account balance?",
        "How do I reset my password?",
        "I need help with my order #12345",
        "Can you explain your refund policy?",
        "My payment failed, what should I do?",
    ]
    query = random.choice(queries)
    
    # Normal flow: get_customer_data -> search_kb -> generate_response
    invocations = []
    
    # Step 1: Get customer data
    inv1 = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id="get_customer_data",
        reasoning=f"Customer is authenticated (C{random.randint(100,999)}), retrieving account data to personalize response",
        user_intent=f"Customer query: {query}",
        input_args={"customer_id": f"C{random.randint(100,999)}"},
        status=InvocationStatus.SUCCESS,
    )
    analyzer.analyze_invocation(inv1, session_history=[])
    tracker.record(inv1)
    invocations.append(inv1)
    
    # Step 2: Search KB
    inv2 = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id="search_knowledge_base",
        reasoning=f"Searching KB for articles related to: {query[:30]}",
        user_intent=query,
        input_args={"query": query},
        status=InvocationStatus.SUCCESS,
    )
    analyzer.analyze_invocation(inv2, session_history=invocations)
    tracker.record(inv2)
    invocations.append(inv2)
    
    # Step 3: Generate response
    inv3 = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id="generate_response",
        reasoning="Generating personalized response using KB articles and customer context",
        user_intent=f"Answer: {query}",
        input_args={"context_size": random.randint(500, 2000)},
        status=InvocationStatus.SUCCESS,
    )
    analyzer.analyze_invocation(inv3, session_history=invocations)
    tracker.record(inv3)
    
    return session_id, "normal"


def simulate_billing_session(tracker, analyzer, session_num: int):
    """Simulate a billing/refund interaction."""
    session_id = f"billing_{uuid.uuid4().hex[:8]}"
    agent_id = "billing_agent"
    
    # Normal flow with approval requirement
    invocations = []
    
    # Step 1: Get customer data
    inv1 = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id="get_customer_data",
        reasoning="Retrieving customer billing history and account status",
        user_intent="Customer requested a refund",
        input_args={"customer_id": f"C{random.randint(100,999)}"},
        status=InvocationStatus.SUCCESS,
    )
    analyzer.analyze_invocation(inv1, session_history=[])
    tracker.record(inv1)
    invocations.append(inv1)
    
    # Step 2: Process refund (requires approval - marked as pending)
    amount = round(random.uniform(10, 500), 2)
    inv2 = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id="process_refund",
        reasoning=f"Processing refund of ${amount} - requires manager approval",
        user_intent="Process customer refund request",
        input_args={"customer_id": f"C{random.randint(100,999)}", "amount": amount},
        status=InvocationStatus.PENDING,  # Pending approval
    )
    analyzer.analyze_invocation(inv2, session_history=invocations)
    tracker.record(inv2)
    invocations.append(inv2)
    
    # Step 3: Send confirmation email
    inv3 = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id="send_email",
        reasoning="Sending refund confirmation email to customer",
        user_intent="Notify customer about refund status",
        input_args={"template": "refund_pending"},
        status=InvocationStatus.SUCCESS,
    )
    analyzer.analyze_invocation(inv3, session_history=invocations)
    tracker.record(inv3)
    
    return session_id, "pending_approval"


def simulate_deviation_scenario(tracker, analyzer, scenario_type: str):
    """Simulate behavioral deviations to demonstrate anomaly detection."""
    session_id = f"deviation_{uuid.uuid4().hex[:8]}"
    
    if scenario_type == "wrong_agent":
        # Analytics agent trying to access customer data (not allowed)
        inv = ToolInvocation(
            session_id=session_id,
            agent_id="analytics_agent",
            tool_id="get_customer_data",  # Not in analytics agent's allowed tools!
            reasoning="Trying to get customer data for report",
            user_intent="Generate customer analytics report",
            input_args={"customer_id": "C001"},
            status=InvocationStatus.BLOCKED,
            was_blocked=True,
            block_reason="Tool not in agent's allowed list",
            deviation_score=0.85,
            deviation_reasons=["Unauthorized tool access", "Tool not in allowed_tools list"],
        )
        tracker.record(inv)
        return session_id, "blocked_unauthorized"
    
    elif scenario_type == "pii_leak":
        # Support agent trying to send PII externally
        invocations = []
        
        inv1 = ToolInvocation(
            session_id=session_id,
            agent_id="customer_support_agent",
            tool_id="get_customer_data",
            reasoning="Getting customer data for email",
            user_intent="Send customer details via email",
            input_args={"customer_id": "C123"},
            status=InvocationStatus.SUCCESS,
        )
        tracker.record(inv1)
        invocations.append(inv1)
        
        # Attempting to send email with PII (should be blocked)
        inv2 = ToolInvocation(
            session_id=session_id,
            agent_id="customer_support_agent",
            tool_id="send_email",  # Not in support agent's allowed tools!
            reasoning="Attempting to email customer SSN and credit card",
            user_intent="Send sensitive data externally",
            input_args={"content": "SSN: 123-45-6789"},
            status=InvocationStatus.BLOCKED,
            was_blocked=True,
            block_reason="PII detected in external communication",
            deviation_score=0.92,
            deviation_reasons=["PII in external tool call", "Unauthorized tool for agent", "Data exfiltration attempt"],
        )
        analyzer.analyze_invocation(inv2, session_history=invocations)
        tracker.record(inv2)
        return session_id, "blocked_pii"
    
    elif scenario_type == "excessive_calls":
        # Agent making too many tool calls (suspicious behavior)
        invocations = []
        for i in range(8):  # More than max_tool_calls_per_request (5)
            inv = ToolInvocation(
                session_id=session_id,
                agent_id="customer_support_agent",
                tool_id="search_knowledge_base",
                reasoning=f"Search attempt {i+1} for customer query",
                user_intent="Repeated search attempts",
                input_args={"query": f"search {i}"},
                status=InvocationStatus.SUCCESS if i < 5 else InvocationStatus.BLOCKED,
                was_blocked=i >= 5,
                block_reason="Exceeded max tool calls" if i >= 5 else "",
                deviation_score=0.3 + (i * 0.1) if i >= 3 else 0,
                deviation_reasons=["Excessive tool calls"] if i >= 3 else [],
            )
            tracker.record(inv)
            invocations.append(inv)
        return session_id, "excessive_calls"
    
    elif scenario_type == "sequence_anomaly":
        # Agent using tools in unexpected order
        invocations = []
        
        # Normally: get_customer_data -> search_kb -> generate_response
        # Anomaly: generate_response first (without context)
        inv1 = ToolInvocation(
            session_id=session_id,
            agent_id="customer_support_agent",
            tool_id="generate_response",  # Should not be first!
            reasoning="Generating response without customer context",
            user_intent="Answer customer question",
            input_args={},
            status=InvocationStatus.SUCCESS,
            deviation_score=0.65,
            deviation_reasons=["Unexpected tool sequence", "generate_response called before get_customer_data"],
        )
        tracker.record(inv1)
        return session_id, "sequence_anomaly"
    
    return session_id, "unknown"


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    AIRS-CP POV DEMO - Agent Observability                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This demo populates the dashboard with realistic agent behavior including:  ║
║    • Multiple agents with different risk levels                              ║
║    • Tool invocations with reasoning chains                                  ║
║    • Behavioral deviations and anomaly detection                             ║
║    • Blocked actions and security enforcement                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize components
    print("Initializing observability components...")
    registry = get_registry()
    tracker = get_tracker()
    analyzer = BehaviorAnalyzer()
    store = get_store()
    
    print(f"Database path: {store.db_path}")
    
    # Setup tools and agents
    print("\n1. Registering tools and agents...")
    tools = setup_tools(registry)
    print(f"   ✓ Registered {len(tools)} tools")
    
    agents = setup_agents(registry)
    print(f"   ✓ Registered {len(agents)} agents")
    
    # Simulate normal customer support sessions
    print("\n2. Simulating customer support sessions...")
    for i in range(5):
        session_id, result = simulate_customer_support_session(tracker, analyzer, i)
        print(f"   ✓ Session {session_id}: {result}")
        time.sleep(0.1)
    
    # Simulate billing sessions
    print("\n3. Simulating billing/refund sessions...")
    for i in range(3):
        session_id, result = simulate_billing_session(tracker, analyzer, i)
        print(f"   ✓ Session {session_id}: {result}")
        time.sleep(0.1)
    
    # Simulate deviation scenarios
    print("\n4. Simulating behavioral deviations (anomaly detection)...")
    
    deviation_scenarios = [
        ("wrong_agent", "Analytics agent accessing unauthorized tool"),
        ("pii_leak", "Attempted PII exfiltration via email"),
        ("excessive_calls", "Agent making too many tool calls"),
        ("sequence_anomaly", "Agent using tools in wrong order"),
    ]
    
    for scenario_type, description in deviation_scenarios:
        session_id, result = simulate_deviation_scenario(tracker, analyzer, scenario_type)
        print(f"   ⚠️  {description}: {result}")
        time.sleep(0.1)
    
    # Print summary
    print("\n" + "="*70)
    print("DEMO COMPLETE - Dashboard Data Summary")
    print("="*70)
    
    db_agents = store.get_agent_registrations()
    db_invocations = store.get_recent_invocations(limit=100)
    db_stats = store.get_invocation_stats()
    db_deviations = store.get_invocations_with_deviations(min_score=0.3)
    
    print(f"\nAgents registered: {len(db_agents)}")
    for a in db_agents:
        print(f"  • {a['name']} ({a['id']})")
    
    print(f"\nTool invocations: {db_stats['total']}")
    print(f"  By agent: {db_stats['by_agent']}")
    print(f"  By tool: {db_stats['by_tool']}")
    
    print(f"\nDeviations detected: {len(db_deviations)}")
    for d in db_deviations[:5]:
        print(f"  ⚠️  {d['tool_id']} (score: {d['deviation_score']:.0%}): {d['deviation_reasons']}")
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                              VIEW IN DASHBOARD                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Visit: http://localhost:8501/dashboard/agents                               ║
║                                                                              ║
║  You should see:                                                             ║
║    • 3 registered agents with their allowed tools                            ║
║    • ~30+ tool invocations with reasoning                                    ║
║    • {len(db_deviations):2d} behavioral deviations (blocked/anomalous actions)              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


if __name__ == "__main__":
    main()
