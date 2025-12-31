# AIRS-CP Observability Module

## Overview

The Observability module provides visibility into agentic AI behavior, enabling:

- **Agent/Tool Registry**: Inventory of all AI agents and their available tools
- **Invocation Tracking**: Record of all tool calls with reasoning
- **Behavioral Analysis**: Detection of deviations from expected patterns
- **Decision Explanation**: Understanding why specific tools were selected

## Problem Statement

AI agents with tool-calling capabilities introduce unique security challenges:

1. **Non-deterministic behavior**: Same input may trigger different tools
2. **Invisible reasoning**: Why did the agent choose tool A over tool B?
3. **Privilege escalation**: Agent might call unauthorized tools
4. **Unusual patterns**: Hard to detect when behavior deviates from normal

## Components

### 1. Agent Registry

Central inventory of all registered agents and tools.

```python
from airs_cp.observability import get_registry, AgentDefinition, ToolDefinition

registry = get_registry()

# Register a custom agent
registry.register_agent(AgentDefinition(
    id="support_agent",
    name="Customer Support Agent",
    description="Handles customer inquiries",
    purpose="Answer questions and resolve issues",
    allowed_tools=["search_kb", "create_ticket", "send_email"],
    max_tool_calls_per_request=5,
    risk_tolerance=RiskLevel.MEDIUM,
    typical_tool_sequence=["search_kb", "create_ticket"],
))

# Register a custom tool
registry.register_tool(ToolDefinition(
    id="search_kb",
    name="Search Knowledge Base",
    description="Search internal knowledge base",
    category=ToolCategory.DATA_RETRIEVAL,
    risk_level=RiskLevel.LOW,
    expected_args=["query"],
))
```

### 2. Invocation Tracker

Records all tool invocations with full context.

```python
from airs_cp.observability import get_tracker, ToolInvocation

tracker = get_tracker()

# Record a tool invocation
invocation = ToolInvocation(
    session_id="sess_123",
    agent_id="support_agent",
    tool_id="search_kb",
    
    # Reasoning (captured from LLM)
    reasoning="User asked about refund policy, searching KB for relevant articles",
    user_intent="Get information about refund policy",
    expected_outcome="Find refund policy document",
    
    # Input/Output
    input_args={"query": "refund policy"},
    input_context="User message: What is your refund policy?",
)

inv_id = tracker.record(invocation)

# Update when complete
tracker.update_status(inv_id, InvocationStatus.SUCCESS, result={"docs": [...]})
```

### 3. Behavioral Analyzer

Detects deviations from expected agent behavior.

```python
from airs_cp.observability import BehaviorAnalyzer

analyzer = BehaviorAnalyzer()

# Analyze an invocation
alerts = analyzer.analyze_invocation(invocation, session_history=previous_invocations)

for alert in alerts:
    print(f"⚠️ {alert.deviation_type.value}: {alert.description}")
    print(f"   Expected: {alert.expected_behavior}")
    print(f"   Actual: {alert.actual_behavior}")
    print(f"   Recommendations: {alert.recommendations}")
```

## Deviation Types

| Type | Description | Severity |
|------|-------------|----------|
| `UNEXPECTED_TOOL` | Agent called a tool not in its allowed list | High |
| `HIGH_RISK_TOOL` | Tool risk exceeds agent's tolerance | Medium-High |
| `UNUSUAL_SEQUENCE` | Tool order doesn't match expected pattern | Medium |
| `EXCESSIVE_CALLS` | Too many tool calls in one session | Medium |
| `UNEXPECTED_ARGS` | Arguments don't match expected schema | Low |
| `SENSITIVITY_VIOLATION` | Data sensitivity mismatch | High |

## Usage Example

### Complete Agent Call Flow

```python
from airs_cp.observability import (
    get_registry, get_tracker, BehaviorAnalyzer,
    AgentDefinition, ToolInvocation, InvocationStatus
)

# Setup
registry = get_registry()
tracker = get_tracker()
analyzer = BehaviorAnalyzer()

# Register agent
registry.register_agent(AgentDefinition(
    id="my_agent",
    name="My Agent",
    description="Does things",
    purpose="Help users",
    allowed_tools=["search_web", "create_ticket"],
    max_tool_calls_per_request=3,
))

# When agent decides to call a tool
def on_tool_call(agent_id, tool_id, args, reasoning, session_id):
    # 1. Validate with registry
    validation = registry.validate_tool_call(agent_id, tool_id)
    if not validation["allowed"]:
        return {"blocked": True, "reason": validation["reason"]}
    
    # 2. Create invocation record
    invocation = ToolInvocation(
        session_id=session_id,
        agent_id=agent_id,
        tool_id=tool_id,
        input_args=args,
        reasoning=reasoning,
    )
    
    # 3. Analyze for deviations
    history = tracker.get_by_session(session_id)
    alerts = analyzer.analyze_invocation(invocation, session_history=history)
    
    if alerts:
        for alert in alerts:
            if alert.severity in ["high", "critical"]:
                return {"blocked": True, "alert": alert.to_dict()}
    
    # 4. Record invocation
    inv_id = tracker.record(invocation)
    
    # 5. Execute tool (your code here)
    result = execute_tool(tool_id, args)
    
    # 6. Update status
    tracker.update_status(inv_id, InvocationStatus.SUCCESS, result=result)
    
    return {"success": True, "result": result}
```

### Explain Agent Decisions

```python
# Get explanation for a tool call
explanation = analyzer.explain_decision(invocation)

print(f"Tool: {explanation['tool']}")
print(f"Reasoning: {explanation['reasoning']}")
print(f"User Intent: {explanation['user_intent']}")
print(f"Analysis:")
print(f"  - Tool Allowed: {explanation['analysis']['tool_allowed']}")
print(f"  - Within Risk Tolerance: {explanation['analysis']['within_risk_tolerance']}")
```

## Integration with Gateway

The observability module can be integrated with the AIRS-CP gateway to automatically track all tool calls:

```python
# In gateway tool call handler
from airs_cp.observability import get_tracker, get_registry, BehaviorAnalyzer

@app.post("/v1/tool_call")
async def handle_tool_call(request: ToolCallRequest):
    tracker = get_tracker()
    analyzer = BehaviorAnalyzer()
    
    # Create invocation
    invocation = ToolInvocation(
        session_id=request.session_id,
        agent_id=request.agent_id,
        tool_id=request.tool_id,
        reasoning=request.reasoning,
        input_args=request.arguments,
    )
    
    # Analyze
    alerts = analyzer.analyze_invocation(invocation)
    
    # Block if high severity deviation
    high_severity = [a for a in alerts if a.severity in ["high", "critical"]]
    if high_severity:
        return {"blocked": True, "alerts": [a.to_dict() for a in high_severity]}
    
    # Continue with tool execution...
```

## Dashboard Integration

The dashboard includes a dedicated **Agents** tab (`/dashboard/agents`) that displays:

- **Tool Inventory**: All registered tools with risk levels, categories, and access flags
- **Agent Registry**: Registered agents with their allowed tools and risk tolerances
- **Recent Invocations**: Tool calls with reasoning captured from the agent
- **Deviation Alerts**: Real-time alerts when behavior deviates from expected patterns

### Dashboard API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/agents/stats/tools` | Count of registered tools |
| `/api/agents/stats/agents` | Count of registered agents |
| `/api/agents/stats/invocations` | Total invocation count |
| `/api/agents/stats/deviations` | Count of deviations detected |
| `/api/agents/tools` | Full tool inventory |
| `/api/agents/list` | Agent registry |
| `/api/agents/invocations` | Recent tool invocations |
| `/api/agents/deviations` | Behavioral deviation alerts |

### Viewing Agent Behavior

```bash
# Start gateway
AIRS_MODE=enforce uvicorn airs_cp.gateway.app:app --port 8080

# Start dashboard  
uvicorn airs_cp.dashboard.app:app --port 8501

# Run enterprise agent sample (populates observability data)
python samples/06_enterprise_agent.py

# View in browser
open http://localhost:8501/dashboard/agents
```

## Best Practices

1. **Register all agents and tools** before deployment
2. **Capture reasoning** from the LLM when tools are called
3. **Set appropriate risk tolerances** per agent
4. **Define expected tool sequences** for common workflows
5. **Monitor deviation alerts** for potential security issues
6. **Review explanations** when investigating incidents

## Data Model

See `airs_cp/observability/` for full implementation:

- `registry.py`: AgentRegistry, ToolDefinition, AgentDefinition
- `tracker.py`: InvocationTracker, ToolInvocation
- `analyzer.py`: BehaviorAnalyzer, DeviationAlert
