# Taint Tracking Specification

## Overview

Taint tracking provides data provenance and lineage across agent workflows. It answers: "Where did this data come from, and where did it go?"

## Taint Sources

Data enters the system from these sources, each assigned a taint label:

| Source Type | Label | Description |
|-------------|-------|-------------|
| `user_input` | `user` | Direct user input |
| `rag_doc` | `rag:{doc_id}` | Retrieved document |
| `tool_output` | `tool:{tool_name}` | Tool execution result |
| `model_response` | `model:{model_name}` | LLM-generated content |
| `system_prompt` | `system` | System instructions |

## Taint Labels

### Structure

```
{source_type}:{source_id}:{sensitivity}:{timestamp}
```

### Sensitivity Levels

| Level | Description | Propagation |
|-------|-------------|-------------|
| `public` | No sensitivity | Unrestricted |
| `internal` | Business data | Monitor |
| `confidential` | Sensitive data | Alert on egress |
| `restricted` | PII/secrets | Block egress |

## Propagation Rules

### Rule 1: Concatenation
When tainted content is concatenated, the result inherits all taints.

```
taint(A + B) = taint(A) ∪ taint(B)
```

### Rule 2: Transformation
When tainted content is transformed (summarized, translated), taints propagate.

```
taint(transform(A)) = taint(A)
```

### Rule 3: Model Processing
Model output inherits taints from all inputs.

```
taint(model_output) = taint(prompt) ∪ taint(system) ∪ taint(context)
```

### Rule 4: Tool Execution
Tool output is tainted by input and tool identity.

```
taint(tool_output) = taint(tool_input) ∪ {tool:{tool_name}}
```

## Taint Sinks

Sinks are points where tainted data leaves the system:

| Sink Type | Monitoring | Action |
|-----------|------------|--------|
| `response` | Log | Allow/block based on sensitivity |
| `tool_call` | Alert | Block if calling external with restricted |
| `storage` | Log | Allow with audit |
| `export` | Alert | Require approval for restricted |

## Lineage Graph

### Nodes

```json
{
    "id": "node_123",
    "type": "user_input|rag_doc|tool_output|model_response",
    "content_hash": "sha256:...",
    "taints": ["user:u123:restricted:2024-12-27T10:00:00Z"],
    "timestamp": "2024-12-27T10:00:00Z"
}
```

### Edges

```json
{
    "id": "edge_456",
    "from": "node_123",
    "to": "node_789",
    "type": "propagate|transform|sink",
    "operation": "concatenate|summarize|tool_call",
    "timestamp": "2024-12-27T10:00:01Z"
}
```

## API Endpoints (Phase 4)

```
GET /sessions/{id}/lineage          # Get taint lineage graph
GET /sessions/{id}/lineage/export   # Export as DOT/JSON
GET /taints/{label}                 # Find all entities with taint
POST /taints/query                  # Query by taint pattern
```

## Visualization

Lineage graphs are rendered in the dashboard using:
- Nodes: Colored by sensitivity level
- Edges: Labeled by operation type
- Timeline: Temporal ordering

## Example: RAG Workflow

```
User Input (restricted)
    ↓ propagate
Prompt Construction
    ↓ propagate
RAG Retrieval → Doc A (internal), Doc B (public)
    ↓ propagate (inherit all)
Model Input (restricted, internal, public)
    ↓ propagate
Model Output (restricted, internal, public, model:gpt-4)
    ↓ sink
Response to User
    → ALERT: restricted data in response
```

## Implementation Notes

1. Taints are computed incrementally (not recomputed from scratch)
2. Lineage graphs are stored in the Evidence Store
3. Large graphs are pruned after configurable time window
4. Export supports DOT format for Graphviz visualization
