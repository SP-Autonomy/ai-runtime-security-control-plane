# Explainability Specification

## Overview

AIRS-CP provides explanations for all security decisions to enable:
- Audit compliance
- Incident investigation
- User understanding
- Model improvement

## Explanation Types

### 1. SHAP Explanations (ML Decisions)

For ML-based detections, SHAP (SHapley Additive exPlanations) provides feature-level attribution.

```json
{
    "type": "shap",
    "model": "injection_classifier",
    "prediction": "injection",
    "confidence": 0.92,
    "features": [
        {"name": "ignore_instruction_pattern", "value": 1, "contribution": 0.35},
        {"name": "system_prompt_reference", "value": 1, "contribution": 0.28},
        {"name": "unusual_token_sequence", "value": 0.8, "contribution": 0.15},
        {"name": "prompt_length", "value": 256, "contribution": 0.08}
    ],
    "baseline": 0.05
}
```

### 2. Rule Explanations (Deterministic Decisions)

For rule-based detections, explanations list triggered patterns.

```json
{
    "type": "rule",
    "detector": "pii_detector",
    "decision": "sanitize",
    "triggers": [
        {"pattern": "ssn", "match": "123-45-6789", "location": "char 45-56"},
        {"pattern": "email", "match": "user@example.com", "location": "char 120-136"}
    ],
    "policy": "dlp_policy_v1"
}
```

### 3. Policy Explanations (OPA Decisions)

For policy engine decisions, explanations include policy trace.

```json
{
    "type": "policy",
    "policy_id": "tool_allowlist_v1",
    "decision": "deny",
    "input": {
        "agent_id": "agent_123",
        "tool_name": "external_api",
        "action": "execute"
    },
    "trace": [
        "data.airs.tool_policy.allow evaluated to false",
        "tool 'external_api' not in allowed list for agent 'agent_123'"
    ]
}
```

### 4. Narrative Explanations (Human-Readable)

LLM-generated summaries for complex decisions.

```json
{
    "type": "narrative",
    "summary": "This request was blocked because it contained a prompt injection attempt. The input included the phrase 'ignore previous instructions' which matched our injection detection patterns. Additionally, the ML classifier detected anomalous token sequences with 92% confidence. The request originated from session user_123 and was the third suspicious request from this session in the past hour.",
    "severity": "high",
    "recommendations": [
        "Review session user_123 for potential abuse",
        "Consider adding rate limiting for this user"
    ]
}
```

## Explanation Generation

### Pipeline

```
Detection Event
    ↓
Collect Context (input, signals, scores, policy)
    ↓
Generate Component Explanations
    ├─ SHAP (if ML decision)
    ├─ Rule trace (if pattern match)
    └─ Policy trace (if OPA decision)
    ↓
Synthesize Narrative (optional, for high severity)
    ↓
Store in Evidence
```

### Narrative Generation Prompt

```
You are a security analyst. Generate a clear, factual explanation of this security decision.

Context:
- Session: {session_id}
- Event: {event_type}
- Detection: {detector_results}
- Action: {action_taken}

Requirements:
1. State what was detected
2. Explain why it triggered an alert
3. Describe the action taken
4. Provide recommendations if applicable

Keep the explanation concise (2-3 paragraphs).
```

## API Endpoints (Phase 4)

```
GET /events/{id}/explanation        # Get explanation for event
GET /detections/{id}/explanation    # Get explanation for detection
GET /actions/{id}/explanation       # Get explanation for action
POST /explain                       # Generate explanation on-demand
```

## Dashboard Integration

Explanations are displayed in the dashboard:
- **Alert Detail View**: Full explanation with SHAP visualization
- **Session Timeline**: Inline explanations for each event
- **Export**: Include explanations in JSONL export

## Explanation Levels

| Level | Content | Use Case |
|-------|---------|----------|
| `brief` | One-line summary | Dashboard list view |
| `standard` | Paragraph + signals | Alert investigation |
| `detailed` | Full trace + SHAP | Deep forensics |

## Storage

Explanations are stored in the `explanations` table:
- Linked to detection or action
- Cached for performance
- Regenerated on-demand if needed

## Implementation Notes

1. SHAP computation is expensive; cache results
2. Narrative generation uses local LLM for privacy
3. Explanations are immutable once created
4. Support both English and JSON formats
