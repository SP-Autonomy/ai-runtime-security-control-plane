# Playbooks

## Overview

Playbooks define automated response actions for security events. They are executed by the Response Orchestrator based on detection signals and policy decisions.

## Playbook Structure

```yaml
playbook:
  id: string                    # Unique identifier
  name: string                  # Human-readable name
  description: string           # Purpose of playbook
  enabled: boolean              # Active/inactive
  
  triggers:                     # Conditions to activate
    - detector: string          # Detector name
      severity: string          # Minimum severity
      confidence: float         # Minimum confidence
  
  conditions:                   # Additional conditions
    - field: string             # Field to check
      operator: string          # eq|gt|lt|contains|regex
      value: any                # Expected value
  
  actions:                      # Ordered list of actions
    - type: string              # Action type
      params: object            # Action parameters
  
  mode:                         # Observe vs enforce behavior
    observe: string             # Action in observe mode
    enforce: string             # Action in enforce mode
```

## Standard Playbooks

### 1. PII Leak Prevention

```yaml
playbook:
  id: pii_leak_prevention
  name: PII Leak Prevention
  description: Detect and sanitize PII in prompts and responses
  enabled: true
  
  triggers:
    - detector: pii_detector
      severity: medium
      confidence: 0.8
  
  actions:
    - type: sanitize
      params:
        patterns:
          - ssn: "***-**-****"
          - credit_card: "****-****-****-****"
          - email: "[REDACTED EMAIL]"
          - phone: "[REDACTED PHONE]"
    
    - type: log
      params:
        level: warning
        include_original: false
    
    - type: alert
      params:
        channel: security_team
        template: pii_detected
  
  mode:
    observe: log
    enforce: sanitize
```

### 2. Prompt Injection Block

```yaml
playbook:
  id: injection_block
  name: Prompt Injection Block
  description: Block detected prompt injection attempts
  enabled: true
  
  triggers:
    - detector: injection_detector
      severity: high
      confidence: 0.9
    - detector: injection_ml
      severity: high
      confidence: 0.85
  
  actions:
    - type: block
      params:
        message: "Request blocked due to security policy"
        code: 403
    
    - type: log
      params:
        level: error
        include_original: true
    
    - type: alert
      params:
        channel: security_team
        template: injection_attempt
        priority: high
    
    - type: increment_counter
      params:
        counter: session_violations
        max: 3
        on_exceed: quarantine_session
  
  mode:
    observe: log
    enforce: block
```

### 3. Session Quarantine

```yaml
playbook:
  id: session_quarantine
  name: Session Quarantine
  description: Quarantine sessions with repeated violations
  enabled: true
  
  triggers:
    - detector: session_monitor
      severity: critical
      confidence: 0.95
  
  conditions:
    - field: session.violation_count
      operator: gt
      value: 3
  
  actions:
    - type: quarantine
      params:
        duration: 3600
        message: "Session temporarily suspended"
    
    - type: log
      params:
        level: critical
        include_session_history: true
    
    - type: alert
      params:
        channel: security_team
        template: session_quarantined
        priority: critical
    
    - type: notify_user
      params:
        message: "Your session has been suspended. Contact support."
  
  mode:
    observe: log
    enforce: quarantine
```

### 4. Tool Misuse Prevention

```yaml
playbook:
  id: tool_misuse
  name: Tool Misuse Prevention
  description: Prevent unauthorized tool usage by agents
  enabled: true
  
  triggers:
    - detector: policy_engine
      severity: high
  
  conditions:
    - field: policy.decision
      operator: eq
      value: deny
  
  actions:
    - type: block
      params:
        message: "Tool execution not authorized"
        code: 403
    
    - type: log
      params:
        level: warning
        include_tool_request: true
    
    - type: taint
      params:
        label: unauthorized_tool_attempt
        propagate: true
  
  mode:
    observe: log
    enforce: block
```

### 5. Rate Limiting

```yaml
playbook:
  id: rate_limit
  name: Rate Limiting
  description: Throttle excessive requests
  enabled: true
  
  triggers:
    - detector: rate_monitor
      severity: medium
  
  conditions:
    - field: session.request_count_1min
      operator: gt
      value: 60
  
  actions:
    - type: throttle
      params:
        delay_ms: 1000
        max_delay_ms: 10000
        backoff: exponential
    
    - type: log
      params:
        level: warning
    
    - type: respond
      params:
        status: 429
        message: "Rate limit exceeded. Please slow down."
        headers:
          Retry-After: "60"
  
  mode:
    observe: log
    enforce: throttle
```

## Action Types

| Action | Description | Parameters |
|--------|-------------|------------|
| `allow` | Pass through | - |
| `block` | Reject request | message, code |
| `sanitize` | Mask/redact content | patterns |
| `quarantine` | Suspend session | duration, message |
| `throttle` | Rate limit | delay_ms, backoff |
| `log` | Write to audit log | level, fields |
| `alert` | Send notification | channel, template |
| `taint` | Add taint label | label, propagate |
| `respond` | Custom response | status, message, headers |
| `increment_counter` | Track violations | counter, max, on_exceed |

## Playbook Execution

```
Security Event
    ↓
Match Triggers (any match activates)
    ↓
Evaluate Conditions (all must pass)
    ↓
Check Mode (observe vs enforce)
    ↓
Execute Actions (in order)
    ↓
Record Outcome
```

## Custom Playbooks

Users can define custom playbooks via:
- YAML files in `/etc/airs/playbooks/`
- API endpoint `POST /playbooks`
- Dashboard UI (Phase 5)

## Kill Switch

The kill switch immediately disables all enforcement:

```bash
# Activate kill switch
curl -X POST http://localhost:8080/kill

# Deactivate kill switch
curl -X DELETE http://localhost:8080/kill
```

When active:
- All playbooks run in observe mode
- No blocking or sanitization
- Logging continues
