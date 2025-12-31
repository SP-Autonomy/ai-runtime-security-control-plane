# Security Model

## Framework Alignment

AIRS-CP aligns with the following industry frameworks:

### 1. NIST AI Risk Management Framework (AI RMF)
- **GOVERN**: Policy-as-code via OPA/Rego
- **MAP**: Threat modeling per MITRE ATLAS
- **MEASURE**: Metrics (detection rates, false positives)
- **MANAGE**: Playbook-based response orchestration

### 2. OWASP Agentic AI Security (Top 10)
- LLM01: Prompt Injection → Deterministic + ML detection
- LLM02: Insecure Output → Output sanitization
- LLM03: Training Data Poisoning → N/A (inference-time only)
- LLM06: Sensitive Information Disclosure → DLP pipeline
- LLM07: Insecure Plugin Design → Tool allowlist enforcement
- LLM08: Excessive Agency → Taint tracking + kill switch

### 3. MITRE ATLAS
- Technique mapping for threat detection
- Adversarial ML threat coverage

## Security Layers

### Layer 1: Deterministic Detection (Fast Path)
- PII patterns (SSN, credit card, email, phone)
- Known injection patterns (ignore instructions, system prompt)
- Blocklist/allowlist enforcement
- Policy evaluation (OPA)

### Layer 2: ML-Based Detection (Enhanced Path)
- Anomaly detection (IsolationForest)
- Supervised classification (injection/benign)
- Embedding similarity for semantic threats

### Layer 3: Taint Tracking
- Data provenance across agent workflows
- Source → sink lineage
- Cross-session tracking

## Detection Categories

| Category | Method | Latency Target |
|----------|--------|----------------|
| PII Leak | Regex + spaCy NER | <50ms |
| Prompt Injection | Pattern + ML | <100ms |
| Tool Misuse | OPA Policy | <20ms |
| Anomaly | IsolationForest | <200ms |
| Output Harmful | Content classifier | <150ms |

## Response Actions

1. **ALLOW**: Pass through unmodified
2. **BLOCK**: Reject with error message
3. **SANITIZE**: Mask/redact sensitive content
4. **QUARANTINE**: Log for review, allow with warning
5. **THROTTLE**: Rate limit the session

## Audit Requirements

Every security event must capture:
- session_id
- timestamp (ISO 8601)
- event_type
- input/output (redacted if needed)
- detection_signals
- policy_decision
- action_taken
- explanation_narrative
