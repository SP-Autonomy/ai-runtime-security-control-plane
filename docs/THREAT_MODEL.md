# Threat Model (MVP)

## Assets

- Prompts and system instructions
- Retrieved documents and embeddings
- Tool call arguments and tool outputs
- Model responses
- Session metadata and audit logs
- Policy packs and ML models

## Actors

- **Benign users**: Normal application usage
- **Malicious users**: Attempting prompt injection, data exfiltration
- **Compromised tools/connectors**: Malicious external integrations
- **Poisoned documents**: RAG corpus contamination
- **Insider misuse**: Authorized users with malicious intent

## Primary Threat Classes (OWASP Agentic AI Aligned)

1. **Direct prompt injection**: User crafts input to override system instructions
2. **Indirect prompt injection**: Malicious content in retrieved docs or tool output
3. **Sensitive data exposure**: PII/secrets leaked in prompts or responses
4. **Tool misuse**: Agent makes unauthorized external calls
5. **Insecure output**: Model generates harmful content, links, or code
6. **Resource abuse**: DoS via long prompts or request flooding

## Key Abuse Scenarios

### Scenario 1: Indirect Injection via RAG
- Attacker plants malicious instructions in a document
- RAG retrieves the document as context
- Model follows attacker's embedded instructions
- **Mitigation**: Taint tracking + content scanning

### Scenario 2: Tool Exfiltration
- Agent retrieves confidential data via allowed tool
- Agent attempts to send data to external endpoint
- **Mitigation**: Tool allowlist + egress monitoring

### Scenario 3: Insecure Output
- Model generates malicious links or code
- User executes harmful content
- **Mitigation**: Output sanitization + content classification

### Scenario 4: Denial of Service
- User floods with long prompts
- User makes repeated rapid requests
- **Mitigation**: Rate limiting + token budgets

### Scenario 5: PII Leakage
- User includes SSN/credit card in prompt
- Model echoes or stores sensitive data
- **Mitigation**: DLP masking + audit logging

## Required Evidence Per Incident

Every security incident must capture:
- `session_id`: Unique session identifier
- `timestamp`: ISO 8601 format
- `timeline`: Sequence of events (request → retrieval → tool call → response)
- `detection_signals`: What triggered the alert
- `scores`: Confidence scores from detectors
- `policy_decision`: Which policy was evaluated
- `action_taken`: Block/sanitize/quarantine/allow
- `explanation`: Human-readable narrative
- `taint_lineage`: Data flow graph (if applicable)

## Risk Matrix

| Threat | Likelihood | Impact | Mitigation Priority |
|--------|------------|--------|---------------------|
| Prompt Injection | High | High | P1 |
| PII Leakage | High | High | P1 |
| Tool Misuse | Medium | High | P2 |
| Indirect Injection | Medium | High | P2 |
| Insecure Output | Medium | Medium | P2 |
| DoS | Low | Medium | P3 |

## Out of Scope (MVP)

- Training data poisoning (inference-time only)
- Model extraction attacks
- Adversarial examples on embeddings
- Side-channel attacks
