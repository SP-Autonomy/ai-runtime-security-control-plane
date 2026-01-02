# AIRS-CP: AI Runtime Security Control Plane

<p align="center">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/Tests-1154%20Passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/ML%20Accuracy-97.8%25-blue" alt="ML Accuracy">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

## The Problem

As organizations deploy AI agents in production, a critical security gap emerges:

**Traditional security tools can't see inside AI workflows.**

When an AI agent processes a customer query, retrieves data from multiple sources, calls external APIs, and generates a response—all in milliseconds—existing security infrastructure is blind to:

- **Data exfiltration**: An agent leaking customer PII through tool calls
- **Prompt injection**: Attackers manipulating agent behavior via crafted inputs  
- **Behavioral drift**: Agents deviating from expected patterns (calling wrong tools, unusual sequences)
- **Unauthorized access**: Agents accessing tools outside their permissions

The [OWASP Top 10 for Agentic AI](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) highlight these risks—but few solutions exist to address them at runtime.

## The Solution

**AIRS-CP** is a production-grade security control plane that provides runtime visibility and protection for AI agents. Think of it as a security gateway that sits between your AI applications and LLM providers.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Your AI App   │────▶│     AIRS-CP      │────▶│   LLM Provider  │
│  (Agents, RAG)  │     │  Security Layer  │     │ (OpenAI, etc.)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │  • PII Detection    │
                    │  • Injection Block  │
                    │  • Agent Monitoring │
                    │  • Taint Tracking   │
                    │  • Audit Trail      │
                    └─────────────────────┘
```

## Key Capabilities

### 🛡️ Security Detection
| Threat | Method | Performance |
|--------|--------|-------------|
| PII Leakage | Pattern matching + ML | ~2ms |
| Prompt Injection | Rule-based + ML classifier (97.8% accuracy) | ~3ms |
| Agent Misbehavior | Behavioral analysis + IsolationForest | Real-time |
| Data Exfiltration | Taint tracking with lineage | Per-request |

### 🔍 Agent Observability
- **Tool invocation tracking**: See every tool call with reasoning
- **Behavioral deviation detection**: Know when agents act unexpectedly
- **Non-determinism monitoring**: Same input, different agent behavior? We detect it.

### 🎛️ Runtime Control
- **Observe mode**: Monitor and log without blocking
- **Enforce mode**: Block threats, sanitize PII
- **Kill switch**: Instant disable via API/CLI

## Quick Start

```bash
# Clone and setup
git clone https://github.com/yourorg/airs-cp.git
cd airs-cp
pip install -e .

# Train ML models (one-time, ~30 seconds)
airc train

# Start gateway (enforce mode)
AIRS_MODE=enforce uvicorn airs_cp.gateway.app:app --port 8080

# Start dashboard
uvicorn airs_cp.dashboard.app:app --port 8501

# Run demo
python samples/pov_realworld.py

# View dashboard
open http://localhost:8501/dashboard
```

## Integration Options

### Option 1: Proxy Mode (Zero Code)
Point your OpenAI client to AIRS-CP:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",  # AIRS-CP gateway
    api_key="your-key"
)

# All requests now flow through AIRS-CP security
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### Option 2: SDK Mode (Minimal Code)
Use the AIRS-CP client for additional features:

```python
from airs_cp.sdk import AIRSClient

client = AIRSClient(
    airs_endpoint="http://localhost:8080",
    default_session_id="user-123"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

## Framework Alignment

### NIST AI Risk Management Framework
| Function | AIRS-CP Implementation |
|----------|----------------------|
| **GOVERN** | Policy-as-code via OPA/Rego |
| **MAP** | Threat modeling per MITRE ATLAS |
| **MEASURE** | Detection metrics, ML accuracy tracking |
| **MANAGE** | Playbook-based response orchestration |

### OWASP Top 10 for Agentic AI
| Risk | Mitigation |
|------|------------|
| LLM01: Prompt Injection | Pattern + ML detection (97.8% accuracy) |
| LLM06: Sensitive Info Disclosure | PII detection + auto-sanitization |
| LLM07: Insecure Plugin Design | Tool allowlist enforcement per agent |
| LLM08: Excessive Agency | Behavioral monitoring + kill switch |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AIRS-CP Gateway                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Proxy     │  │    SDK      │  │     Sidecar (K8s)       │  │
│  │   Mode      │  │    Mode     │  │        Mode             │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────────┘  │
│         └────────────────┴─────────────────────┘                │
│                          │                                      │
│  ┌───────────────────────┴───────────────────────────────────┐  │
│  │                  Security Pipeline                         │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │  │
│  │  │   PII    │ │ Injection│ │  Policy  │ │   Taint      │  │  │
│  │  │ Detector │ │ Detector │ │  Engine  │ │   Tracker    │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                      │
│  ┌───────────────────────┴───────────────────────────────────┐  │
│  │                 Agent Observability                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │  │
│  │  │  Agent   │ │   Tool   │ │ Behavior │ │     ML       │  │  │
│  │  │ Registry │ │ Tracker  │ │ Analyzer │ │   Anomaly    │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  Provider Adapters: OpenAI │ Anthropic │ Azure │ Ollama        │
└─────────────────────────────────────────────────────────────────┘
```

## Dashboard

The web dashboard provides real-time visibility:

- **Monitor Tab**: Request counts, blocked/sanitized stats, live alerts
- **Agents Tab**: Registered agents, tool invocations, behavioral deviations
- **Metrics Tab**: Security overhead latency, detection distribution
- **Lineage Tab**: Data flow visualization with taint tracking

## CLI Tool

```bash
airc status              # Gateway status
airc logs -n 20          # Recent security events
airc mode enforce        # Switch to enforce mode
airc kill                # Emergency kill switch
airc train               # Train ML models
airc export              # Export audit trail
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AIRS_MODE` | `observe` | Runtime mode: `observe` or `enforce` |
| `AIRS_PROVIDER` | `ollama` | LLM provider |
| `AIRS_ML_ENABLED` | `true` | Enable ML detection |

## Testing

```bash
# All tests (154 passing)
pytest tests/ -v

# With coverage
pytest tests/ --cov=airs_cp --cov-report=html
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE_CONTRACT](docs/ARCHITECTURE_CONTRACT.md) | System design principles |
| [SECURITY_MODEL](docs/SECURITY_MODEL.md) | Security framework alignment |
| [TAINT_SPEC](docs/TAINT_SPEC.md) | Data lineage tracking |
| [RESULTS](RESULTS.md) | Benchmark results and achievements |

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built for securing the next generation of AI applications</strong>
</p>
