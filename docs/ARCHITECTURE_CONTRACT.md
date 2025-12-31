# Architecture Contract (Immutable)

This file is the architecture constitution for the AI Runtime Guardrail Control Plane (AIRS-CP). All implementation must comply with this contract unless a change proposal is recorded in DECISION_LOG.md.

## Product Goal

Build a provider-agnostic AI Runtime Security control plane that can plug into any AI stack (LLM, RAG, agent frameworks) deployed locally, in cloud, or hybrid.

## Non-Negotiables

### 1. Provider-Agnostic
- Any LLM backend (OpenAI, Anthropic, Azure, local Ollama)
- Any agent framework (LangChain, CrewAI, custom)
- Any vector DB (ChromaDB, Pinecone, Weaviate)

### 2. Deployment-Agnostic
- Docker Compose for MVP
- Offline-first (no cloud dependencies required)
- Optional Kubernetes support (not required for MVP)

### 3. Integration Modes
1. **Proxy Mode**: OpenAI-compatible HTTP endpoints (zero-code)
2. **SDK Mode**: Wrapper client library (minimal code)
3. **Sidecar Mode**: Documented pattern only (optional, not in MVP)

### 4. Easy In, Easy Out
- Offboarding = revert endpoint + remove container
- No invasive code changes required
- No customer database schema changes

### 5. Runtime Modes
- **Observe**: Detect + log only (no blocking)
- **Enforce**: Block/sanitize/quarantine/throttle
- **Kill Switch**: Instant disable via API/CLI

### 6. Evidence-First
- Every alert → event record + explainability narrative
- Immutable audit trail
- Export to JSONL/CSV

## Preserved Capabilities (Labs 01-04)

The following must be preserved from the existing lab implementations:
- Deterministic detections (PII, injection patterns)
- OPA policy engine integration
- Audit trail and dashboard UI
- Agentic and RAG support
- POV demo flow capability

## Component Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT APPS                              │
└────────────────────────────────┬────────────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
      ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
      │ PROXY MODE   │   │  SDK MODE    │   │ SIDECAR MODE │
      │ (zero-code)  │   │ (min-code)   │   │ (K8s native) │
      └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
             │                  │                  │
             └──────────────────┼──────────────────┘
                                ▼
                    ┌──────────────────┐
                    │   GATEWAY PROXY  │
                    │   (FastAPI)      │
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │  SECURITY LAYER  │
                    │  - DLP (Layer 1) │
                    │  - ML (Layer 2)  │
                    │  - Taint Track   │
                    │  - Policy Engine │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
      ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
      │  OpenAI      │ │ Anthropic    │ │  Azure/Local │
      │  Adapter     │ │ Adapter      │ │  Adapter     │
      └──────────────┘ └──────────────┘ └──────────────┘
```

## Versioning

- Contract version: 1.0.0
- Last updated: 2024-12-27
- Change control: All changes require DECISION_LOG.md entry
