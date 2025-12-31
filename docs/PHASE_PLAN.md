# Phase Plan

## Overview

AIRS-CP development follows a strict phase-gated approach. Each phase must be complete before proceeding to the next.

## Phase 1: Provider-Agnostic Gateway (Current)

**Duration**: 4-6 hours
**Goal**: Multi-provider streaming gateway with integration modes

### Deliverables
- [ ] Provider adapters (OpenAI, Anthropic, Azure, Ollama)
- [ ] Streaming support (SSE) in gateway
- [ ] Proxy mode (OpenAI-compatible endpoints)
- [ ] SDK wrapper (Python client library)
- [ ] Docker Compose for unified startup
- [ ] Basic health checks and metrics

### Success Criteria
- Can send requests to any configured LLM provider
- Streaming responses work end-to-end
- Single `docker-compose up` starts all services
- Can run/test locally with Ollama (llama3.2:1b)

### Preserved from Labs
- FastAPI foundation
- Basic request/response logging

---

## Phase 2: Deterministic Security Pipeline

**Duration**: 4-6 hours
**Goal**: Migrate and enhance Labs 01-04 security processors

### Deliverables
- [ ] DLP processor (PII detection/masking)
- [ ] Injection detector (pattern-based)
- [ ] OPA policy engine integration
- [ ] Audit trail with SQLite backend
- [ ] Security event schema

### Success Criteria
- 90%+ PII detection rate
- <50ms latency for deterministic checks
- Policy toggles work at runtime

---

## Phase 3: ML Detection Layer

**Duration**: 6-8 hours
**Goal**: Add ML-based anomaly and classification

### Deliverables
- [ ] Anomaly detector (IsolationForest)
- [ ] Supervised classifier (injection detection)
- [ ] Feature extraction pipeline
- [ ] Model training scripts
- [ ] Inference integration in gateway

### Success Criteria
- Anomaly detection with <5% false positive rate
- Model hot-reload capability
- Graceful fallback if ML unavailable

---

## Phase 4: Taint Tracking & Explainability

**Duration**: 6-8 hours
**Goal**: Add provenance tracking and explanation generation

### Deliverables
- [ ] Taint label creation/propagation
- [ ] Lineage graph storage
- [ ] SHAP integration for ML explanations
- [ ] LLM-generated narratives
- [ ] Explanation API endpoints

### Success Criteria
- Full taint lineage for multi-step agent workflows
- Human-readable explanations for all alerts

---

## Phase 5: Dashboard & Demo

**Duration**: 4-6 hours
**Goal**: Unified UI and POV demo capability

### Deliverables
- [ ] Streamlit dashboard (4 tabs)
- [ ] CLI tool for operations
- [ ] Demo scripts and attack simulations
- [ ] Documentation and README

### Success Criteria
- "POV in 10 minutes" demo works
- All 6 demo scenarios functional
- Professional documentation

---

## Phase Gates

| Gate | Criteria | Approval |
|------|----------|----------|
| P1→P2 | All providers working, streaming OK, docker-compose OK | Self |
| P2→P3 | Security tests passing, 90% PII detection | Self |
| P3→P4 | ML models trained, inference working | Self |
| P4→P5 | Taint tracking demo, explanations generating | Self |
| P5→Done | Full demo runs, docs complete | Self |

## Risk Mitigations

1. **Scope creep**: Strict phase gates
2. **Context drift**: Always reference ARCHITECTURE_CONTRACT.md
3. **Integration complexity**: Test each provider independently
4. **ML training time**: Use pre-trained embeddings where possible
