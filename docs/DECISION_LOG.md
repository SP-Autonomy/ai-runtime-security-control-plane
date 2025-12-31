# Decision Log

## Purpose

This log tracks all architecture decisions that deviate from or extend the ARCHITECTURE_CONTRACT.md. Every significant decision must be recorded here with rationale and alternatives considered.

## Template

```
### Decision [ID]: [Title]

**Date**: YYYY-MM-DD
**Status**: Proposed | Accepted | Deprecated | Superseded by [ID]
**Deciders**: [Names/Roles]

**Context**:
What is the issue that we're seeing that motivates this decision?

**Decision**:
What is the change that we're proposing and/or doing?

**Rationale**:
Why is this change being proposed? What are the benefits?

**Alternatives Considered**:
1. Alternative A - Why rejected
2. Alternative B - Why rejected

**Consequences**:
- Positive: What becomes easier?
- Negative: What becomes harder?
- Risks: What could go wrong?

**Follow-up Actions**:
- [ ] Action 1
- [ ] Action 2
```

---

## Decisions

### Decision 001: Use FastAPI for Gateway

**Date**: 2024-12-27
**Status**: Accepted
**Deciders**: Jelli

**Context**:
Need a Python web framework for the gateway that supports async, streaming, and has good OpenAPI support.

**Decision**:
Use FastAPI as the gateway framework.

**Rationale**:
- Native async support (critical for streaming)
- Automatic OpenAPI documentation
- Excellent performance
- Strong typing with Pydantic
- Already used in Labs 01-04

**Alternatives Considered**:
1. Flask - Rejected: No native async, would need Flask-Async
2. Django - Rejected: Too heavyweight for a gateway service
3. Starlette - Rejected: Lower-level, would reinvent FastAPI features

**Consequences**:
- Positive: Fast development, good DX, reuse existing code
- Negative: Python GIL limits true parallelism
- Risks: None significant

**Follow-up Actions**:
- [x] Scaffold FastAPI gateway
- [ ] Add streaming support

---

### Decision 002: SQLite as Default Database

**Date**: 2024-12-27
**Status**: Accepted
**Deciders**: Jelli

**Context**:
Need a database for the evidence store that works offline and is easy to deploy.

**Decision**:
Use SQLite as the default database with optional PostgreSQL for production.

**Rationale**:
- Zero configuration
- File-based (easy backup/export)
- Sufficient for MVP volumes
- PostgreSQL option for scale

**Alternatives Considered**:
1. PostgreSQL only - Rejected: Adds deployment complexity
2. MongoDB - Rejected: Not as good for relational queries
3. In-memory only - Rejected: Need persistence

**Consequences**:
- Positive: Simple deployment, easy testing
- Negative: Not suitable for high-volume production
- Risks: SQLite locking under concurrent writes

**Follow-up Actions**:
- [x] Create database schema
- [ ] Add PostgreSQL adapter (Phase 2)

---

### Decision 003: Provider Adapter Pattern

**Date**: 2024-12-27
**Status**: Accepted
**Deciders**: Jelli

**Context**:
Need to support multiple LLM providers without changing gateway logic.

**Decision**:
Use an adapter pattern with a common interface for all providers.

**Rationale**:
- Clean separation of concerns
- Easy to add new providers
- Provider-specific logic isolated
- Supports streaming uniformly

**Alternatives Considered**:
1. Direct API calls - Rejected: Too much duplication
2. LiteLLM - Rejected: External dependency, less control
3. LangChain - Rejected: Too heavyweight for just provider switching

**Consequences**:
- Positive: Clean architecture, easy testing
- Negative: Must maintain adapters for each provider
- Risks: Provider API changes require adapter updates

**Follow-up Actions**:
- [ ] Implement OpenAI adapter
- [ ] Implement Anthropic adapter
- [ ] Implement Azure adapter
- [ ] Implement Ollama adapter

---

(Add new decisions above this line)
