# Integration and Offboarding

## Integration Modes

### 1. Proxy Mode (Zero-Code)

**How it works:**
- Customer points their LLM base URL to the AIRS-CP gateway proxy
- Requests flow through AIRS-CP, then forwarded to the backend LLM
- No code changes required in customer application

**Setup:**
```bash
# Before (direct to OpenAI)
OPENAI_BASE_URL=https://api.openai.com/v1

# After (through AIRS-CP)
OPENAI_BASE_URL=http://localhost:8080/v1
```

**Supported endpoints:**
- `POST /v1/chat/completions` (streaming supported)
- `POST /v1/completions`
- `GET /v1/models`

**Headers passed through:**
- `Authorization: Bearer <api_key>`
- `X-Session-ID: <optional session tracking>`

### 2. SDK Mode (Minimal-Code)

**How it works:**
- Customer imports AIRS-CP Python SDK
- SDK wraps their existing LLM client
- Additional context (session, user, tags) can be passed

**Installation:**
```bash
pip install airs-cp-sdk
```

**Usage:**
```python
from airs_cp import AIRSClient

# Wrap existing client
client = AIRSClient(
    provider="openai",
    api_key="sk-...",
    airs_endpoint="http://localhost:8080"
)

# Use like normal OpenAI client
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}],
    # AIRS-specific options
    session_id="user-123",
    tags=["support", "billing"]
)
```

### 3. Sidecar Mode (K8s Native) - Future

**How it works:**
- AIRS-CP runs as sidecar container in the same pod
- Intercepts traffic via iptables or service mesh
- No application changes required

**Status:** Documented pattern only, not in MVP scope

---

## Offboarding

### Principle: Easy Out

AIRS-CP follows the "easy in, easy out" principle. Offboarding should be:
- **Fast**: < 5 minutes
- **Safe**: No data loss
- **Clean**: No residual configuration

### Proxy Mode Offboarding

```bash
# Step 1: Revert base URL
OPENAI_BASE_URL=https://api.openai.com/v1

# Step 2: Stop AIRS-CP
docker-compose down

# Step 3: (Optional) Export audit logs
docker exec airs-cp-gateway airs export --format jsonl > audit.jsonl
```

### SDK Mode Offboarding

```python
# Before (with AIRS-CP)
from airs_cp import AIRSClient
client = AIRSClient(provider="openai", api_key="sk-...")

# After (direct OpenAI)
from openai import OpenAI
client = OpenAI(api_key="sk-...")
```

### Data Export

Before offboarding, export audit data:

```bash
# Export all events
airs export events --format jsonl --output events.jsonl

# Export specific date range
airs export events --from 2024-01-01 --to 2024-12-31 --output 2024.jsonl

# Export with full lineage
airs export sessions --include-lineage --output sessions.jsonl
```

### Cleanup Checklist

- [ ] Export audit logs
- [ ] Revert LLM endpoint configuration
- [ ] Stop AIRS-CP containers
- [ ] Remove Docker volumes (optional)
- [ ] Update application documentation

---

## Migration Scenarios

### From Direct API to AIRS-CP

1. Deploy AIRS-CP (`docker-compose up -d`)
2. Update `OPENAI_BASE_URL` to AIRS-CP endpoint
3. Verify requests flow through gateway
4. Enable security policies incrementally

### From AIRS-CP to Another Solution

1. Export all audit data
2. Revert to direct API access
3. Import audit data into new solution
4. Decommission AIRS-CP

### Provider Migration (e.g., OpenAI → Anthropic)

1. Add new provider credentials
2. Update `AIRS_PROVIDER` environment variable
3. No application code changes required (proxy mode)
