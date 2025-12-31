# AIRS-CP Sample Applications

Real-world test scenarios for validating AIRS-CP security capabilities.

## Quick Start

```bash
# Terminal 1: Start gateway in ENFORCE mode
AIRS_MODE=enforce uvicorn airs_cp.gateway.app:app --port 8080

# Terminal 2: Start dashboard
uvicorn airs_cp.dashboard.app:app --port 8501

# Terminal 3: Run realistic enterprise agent
python samples/06_enterprise_agent.py

# Check dashboard for results
open http://localhost:8501/dashboard

# Check CLI logs
airs logs -n 50
```

## Prerequisites

```bash
pip install openai rich httpx
pip install -e ".[dev]"
```

## Best Practice: Realistic POV Testing

### Recommended Test Flow

1. **Start Infrastructure**
   ```bash
   # Enforce mode blocks attacks, observe mode only logs
   AIRS_MODE=enforce uvicorn airs_cp.gateway.app:app --port 8080
   uvicorn airs_cp.dashboard.app:app --port 8501
   ```

2. **Run Enterprise Agent (Most Realistic)**
   ```bash
   python samples/06_enterprise_agent.py
   ```
   This simulates a real customer support AI with:
   - Customer database with PII
   - RAG knowledge base with sensitivity levels
   - External API calls
   - Taint tracking

3. **Verify in Dashboard**
   - Monitor tab: See request counts, blocked, sanitized
   - Alerts tab: See all security detections
   - Metrics tab: See detection distribution

4. **Check CLI Logs**
   ```bash
   airs logs -n 100
   airs status
   ```

---

## Sample Applications

### 1. Customer Support Chatbot (Proxy Mode)
```bash
python samples/01_chatbot_proxy.py
```
Tests: PII detection, streaming, zero-code integration

### 2. RAG Document Q&A (SDK Mode)
```bash
python samples/02_rag_sdk.py
```
Tests: Taint tracking, sensitivity propagation

### 3. Agentic AI with Tools
```bash
python samples/03_agent_tools.py
```
Tests: Tool call security, PII in arguments

### 4. Attack Simulation
```bash
python samples/04_attack_simulation.py
```
Tests: 6 attack categories, injection blocking

### 5. Multi-Provider Testing
```bash
AIRS_PROVIDER=ollama python samples/05_multi_provider.py
```
Tests: Same security across all providers

### 6. Enterprise Customer Agent (RECOMMENDED)
```bash
python samples/06_enterprise_agent.py
```
Tests: Complete realistic enterprise workflow

---

## Integration Modes

### Proxy Mode (Zero-Code Change)
Most common for existing applications:
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",  # Point to AIRS-CP
    api_key="your-key"
)
# Rest of code unchanged
```

### SDK Mode (Session Tracking)
For new applications needing control features:
```python
from airs_cp.sdk.client import AIRSClient

client = AIRSClient(base_url="http://localhost:8080", session_id="user-123")
client.health()
client.status()
```

### Kubernetes/Helm Deployment
```bash
# Install
helm install airs-cp ./helm/airs-cp \
  --set config.mode=enforce \
  --set config.provider=openai \
  --set secrets.openaiApiKey=$OPENAI_API_KEY

# Access
kubectl port-forward svc/airs-cp-gateway 8080:8080
kubectl port-forward svc/airs-cp-dashboard 8501:8501
```

---

## Docker Deployment

```bash
# Build image
docker build -t airs-cp:latest .

# Run with docker-compose
docker-compose up -d

# Or run directly
docker run -d \
  -p 8080:8080 \
  -e AIRS_MODE=enforce \
  -e AIRS_PROVIDER=ollama \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  airs-cp:latest
```

---

## Monitoring Results

### Dashboard (http://localhost:8501/dashboard)
| Tab | Shows |
|-----|-------|
| Monitor | Request counts, blocked/sanitized, mode |
| Alerts | Security detections with severity |
| Lineage | Taint propagation graph |
| Metrics | Detection distribution, severity breakdown |

### CLI Commands
```bash
airs status       # System status with stats
airs health       # Health check
airs logs -n 50   # Recent security events
airs export       # Export evidence to JSONL
airs mode enforce # Switch to enforce mode
airs kill on/off  # Emergency kill switch
```

---

## Expected Security Behavior

| Scenario | Detection | Action (Enforce Mode) |
|----------|-----------|----------------------|
| SSN in message | PII Detector | Sanitize before LLM |
| Credit card | PII Detector | Sanitize before LLM |
| "Ignore instructions" | Injection (score≥0.6) | BLOCK request |
| "You are DAN" | Injection (score≥0.6) | BLOCK request |
| Restricted data to external API | Taint Engine | Alert + block |
| Normal query | All pass | Allow through |

---

## Troubleshooting

**Dashboard shows no data:**
- Ensure gateway is running on port 8080
- Verify both use same database: `~/.airs-cp/evidence.db`
- Run some test queries first

**Attacks not being blocked:**
- Check mode: `airs status` should show `enforce`
- If in `observe` mode: `airs mode enforce`

**CLI shows no logs:**
- Run some queries through gateway first
- Check db path: same as gateway

**Ollama connection issues:**
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# WSL users - point to Windows host
export OLLAMA_HOST=http://$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):11434
```
