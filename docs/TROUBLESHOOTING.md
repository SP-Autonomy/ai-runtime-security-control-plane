# Troubleshooting Guide

## Common Issues and Solutions

### 1. Docker Permission Denied

**Error:**
```
PermissionError: [Errno 13] Permission denied
docker.errors.DockerException: Error while fetching server API version
```

**Solutions:**

Option A: Run with sudo (quick fix)
```bash
sudo docker-compose up -d
```

Option B: Add user to docker group (permanent fix)
```bash
# Add current user to docker group
sudo usermod -aG docker $USER

# Log out and log back in, or run:
newgrp docker

# Verify it works
docker ps
```

Option C: Use rootless Docker
```bash
# See: https://docs.docker.com/engine/security/rootless/
```

---

### 2. Ollama Connection Refused

**Error:**
```
httpx.ConnectError: Connection refused
```

**Solutions:**

1. **Check Ollama is running:**
   ```bash
   # Start Ollama
   ollama serve
   
   # Verify it's running
   curl http://localhost:11434/api/tags
   ```

2. **Check OLLAMA_HOST environment variable:**
   ```bash
   # For local development
   export OLLAMA_HOST=http://localhost:11434
   
   # For Docker (gateway connecting to host Ollama)
   export OLLAMA_HOST=http://host.docker.internal:11434
   ```

3. **For WSL users connecting to Windows Ollama:**
   ```bash
   # Get Windows host IP
   export OLLAMA_HOST=http://$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):11434
   ```

4. **Pull the model if not available:**
   ```bash
   ollama pull llama3.2:1b
   ```

---

### 3. Gateway Not Starting

**Error:**
```
ModuleNotFoundError: No module named 'airs_cp'
```

**Solution:**
```bash
# Install the package in development mode
cd ai-runtime-guardrail-control-plane
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

---

### 4. Port Already in Use

**Error:**
```
OSError: [Errno 98] Address already in use
```

**Solutions:**

1. **Find and kill the process:**
   ```bash
   # Find what's using port 8080
   lsof -i :8080
   
   # Kill it
   kill -9 <PID>
   ```

2. **Use a different port:**
   ```bash
   uvicorn airs_cp.gateway.app:app --port 8081
   ```

---

### 5. Streaming Not Working

**Symptoms:**
- Response comes all at once instead of streaming
- Timeout errors on long responses

**Solutions:**

1. **Check you're using stream=True:**
   ```python
   response = client.chat.completions.create(
       model="llama3.2:1b",
       messages=[...],
       stream=True,  # Must be True for streaming
   )
   ```

2. **Iterate over the stream:**
   ```python
   for chunk in response:
       if chunk.choices[0].delta.content:
           print(chunk.choices[0].delta.content, end="")
   ```

---

### 6. Tests Failing

**Run tests with verbose output:**
```bash
pytest tests/ -v --tb=long
```

**Run specific test:**
```bash
pytest tests/test_gateway.py::TestHealthEndpoints::test_health_check -v
```

**Check test coverage:**
```bash
pytest tests/ --cov=airs_cp --cov-report=term-missing
```

---

### 7. Model Not Found

**Error:**
```
Model 'llama3.2:1b' not found
```

**Solutions:**

1. **List available models:**
   ```bash
   ollama list
   ```

2. **Pull the model:**
   ```bash
   ollama pull llama3.2:1b
   ```

3. **Use a different model:**
   ```bash
   export AIRS_MODEL=mistral
   # or
   export AIRS_MODEL=llama2
   ```

---

## Quick Health Checks

### 1. Check Gateway
```bash
curl http://localhost:8080/health
```

Expected:
```json
{"status":"healthy","mode":"observe","provider":"ollama","kill_switch":false,"version":"0.1.0"}
```

### 2. Check Ollama
```bash
curl http://localhost:11434/api/tags
```

### 3. Test Chat Completion
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.2:1b",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

### 4. Run Demo Script
```bash
python scripts/demo.py
```

---

## Getting Help

1. Check the logs:
   ```bash
   # Gateway logs show request/response details
   uvicorn airs_cp.gateway.app:app --port 8080 --log-level debug
   ```

2. Check the documentation:
   - [README.md](../README.md)
   - [Architecture Contract](ARCHITECTURE_CONTRACT.md)
   - [Integration Guide](INTEGRATION_AND_OFFBOARDING.md)

3. Run the test suite:
   ```bash
   pytest tests/ -v
   ```
