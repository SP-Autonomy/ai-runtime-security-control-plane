"""
AIRS-CP Gateway

FastAPI-based gateway providing OpenAI-compatible endpoints.
Supports streaming responses via SSE (Server-Sent Events).
"""

import json
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from airs_cp.adapters import AdapterError, ChatRequest, get_adapter, get_registry
from airs_cp.config import Provider, RuntimeMode, settings

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


# === Global State ===

class GatewayState:
    """Global gateway state for statistics and control."""
    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.sanitized_requests = 0
        self.anomaly_requests = 0
        self.kill_switch = False
        self.mode = "observe"
        self.provider_usage = {"ollama": 0, "openai": 0, "anthropic": 0, "azure": 0}
        # Latency tracking (rolling averages)
        self._pii_latencies: list[float] = []
        self._injection_latencies: list[float] = []
        self._ml_latencies: list[float] = []
        self._total_latencies: list[float] = []
        self._max_samples = 100  # Keep last 100 samples
    
    def record_provider(self, provider: str):
        """Record provider usage."""
        provider_key = provider.lower()
        if provider_key in self.provider_usage:
            self.provider_usage[provider_key] += 1
    
    def record_latency(self, pii_ms: float = 0, injection_ms: float = 0, ml_ms: float = 0):
        """Record security check latencies."""
        total_ms = pii_ms + injection_ms + ml_ms
        
        self._pii_latencies.append(pii_ms)
        self._injection_latencies.append(injection_ms)
        self._ml_latencies.append(ml_ms)
        self._total_latencies.append(total_ms)
        
        # Keep only recent samples
        if len(self._pii_latencies) > self._max_samples:
            self._pii_latencies = self._pii_latencies[-self._max_samples:]
            self._injection_latencies = self._injection_latencies[-self._max_samples:]
            self._ml_latencies = self._ml_latencies[-self._max_samples:]
            self._total_latencies = self._total_latencies[-self._max_samples:]
    
    def get_avg_latencies(self) -> dict:
        """Get average latencies."""
        def avg(lst):
            return sum(lst) / len(lst) if lst else 0.0
        
        return {
            "pii_ms": round(avg(self._pii_latencies), 1),
            "injection_ms": round(avg(self._injection_latencies), 1),
            "ml_ms": round(avg(self._ml_latencies), 1),
            "total_ms": round(avg(self._total_latencies), 1),
        }
    
    def to_dict(self):
        return {
            "total_requests": self.total_requests,
            "blocked": self.blocked_requests,
            "sanitized": self.sanitized_requests,
            "anomalies": self.anomaly_requests,
            "provider_usage": self.provider_usage,
            "latencies": self.get_avg_latencies(),
        }

gateway_state = GatewayState()


# === Pydantic Models for API ===

class ChatMessage(BaseModel):
    """A chat message in OpenAI format."""
    role: str
    content: str
    name: Optional[str] = None
    tool_calls: Optional[list[dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion request."""
    model: str
    messages: list[ChatMessage]
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: Optional[int] = None
    stream: bool = False
    top_p: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    stop: Optional[list[str]] = None
    tools: Optional[list[dict[str, Any]]] = None
    tool_choice: Optional[str | dict[str, Any]] = None
    user: Optional[str] = None


class ModeChangeRequest(BaseModel):
    """Request to change runtime mode."""
    mode: RuntimeMode


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    mode: str
    provider: str
    kill_switch: bool
    version: str


class StatusResponse(BaseModel):
    """System status response."""
    status: str
    mode: str
    provider: str
    model: str
    kill_switch: bool
    adapters: dict[str, bool]
    uptime_seconds: float
    stats: dict


# === Application Lifecycle ===

startup_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global startup_time
    startup_time = time.time()
    
    logger.info(
        "AIRS-CP Gateway starting",
        mode=settings.mode.value,
        provider=settings.provider.value,
        host=settings.host,
        port=settings.port,
    )
    
    yield
    
    # Cleanup
    logger.info("AIRS-CP Gateway shutting down")
    registry = get_registry(settings)
    await registry.close_all()


# === FastAPI Application ===

app = FastAPI(
    title="AIRS-CP Gateway",
    description="AI Runtime Security Control Plane - OpenAI-compatible proxy",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# === Security Pipeline ===

def run_security_checks(content: str, session_id: str, count_sanitized: bool = True) -> dict:
    """Run security checks on content. Returns dict with action and details.
    
    Args:
        content: Content to check
        session_id: Session ID for tracking
        count_sanitized: Whether to increment sanitized counter (False for response scans to avoid double-counting)
    """
    import time as _time
    from airs_cp.security.detectors.pii import get_pii_detector
    from airs_cp.security.detectors.injection import get_injection_detector
    
    result = {
        "action": "allow",  # allow, block, sanitize
        "pii_detected": False,
        "injection_detected": False,
        "sanitized_content": content,
        "detections": [],
    }
    
    # PII Detection with timing
    pii_start = _time.time()
    pii_detector = get_pii_detector()
    pii_result = pii_detector.analyze(content)
    pii_ms = (_time.time() - pii_start) * 1000
    
    if pii_result["has_pii"]:
        result["pii_detected"] = True
        result["sanitized_content"] = pii_result["masked_text"]
        result["action"] = "sanitize"
        if count_sanitized:
            gateway_state.sanitized_requests += 1
        
        # Store detection (with error handling)
        try:
            from airs_cp.store.database import get_store
            from airs_cp.store.models import Detection, DetectorType, Severity
            
            store = get_store()
            detection = Detection(
                event_id=str(uuid.uuid4()),
                detector_type=DetectorType.DLP,
                detector_name="pii_detector",
                severity=Severity.HIGH if pii_result.get("max_severity") == "high" else Severity.MEDIUM,
                confidence=0.95,
                signals=[{"patterns": list(pii_result["by_pattern"].keys()), "count": pii_result["match_count"]}],
                metadata={"session_id": session_id},
            )
            store.create_detection(detection)
            result["detections"].append(detection)
        except Exception as e:
            logger.warning(f"Failed to store PII detection: {e}")
    
    # Injection Detection with timing
    injection_start = _time.time()
    injection_detector = get_injection_detector(use_ml=False)
    injection_result = injection_detector.analyze(content)
    injection_ms = (_time.time() - injection_start) * 1000
    
    if injection_result["is_injection"]:
        result["injection_detected"] = True
        
        # Determine severity based on score
        if injection_result["combined_score"] >= 0.8:
            severity_level = "critical"
        elif injection_result["combined_score"] >= 0.5:
            severity_level = "high"
        else:
            severity_level = "medium"
        
        # Store detection (with error handling)
        try:
            from airs_cp.store.database import get_store
            from airs_cp.store.models import Detection, DetectorType, Severity
            
            severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}
            store = get_store()
            detection = Detection(
                event_id=str(uuid.uuid4()),
                detector_type=DetectorType.INJECTION,
                detector_name="injection_detector",
                severity=severity_map[severity_level],
                confidence=injection_result["combined_score"],
                signals=[{
                    "categories": injection_result["categories_matched"],
                    "score": injection_result["combined_score"],
                }],
                metadata={"session_id": session_id, "blocked": injection_result["combined_score"] >= 0.6},
            )
            store.create_detection(detection)
            result["detections"].append(detection)
        except Exception as e:
            logger.warning(f"Failed to store injection detection: {e}")
        
        # Block in enforce mode if high confidence
        effective_mode = settings.get_effective_mode()
        if effective_mode == RuntimeMode.ENFORCE and injection_result["combined_score"] >= 0.6:
            result["action"] = "block"
            gateway_state.blocked_requests += 1
    
    # Record latencies (ML latency is 0 for now since we're not using ML detection by default)
    gateway_state.record_latency(pii_ms=pii_ms, injection_ms=injection_ms, ml_ms=0)
    
    return result


# === Root Endpoint ===

@app.get("/", tags=["Info"])
async def root():
    """API landing page."""
    return {
        "name": "AIRS-CP Gateway",
        "description": "AI Runtime Security Control Plane - OpenAI-compatible proxy",
        "version": "0.2.0",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "openai_compatible": {
                "chat_completions": "POST /v1/chat/completions",
                "models": "GET /v1/models",
            },
            "control": {
                "health": "GET /health",
                "status": "GET /status",
                "mode": "POST /mode",
                "kill_switch_on": "POST /kill",
                "kill_switch_off": "DELETE /kill",
                "metrics": "GET /metrics",
            }
        }
    }


# === Health & Status Endpoints ===

@app.get("/health", response_model=HealthResponse, tags=["Control"])
async def health_check():
    """Check gateway health."""
    return HealthResponse(
        status="healthy",
        mode=settings.get_effective_mode().value,
        provider=settings.provider.value,
        kill_switch=settings.kill_switch,
        version="0.2.0",
    )


@app.get("/status", tags=["Control"])
async def get_status():
    """Get detailed system status."""
    registry = get_registry(settings)
    adapter_health = await registry.health_check_all()
    
    return {
        "status": "operational",
        "mode": settings.get_effective_mode().value,
        "provider": settings.provider.value,
        "model": settings.model,
        "kill_switch": settings.kill_switch,
        "adapters": adapter_health,
        "uptime_seconds": time.time() - startup_time,
        "stats": gateway_state.to_dict(),
    }


@app.post("/mode", tags=["Control"])
async def set_mode(request: ModeChangeRequest):
    """Change runtime mode (observe/enforce)."""
    settings.mode = request.mode
    gateway_state.mode = request.mode.value
    logger.info("Mode changed", new_mode=request.mode.value)
    return {"status": "ok", "mode": request.mode.value}


@app.post("/kill", tags=["Control"])
async def activate_kill_switch():
    """Activate the emergency kill switch."""
    settings.kill_switch = True
    gateway_state.kill_switch = True
    logger.warning("Kill switch activated")
    return {"status": "kill_switch_active", "mode": "observe"}


@app.delete("/kill", tags=["Control"])
async def deactivate_kill_switch():
    """Deactivate the emergency kill switch."""
    settings.kill_switch = False
    gateway_state.kill_switch = False
    logger.info("Kill switch deactivated")
    return {"status": "normal", "mode": settings.mode.value}


# === OpenAI-Compatible Endpoints ===

@app.get("/v1/models", tags=["OpenAI API"])
async def list_models():
    """List available models (OpenAI-compatible)."""
    try:
        adapter = get_adapter(settings.provider)
        models = await adapter.list_models()
        
        return {
            "object": "list",
            "data": [
                {
                    "id": model,
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": settings.provider.value,
                }
                for model in models
            ],
        }
    except AdapterError as e:
        logger.error("Failed to list models", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/chat/completions", tags=["OpenAI API"])
async def chat_completions(request: ChatCompletionRequest, req: Request):
    """
    Create a chat completion (OpenAI-compatible).
    
    Supports both streaming and non-streaming responses.
    """
    # Generate session/trace IDs
    session_id = req.headers.get("X-Session-ID", str(uuid.uuid4()))
    trace_id = req.headers.get("X-Trace-ID", str(uuid.uuid4()))
    
    gateway_state.total_requests += 1
    
    logger.info(
        "Chat completion request",
        session_id=session_id,
        trace_id=trace_id,
        model=request.model,
        stream=request.stream,
        message_count=len(request.messages),
    )
    
    try:
        # Track if this request has been counted as sanitized
        request_counted_sanitized = False
        
        # Run security checks on all messages
        for i, msg in enumerate(request.messages):
            if msg.content:
                # Only count sanitized once per request
                security_result = run_security_checks(
                    msg.content, 
                    session_id, 
                    count_sanitized=not request_counted_sanitized
                )
                
                if security_result["action"] == "sanitize":
                    request_counted_sanitized = True
                
                # Handle blocked requests
                if security_result["action"] == "block":
                    logger.warning(
                        "Request blocked by security policy",
                        session_id=session_id,
                        reason="injection_detected",
                    )
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error": {
                                "message": "Request blocked due to security policy violation",
                                "type": "security_block",
                                "code": "injection_detected",
                            }
                        },
                    )
                
                # Handle sanitized content
                if security_result["action"] == "sanitize":
                    # Create new message with sanitized content
                    request.messages[i] = ChatMessage(
                        role=msg.role,
                        content=security_result["sanitized_content"],
                        name=msg.name,
                    )
                    logger.info(
                        "Content sanitized",
                        session_id=session_id,
                        pii_detected=security_result["pii_detected"],
                    )
        
        # Get the adapter for the configured provider
        adapter = get_adapter(settings.provider)
        
        # Track provider usage
        gateway_state.record_provider(settings.provider.value)
        
        # Convert to unified request format
        chat_request = ChatRequest.from_openai_format(request.model_dump())
        
        if request.stream:
            return await _handle_streaming(adapter, chat_request, session_id, trace_id)
        else:
            return await _handle_non_streaming(adapter, chat_request, session_id, trace_id)
            
    except HTTPException:
        raise
    except AdapterError as e:
        logger.error(
            "Adapter error",
            session_id=session_id,
            error=str(e),
            provider=e.provider,
        )
        raise HTTPException(
            status_code=e.status_code or 500,
            detail={"error": {"message": str(e), "type": "adapter_error"}},
        )
    except Exception as e:
        logger.exception("Unexpected error", session_id=session_id)
        raise HTTPException(
            status_code=500,
            detail={"error": {"message": str(e), "type": "internal_error"}},
        )


async def _handle_non_streaming(adapter, chat_request, session_id, trace_id):
    """Handle non-streaming chat completion."""
    start_time = time.time()
    
    response = await adapter.chat_completion(chat_request)
    
    latency_ms = int((time.time() - start_time) * 1000)
    logger.info(
        "Chat completion response",
        session_id=session_id,
        trace_id=trace_id,
        latency_ms=latency_ms,
        tokens_in=response.usage.prompt_tokens,
        tokens_out=response.usage.completion_tokens,
    )
    
    return JSONResponse(
        content=response.to_openai_format(),
        headers={
            "X-Session-ID": session_id,
            "X-Trace-ID": trace_id,
            "X-Latency-MS": str(latency_ms),
        },
    )


async def _handle_streaming(adapter, chat_request, session_id, trace_id):
    """Handle streaming chat completion."""
    
    async def event_generator():
        start_time = time.time()
        created = int(time.time())
        
        try:
            async for chunk in adapter.chat_completion_stream(chat_request):
                # Convert to SSE format
                data = chunk.to_openai_format()
                data["created"] = created
                
                yield {
                    "event": "message",
                    "data": json.dumps(data),
                }
                
                # Log completion
                if chunk.finish_reason:
                    latency_ms = int((time.time() - start_time) * 1000)
                    logger.info(
                        "Streaming completion finished",
                        session_id=session_id,
                        trace_id=trace_id,
                        latency_ms=latency_ms,
                        finish_reason=chunk.finish_reason,
                    )
            
            # Send [DONE] marker
            yield {"event": "message", "data": "[DONE]"}
            
        except Exception as e:
            logger.error(
                "Streaming error",
                session_id=session_id,
                error=str(e),
            )
            # Send error as SSE
            yield {
                "event": "error",
                "data": json.dumps({"error": str(e)}),
            }
    
    return EventSourceResponse(
        event_generator(),
        headers={
            "X-Session-ID": session_id,
            "X-Trace-ID": trace_id,
        },
    )


# === Legacy Completions Endpoint ===

@app.post("/v1/completions", tags=["OpenAI API"])
async def legacy_completions(request: Request):
    """
    Legacy completions endpoint.
    
    Converts to chat format and forwards to chat completions.
    """
    body = await request.json()
    
    # Convert legacy format to chat format
    prompt = body.get("prompt", "")
    if isinstance(prompt, list):
        prompt = "\n".join(prompt)
    
    chat_request = ChatCompletionRequest(
        model=body.get("model", settings.model),
        messages=[ChatMessage(role="user", content=prompt)],
        temperature=body.get("temperature", 0.7),
        max_tokens=body.get("max_tokens"),
        stream=body.get("stream", False),
        stop=body.get("stop"),
    )
    
    return await chat_completions(chat_request, request)


# === Metrics Endpoint (Prometheus format) ===

@app.get("/metrics", tags=["Control"])
async def prometheus_metrics():
    """
    Prometheus metrics endpoint.
    
    Returns basic metrics in Prometheus format.
    """
    uptime = time.time() - startup_time
    
    metrics = [
        f'# HELP airs_uptime_seconds Gateway uptime in seconds',
        f'# TYPE airs_uptime_seconds gauge',
        f'airs_uptime_seconds {uptime:.2f}',
        f'',
        f'# HELP airs_kill_switch Kill switch status (1=active, 0=inactive)',
        f'# TYPE airs_kill_switch gauge',
        f'airs_kill_switch {1 if settings.kill_switch else 0}',
        f'',
        f'# HELP airs_mode_enforce Enforce mode status (1=enforce, 0=observe)',
        f'# TYPE airs_mode_enforce gauge',
        f'airs_mode_enforce {1 if settings.mode == RuntimeMode.ENFORCE else 0}',
        f'',
        f'# HELP airs_requests_total Total requests processed',
        f'# TYPE airs_requests_total counter',
        f'airs_requests_total {gateway_state.total_requests}',
        f'',
        f'# HELP airs_requests_blocked Total requests blocked',
        f'# TYPE airs_requests_blocked counter',
        f'airs_requests_blocked {gateway_state.blocked_requests}',
        f'',
        f'# HELP airs_requests_sanitized Total requests sanitized',
        f'# TYPE airs_requests_sanitized counter',
        f'airs_requests_sanitized {gateway_state.sanitized_requests}',
    ]
    
    return Response(
        content="\n".join(metrics),
        media_type="text/plain; charset=utf-8",
    )
