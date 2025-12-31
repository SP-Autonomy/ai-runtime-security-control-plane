"""
Ollama Adapter

Implements the BaseAdapter interface for Ollama (local LLM).
Supports both chat completions and streaming.
"""

import json
import time
from typing import Any, AsyncIterator

import httpx

from airs_cp.adapters.base import (
    AdapterError,
    BaseAdapter,
    ChatRequest,
    ChatResponse,
    Choice,
    Message,
    StreamChunk,
    Usage,
)


class OllamaAdapter(BaseAdapter):
    """
    Ollama Local LLM Adapter.
    
    Provides chat completion functionality using Ollama's local API,
    with support for streaming responses.
    """
    
    def __init__(
        self,
        host: str = "http://localhost:11434",
        timeout: float = 120.0,
    ):
        """
        Initialize the Ollama adapter.
        
        Args:
            host: Ollama host URL.
            timeout: Request timeout in seconds.
        """
        self._host = host.rstrip("/")
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout))
    
    @property
    def provider_name(self) -> str:
        return "ollama"
    
    def _convert_messages_to_prompt(self, messages: list[Message]) -> str:
        """Convert messages to a single prompt for Ollama generate API."""
        parts = []
        for msg in messages:
            if msg.role == "system":
                parts.append(f"System: {msg.content}")
            elif msg.role == "assistant":
                parts.append(f"Assistant: {msg.content}")
            else:
                parts.append(f"User: {msg.content}")
        parts.append("Assistant:")
        return "\n\n".join(parts)
    
    def _convert_to_ollama_chat(self, messages: list[Message]) -> list[dict[str, Any]]:
        """Convert messages to Ollama chat format."""
        return [
            {
                "role": m.role,
                "content": m.content,
            }
            for m in messages
        ]
    
    async def chat_completion(self, request: ChatRequest) -> ChatResponse:
        """Execute a chat completion request."""
        try:
            # Use Ollama's chat API
            url = f"{self._host}/api/chat"
            
            payload = {
                "model": request.model,
                "messages": self._convert_to_ollama_chat(request.messages),
                "stream": False,
                "options": {
                    "temperature": request.temperature,
                },
            }
            
            if request.max_tokens:
                payload["options"]["num_predict"] = request.max_tokens
            if request.top_p:
                payload["options"]["top_p"] = request.top_p
            if request.stop:
                payload["options"]["stop"] = request.stop
            
            response = await self._client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            
            # Extract response
            message_data = data.get("message", {})
            content = message_data.get("content", "")
            
            # Estimate token counts (Ollama provides this)
            prompt_tokens = data.get("prompt_eval_count", 0)
            completion_tokens = data.get("eval_count", 0)
            
            choices = [
                Choice(
                    index=0,
                    message=Message(
                        role="assistant",
                        content=content,
                    ),
                    finish_reason="stop" if data.get("done") else None,
                )
            ]
            
            usage = Usage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            )
            
            return ChatResponse(
                id=f"ollama-{int(time.time())}",
                model=data.get("model", request.model),
                choices=choices,
                usage=usage,
                created=int(time.time()),
            )
            
        except httpx.ConnectError as e:
            raise AdapterError(
                message=f"Failed to connect to Ollama at {self._host}",
                provider=self.provider_name,
                original_error=e,
            )
        except httpx.HTTPStatusError as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                status_code=e.response.status_code,
                original_error=e,
            )
        except Exception as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                original_error=e,
            )
    
    async def chat_completion_stream(
        self, request: ChatRequest
    ) -> AsyncIterator[StreamChunk]:
        """Execute a streaming chat completion request."""
        try:
            # Use Ollama's chat API with streaming
            url = f"{self._host}/api/chat"
            
            payload = {
                "model": request.model,
                "messages": self._convert_to_ollama_chat(request.messages),
                "stream": True,
                "options": {
                    "temperature": request.temperature,
                },
            }
            
            if request.max_tokens:
                payload["options"]["num_predict"] = request.max_tokens
            if request.top_p:
                payload["options"]["top_p"] = request.top_p
            if request.stop:
                payload["options"]["stop"] = request.stop
            
            response_id = f"ollama-{int(time.time())}"
            sent_role = False
            
            async with self._client.stream("POST", url, json=payload) as response:
                response.raise_for_status()
                
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    
                    message_data = data.get("message", {})
                    content = message_data.get("content", "")
                    done = data.get("done", False)
                    
                    if content or done:
                        yield StreamChunk(
                            id=response_id,
                            model=data.get("model", request.model),
                            delta_content=content if content else None,
                            delta_role="assistant" if not sent_role else None,
                            finish_reason="stop" if done else None,
                            index=0,
                        )
                        if not sent_role and content:
                            sent_role = True
                    
        except httpx.ConnectError as e:
            raise AdapterError(
                message=f"Failed to connect to Ollama at {self._host}",
                provider=self.provider_name,
                original_error=e,
            )
        except httpx.HTTPStatusError as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                status_code=e.response.status_code,
                original_error=e,
            )
        except Exception as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                original_error=e,
            )
    
    async def list_models(self) -> list[str]:
        """List available Ollama models."""
        try:
            url = f"{self._host}/api/tags"
            response = await self._client.get(url)
            response.raise_for_status()
            data = response.json()
            
            models = data.get("models", [])
            return [m.get("name", "") for m in models if m.get("name")]
            
        except Exception as e:
            raise AdapterError(
                message="Failed to list Ollama models",
                provider=self.provider_name,
                original_error=e,
            )
    
    async def health_check(self) -> bool:
        """Check Ollama health."""
        try:
            url = f"{self._host}/api/tags"
            response = await self._client.get(url)
            return response.status_code == 200
        except Exception:
            return False
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
