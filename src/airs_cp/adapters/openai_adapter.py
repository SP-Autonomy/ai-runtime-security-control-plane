"""
OpenAI Adapter

Implements the BaseAdapter interface for OpenAI's API.
Supports both chat completions and streaming.
"""

import time
from typing import AsyncIterator, Optional

import httpx
from openai import AsyncOpenAI, APIError, APIConnectionError, RateLimitError

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


class OpenAIAdapter(BaseAdapter):
    """
    OpenAI API Adapter.
    
    Provides chat completion functionality using OpenAI's API,
    with support for streaming responses.
    """
    
    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 120.0,
    ):
        """
        Initialize the OpenAI adapter.
        
        Args:
            api_key: OpenAI API key.
            base_url: Optional custom base URL (for proxies or Azure).
            timeout: Request timeout in seconds.
        """
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=httpx.Timeout(timeout),
        )
        self._timeout = timeout
    
    @property
    def provider_name(self) -> str:
        return "openai"
    
    async def chat_completion(self, request: ChatRequest) -> ChatResponse:
        """Execute a chat completion request."""
        try:
            # Convert to OpenAI format
            messages = [
                {
                    "role": m.role,
                    "content": m.content,
                    **({"name": m.name} if m.name else {}),
                    **({"tool_calls": m.tool_calls} if m.tool_calls else {}),
                    **({"tool_call_id": m.tool_call_id} if m.tool_call_id else {}),
                }
                for m in request.messages
            ]
            
            # Build request kwargs
            kwargs: dict = {
                "model": request.model,
                "messages": messages,
                "temperature": request.temperature,
                "stream": False,
            }
            
            if request.max_tokens:
                kwargs["max_tokens"] = request.max_tokens
            if request.top_p:
                kwargs["top_p"] = request.top_p
            if request.stop:
                kwargs["stop"] = request.stop
            if request.tools:
                kwargs["tools"] = request.tools
            if request.tool_choice:
                kwargs["tool_choice"] = request.tool_choice
            if request.user:
                kwargs["user"] = request.user
            
            # Make the request
            response = await self._client.chat.completions.create(**kwargs)
            
            # Convert response
            choices = [
                Choice(
                    index=c.index,
                    message=Message(
                        role=c.message.role,
                        content=c.message.content or "",
                        tool_calls=[tc.model_dump() for tc in c.message.tool_calls]
                        if c.message.tool_calls else None,
                    ),
                    finish_reason=c.finish_reason,
                )
                for c in response.choices
            ]
            
            usage = Usage(
                prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
                completion_tokens=response.usage.completion_tokens if response.usage else 0,
                total_tokens=response.usage.total_tokens if response.usage else 0,
            )
            
            return ChatResponse(
                id=response.id,
                model=response.model,
                choices=choices,
                usage=usage,
                created=response.created,
            )
            
        except RateLimitError as e:
            raise AdapterError(
                message="Rate limit exceeded",
                provider=self.provider_name,
                status_code=429,
                original_error=e,
            )
        except APIConnectionError as e:
            raise AdapterError(
                message="Failed to connect to OpenAI API",
                provider=self.provider_name,
                original_error=e,
            )
        except APIError as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                status_code=e.status_code,
                original_error=e,
            )
    
    async def chat_completion_stream(
        self, request: ChatRequest
    ) -> AsyncIterator[StreamChunk]:
        """Execute a streaming chat completion request."""
        try:
            # Convert to OpenAI format
            messages = [
                {
                    "role": m.role,
                    "content": m.content,
                    **({"name": m.name} if m.name else {}),
                }
                for m in request.messages
            ]
            
            # Build request kwargs
            kwargs: dict = {
                "model": request.model,
                "messages": messages,
                "temperature": request.temperature,
                "stream": True,
            }
            
            if request.max_tokens:
                kwargs["max_tokens"] = request.max_tokens
            if request.top_p:
                kwargs["top_p"] = request.top_p
            if request.stop:
                kwargs["stop"] = request.stop
            
            # Make the streaming request
            stream = await self._client.chat.completions.create(**kwargs)
            
            response_id = f"chatcmpl-{int(time.time())}"
            
            async for chunk in stream:
                if chunk.choices:
                    choice = chunk.choices[0]
                    delta = choice.delta
                    
                    yield StreamChunk(
                        id=chunk.id or response_id,
                        model=chunk.model or request.model,
                        delta_content=delta.content if delta else None,
                        delta_role=delta.role if delta else None,
                        finish_reason=choice.finish_reason,
                        index=choice.index,
                    )
                    
        except RateLimitError as e:
            raise AdapterError(
                message="Rate limit exceeded",
                provider=self.provider_name,
                status_code=429,
                original_error=e,
            )
        except APIConnectionError as e:
            raise AdapterError(
                message="Failed to connect to OpenAI API",
                provider=self.provider_name,
                original_error=e,
            )
        except APIError as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                status_code=e.status_code,
                original_error=e,
            )
    
    async def list_models(self) -> list[str]:
        """List available OpenAI models."""
        try:
            models = await self._client.models.list()
            return [m.id for m in models.data if "gpt" in m.id.lower()]
        except Exception as e:
            raise AdapterError(
                message="Failed to list models",
                provider=self.provider_name,
                original_error=e,
            )
    
    async def health_check(self) -> bool:
        """Check OpenAI API health."""
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
