"""
Anthropic Adapter

Implements the BaseAdapter interface for Anthropic's Claude API.
Supports both chat completions and streaming.
"""

import time
from typing import AsyncIterator, Optional

import httpx
from anthropic import AsyncAnthropic, APIError, APIConnectionError, RateLimitError

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


class AnthropicAdapter(BaseAdapter):
    """
    Anthropic Claude API Adapter.
    
    Provides chat completion functionality using Anthropic's API,
    with support for streaming responses. Translates between
    OpenAI-style requests and Anthropic's message format.
    """
    
    def __init__(
        self,
        api_key: str,
        timeout: float = 120.0,
    ):
        """
        Initialize the Anthropic adapter.
        
        Args:
            api_key: Anthropic API key.
            timeout: Request timeout in seconds.
        """
        self._client = AsyncAnthropic(
            api_key=api_key,
            timeout=httpx.Timeout(timeout),
        )
        self._timeout = timeout
    
    @property
    def provider_name(self) -> str:
        return "anthropic"
    
    def _convert_messages(
        self, messages: list[Message]
    ) -> tuple[Optional[str], list[dict]]:
        """
        Convert OpenAI-style messages to Anthropic format.
        
        Returns:
            Tuple of (system_prompt, messages)
        """
        system_prompt: Optional[str] = None
        converted: list[dict] = []
        
        for msg in messages:
            if msg.role == "system":
                # Anthropic uses a separate system parameter
                system_prompt = msg.content
            elif msg.role == "assistant":
                converted.append({
                    "role": "assistant",
                    "content": msg.content,
                })
            else:
                # Map user, tool results, etc.
                converted.append({
                    "role": "user",
                    "content": msg.content,
                })
        
        return system_prompt, converted
    
    def _model_mapping(self, model: str) -> str:
        """Map model names to Anthropic equivalents."""
        mappings = {
            "gpt-4": "claude-3-opus-20240229",
            "gpt-4-turbo": "claude-3-opus-20240229",
            "gpt-3.5-turbo": "claude-3-sonnet-20240229",
            "claude-3-opus": "claude-3-opus-20240229",
            "claude-3-sonnet": "claude-3-sonnet-20240229",
            "claude-3-haiku": "claude-3-haiku-20240307",
        }
        return mappings.get(model, model)
    
    async def chat_completion(self, request: ChatRequest) -> ChatResponse:
        """Execute a chat completion request."""
        try:
            system_prompt, messages = self._convert_messages(request.messages)
            model = self._model_mapping(request.model)
            
            # Build request kwargs
            kwargs: dict = {
                "model": model,
                "messages": messages,
                "max_tokens": request.max_tokens or 4096,
            }
            
            if system_prompt:
                kwargs["system"] = system_prompt
            if request.temperature:
                kwargs["temperature"] = request.temperature
            if request.top_p:
                kwargs["top_p"] = request.top_p
            if request.stop:
                kwargs["stop_sequences"] = request.stop
            
            # Make the request
            response = await self._client.messages.create(**kwargs)
            
            # Convert response to OpenAI format
            content = ""
            if response.content:
                for block in response.content:
                    if hasattr(block, "text"):
                        content += block.text
            
            choices = [
                Choice(
                    index=0,
                    message=Message(
                        role="assistant",
                        content=content,
                    ),
                    finish_reason=self._map_stop_reason(response.stop_reason),
                )
            ]
            
            usage = Usage(
                prompt_tokens=response.usage.input_tokens,
                completion_tokens=response.usage.output_tokens,
                total_tokens=response.usage.input_tokens + response.usage.output_tokens,
            )
            
            return ChatResponse(
                id=response.id,
                model=response.model,
                choices=choices,
                usage=usage,
                created=int(time.time()),
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
                message="Failed to connect to Anthropic API",
                provider=self.provider_name,
                original_error=e,
            )
        except APIError as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                status_code=getattr(e, "status_code", None),
                original_error=e,
            )
    
    async def chat_completion_stream(
        self, request: ChatRequest
    ) -> AsyncIterator[StreamChunk]:
        """Execute a streaming chat completion request."""
        try:
            system_prompt, messages = self._convert_messages(request.messages)
            model = self._model_mapping(request.model)
            
            # Build request kwargs
            kwargs: dict = {
                "model": model,
                "messages": messages,
                "max_tokens": request.max_tokens or 4096,
            }
            
            if system_prompt:
                kwargs["system"] = system_prompt
            if request.temperature:
                kwargs["temperature"] = request.temperature
            if request.top_p:
                kwargs["top_p"] = request.top_p
            if request.stop:
                kwargs["stop_sequences"] = request.stop
            
            response_id = f"msg_{int(time.time())}"
            sent_role = False
            
            # Make the streaming request
            async with self._client.messages.stream(**kwargs) as stream:
                async for event in stream:
                    if hasattr(event, "type"):
                        if event.type == "content_block_delta":
                            if hasattr(event.delta, "text"):
                                yield StreamChunk(
                                    id=response_id,
                                    model=model,
                                    delta_content=event.delta.text,
                                    delta_role="assistant" if not sent_role else None,
                                    index=0,
                                )
                                sent_role = True
                        elif event.type == "message_stop":
                            yield StreamChunk(
                                id=response_id,
                                model=model,
                                finish_reason="stop",
                                index=0,
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
                message="Failed to connect to Anthropic API",
                provider=self.provider_name,
                original_error=e,
            )
        except APIError as e:
            raise AdapterError(
                message=str(e),
                provider=self.provider_name,
                status_code=getattr(e, "status_code", None),
                original_error=e,
            )
    
    def _map_stop_reason(self, reason: Optional[str]) -> Optional[str]:
        """Map Anthropic stop reasons to OpenAI format."""
        if reason is None:
            return None
        mapping = {
            "end_turn": "stop",
            "stop_sequence": "stop",
            "max_tokens": "length",
        }
        return mapping.get(reason, reason)
    
    async def list_models(self) -> list[str]:
        """List available Anthropic models."""
        # Anthropic doesn't have a list models endpoint
        return [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
            "claude-2.0",
        ]
    
    async def health_check(self) -> bool:
        """Check Anthropic API health."""
        try:
            # Make a minimal request to check connectivity
            await self._client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
            return True
        except Exception:
            return False
