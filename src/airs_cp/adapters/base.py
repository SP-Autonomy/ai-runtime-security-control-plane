"""
Base Adapter Interface

Defines the abstract interface that all LLM provider adapters must implement.
This enables provider-agnostic operation of the gateway.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional


@dataclass
class Message:
    """A chat message."""
    role: str
    content: str
    name: Optional[str] = None
    tool_calls: Optional[list[dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


@dataclass
class ChatRequest:
    """Unified chat completion request."""
    messages: list[Message]
    model: str
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    stream: bool = False
    top_p: Optional[float] = None
    stop: Optional[list[str]] = None
    tools: Optional[list[dict[str, Any]]] = None
    tool_choice: Optional[str | dict[str, Any]] = None
    user: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_openai_format(cls, data: dict[str, Any]) -> "ChatRequest":
        """Create from OpenAI API format."""
        messages = [
            Message(
                role=m["role"],
                content=m.get("content", ""),
                name=m.get("name"),
                tool_calls=m.get("tool_calls"),
                tool_call_id=m.get("tool_call_id"),
            )
            for m in data.get("messages", [])
        ]
        
        return cls(
            messages=messages,
            model=data.get("model", ""),
            temperature=data.get("temperature", 0.7),
            max_tokens=data.get("max_tokens"),
            stream=data.get("stream", False),
            top_p=data.get("top_p"),
            stop=data.get("stop"),
            tools=data.get("tools"),
            tool_choice=data.get("tool_choice"),
            user=data.get("user"),
        )
    
    def to_openai_format(self) -> dict[str, Any]:
        """Convert to OpenAI API format."""
        result: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {k: v for k, v in {
                    "role": m.role,
                    "content": m.content,
                    "name": m.name,
                    "tool_calls": m.tool_calls,
                    "tool_call_id": m.tool_call_id,
                }.items() if v is not None}
                for m in self.messages
            ],
            "temperature": self.temperature,
            "stream": self.stream,
        }
        
        if self.max_tokens:
            result["max_tokens"] = self.max_tokens
        if self.top_p:
            result["top_p"] = self.top_p
        if self.stop:
            result["stop"] = self.stop
        if self.tools:
            result["tools"] = self.tools
        if self.tool_choice:
            result["tool_choice"] = self.tool_choice
        if self.user:
            result["user"] = self.user
            
        return result


@dataclass
class Usage:
    """Token usage statistics."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class Choice:
    """A completion choice."""
    index: int
    message: Message
    finish_reason: Optional[str] = None


@dataclass
class ChatResponse:
    """Unified chat completion response."""
    id: str
    model: str
    choices: list[Choice]
    usage: Usage
    created: int
    object: str = "chat.completion"
    
    def to_openai_format(self) -> dict[str, Any]:
        """Convert to OpenAI API format."""
        return {
            "id": self.id,
            "object": self.object,
            "created": self.created,
            "model": self.model,
            "choices": [
                {
                    "index": c.index,
                    "message": {
                        "role": c.message.role,
                        "content": c.message.content,
                    },
                    "finish_reason": c.finish_reason,
                }
                for c in self.choices
            ],
            "usage": {
                "prompt_tokens": self.usage.prompt_tokens,
                "completion_tokens": self.usage.completion_tokens,
                "total_tokens": self.usage.total_tokens,
            },
        }


@dataclass
class StreamChunk:
    """A streaming response chunk."""
    id: str
    model: str
    delta_content: Optional[str] = None
    delta_role: Optional[str] = None
    finish_reason: Optional[str] = None
    index: int = 0
    
    def to_openai_format(self) -> dict[str, Any]:
        """Convert to OpenAI SSE format."""
        delta: dict[str, Any] = {}
        if self.delta_role:
            delta["role"] = self.delta_role
        if self.delta_content is not None:
            delta["content"] = self.delta_content
        
        return {
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": 0,  # Will be set by caller
            "model": self.model,
            "choices": [
                {
                    "index": self.index,
                    "delta": delta,
                    "finish_reason": self.finish_reason,
                }
            ],
        }


class BaseAdapter(ABC):
    """
    Abstract base class for LLM provider adapters.
    
    All provider adapters must implement this interface to ensure
    consistent behavior across the gateway.
    """
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'openai', 'anthropic')."""
        ...
    
    @abstractmethod
    async def chat_completion(self, request: ChatRequest) -> ChatResponse:
        """
        Execute a chat completion request.
        
        Args:
            request: The unified chat request.
            
        Returns:
            ChatResponse with the completion result.
            
        Raises:
            AdapterError: If the request fails.
        """
        ...
    
    @abstractmethod
    async def chat_completion_stream(
        self, request: ChatRequest
    ) -> AsyncIterator[StreamChunk]:
        """
        Execute a streaming chat completion request.
        
        Args:
            request: The unified chat request (stream=True).
            
        Yields:
            StreamChunk objects as they arrive.
            
        Raises:
            AdapterError: If the request fails.
        """
        ...
    
    @abstractmethod
    async def list_models(self) -> list[str]:
        """
        List available models for this provider.
        
        Returns:
            List of model identifiers.
        """
        ...
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the provider is reachable and operational.
        
        Returns:
            True if healthy, False otherwise.
        """
        ...


class AdapterError(Exception):
    """Base exception for adapter errors."""
    
    def __init__(
        self,
        message: str,
        provider: str,
        status_code: Optional[int] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code
        self.original_error = original_error
