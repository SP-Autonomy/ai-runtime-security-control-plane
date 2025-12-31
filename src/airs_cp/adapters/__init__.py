"""
LLM Provider Adapters

Provides a unified interface to multiple LLM providers:
- OpenAI
- Anthropic (Claude)
- Azure OpenAI
- Ollama (local)
"""

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
from airs_cp.adapters.registry import AdapterRegistry, get_adapter, get_registry

__all__ = [
    "BaseAdapter",
    "AdapterError",
    "ChatRequest",
    "ChatResponse",
    "Choice",
    "Message",
    "StreamChunk",
    "Usage",
    "AdapterRegistry",
    "get_adapter",
    "get_registry",
]
