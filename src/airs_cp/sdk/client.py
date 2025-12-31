"""
AIRS-CP SDK Client

A lightweight SDK wrapper that provides easy integration with AIRS-CP.
Mimics the OpenAI client interface for minimal code changes.
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Iterator, Optional

import httpx


@dataclass
class Message:
    """A chat message."""
    role: str
    content: str
    name: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        result = {"role": self.role, "content": self.content}
        if self.name:
            result["name"] = self.name
        return result


@dataclass
class Choice:
    """A completion choice."""
    index: int
    message: Message
    finish_reason: Optional[str] = None


@dataclass
class Usage:
    """Token usage."""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass
class ChatCompletion:
    """Chat completion response."""
    id: str
    model: str
    choices: list[Choice]
    usage: Usage
    created: int
    object: str = "chat.completion"
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChatCompletion":
        choices = [
            Choice(
                index=c["index"],
                message=Message(
                    role=c["message"]["role"],
                    content=c["message"].get("content", ""),
                ),
                finish_reason=c.get("finish_reason"),
            )
            for c in data.get("choices", [])
        ]
        
        usage_data = data.get("usage", {})
        usage = Usage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )
        
        return cls(
            id=data.get("id", ""),
            model=data.get("model", ""),
            choices=choices,
            usage=usage,
            created=data.get("created", int(time.time())),
            object=data.get("object", "chat.completion"),
        )


@dataclass
class StreamChunk:
    """Streaming response chunk."""
    id: str
    model: str
    delta_content: Optional[str] = None
    delta_role: Optional[str] = None
    finish_reason: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StreamChunk":
        choices = data.get("choices", [])
        if not choices:
            return cls(id=data.get("id", ""), model=data.get("model", ""))
        
        delta = choices[0].get("delta", {})
        return cls(
            id=data.get("id", ""),
            model=data.get("model", ""),
            delta_content=delta.get("content"),
            delta_role=delta.get("role"),
            finish_reason=choices[0].get("finish_reason"),
        )


class AIRSError(Exception):
    """AIRS-CP SDK error."""
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response: Optional[httpx.Response] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


@dataclass
class ChatCompletions:
    """Chat completions API interface."""
    
    _client: "AIRSClient" = field(repr=False)
    
    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        session_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
        **kwargs,
    ) -> ChatCompletion | Iterator[StreamChunk]:
        """
        Create a chat completion.
        
        Args:
            model: Model to use.
            messages: List of messages.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            stream: Whether to stream the response.
            session_id: Optional AIRS session ID for tracking.
            tags: Optional tags for the request.
            **kwargs: Additional parameters passed to the API.
            
        Returns:
            ChatCompletion or Iterator of StreamChunks if streaming.
        """
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
            **kwargs,
        }
        
        if max_tokens:
            payload["max_tokens"] = max_tokens
        
        headers = self._client._build_headers(session_id, tags)
        
        if stream:
            return self._stream_response(payload, headers)
        else:
            return self._sync_response(payload, headers)
    
    def _sync_response(
        self, payload: dict[str, Any], headers: dict[str, str]
    ) -> ChatCompletion:
        """Make synchronous request."""
        response = self._client._http.post(
            f"{self._client._base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        )
        
        if response.status_code != 200:
            raise AIRSError(
                message=response.text,
                status_code=response.status_code,
                response=response,
            )
        
        return ChatCompletion.from_dict(response.json())
    
    def _stream_response(
        self, payload: dict[str, Any], headers: dict[str, str]
    ) -> Iterator[StreamChunk]:
        """Make streaming request."""
        with self._client._http.stream(
            "POST",
            f"{self._client._base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        ) as response:
            if response.status_code != 200:
                raise AIRSError(
                    message="Streaming request failed",
                    status_code=response.status_code,
                    response=response,
                )
            
            for line in response.iter_lines():
                if not line:
                    continue
                
                # Parse SSE format
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    
                    try:
                        chunk_data = json.loads(data)
                        yield StreamChunk.from_dict(chunk_data)
                    except json.JSONDecodeError:
                        continue


@dataclass
class Chat:
    """Chat API interface."""
    
    completions: ChatCompletions = field(init=False)
    _client: "AIRSClient" = field(repr=False)
    
    def __post_init__(self):
        self.completions = ChatCompletions(_client=self._client)


class AIRSClient:
    """
    AIRS-CP SDK Client.
    
    Provides an OpenAI-compatible interface to the AIRS-CP gateway.
    
    Example:
        >>> client = AIRSClient(airs_endpoint="http://localhost:8080")
        >>> response = client.chat.completions.create(
        ...     model="llama3.2:1b",
        ...     messages=[{"role": "user", "content": "Hello!"}],
        ... )
        >>> print(response.choices[0].message.content)
    """
    
    def __init__(
        self,
        airs_endpoint: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 120.0,
        default_session_id: Optional[str] = None,
    ):
        """
        Initialize the AIRS-CP client.
        
        Args:
            airs_endpoint: AIRS-CP gateway URL.
            api_key: Optional API key (passed through to backend).
            timeout: Request timeout in seconds.
            default_session_id: Default session ID for tracking.
        """
        self._base_url = airs_endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._default_session_id = default_session_id
        
        self._http = httpx.Client(timeout=httpx.Timeout(timeout))
        
        # Initialize chat interface
        self.chat = Chat(_client=self)
    
    def _build_headers(
        self,
        session_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "X-Session-ID": session_id or self._default_session_id or str(uuid.uuid4()),
            "X-Trace-ID": str(uuid.uuid4()),
        }
        
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        
        if tags:
            headers["X-Tags"] = ",".join(tags)
        
        return headers
    
    def health(self) -> dict[str, Any]:
        """Check gateway health."""
        response = self._http.get(f"{self._base_url}/health")
        response.raise_for_status()
        return response.json()
    
    def status(self) -> dict[str, Any]:
        """Get gateway status."""
        response = self._http.get(f"{self._base_url}/status")
        response.raise_for_status()
        return response.json()
    
    def set_mode(self, mode: str) -> dict[str, Any]:
        """
        Set runtime mode.
        
        Args:
            mode: Either "observe" or "enforce".
        """
        response = self._http.post(
            f"{self._base_url}/mode",
            json={"mode": mode},
        )
        response.raise_for_status()
        return response.json()
    
    def kill(self, activate: bool = True) -> dict[str, Any]:
        """
        Control kill switch.
        
        Args:
            activate: True to activate, False to deactivate.
        """
        if activate:
            response = self._http.post(f"{self._base_url}/kill")
        else:
            response = self._http.delete(f"{self._base_url}/kill")
        response.raise_for_status()
        return response.json()
    
    def close(self):
        """Close the HTTP client."""
        self._http.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


# Async version
class AsyncChatCompletions:
    """Async chat completions API interface."""
    
    def __init__(self, client: "AsyncAIRSClient"):
        self._client = client
    
    async def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        session_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
        **kwargs,
    ) -> ChatCompletion | AsyncIterator[StreamChunk]:
        """Create a chat completion (async)."""
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "stream": stream,
            **kwargs,
        }
        
        if max_tokens:
            payload["max_tokens"] = max_tokens
        
        headers = self._client._build_headers(session_id, tags)
        
        if stream:
            return self._stream_response(payload, headers)
        else:
            return await self._async_response(payload, headers)
    
    async def _async_response(
        self, payload: dict[str, Any], headers: dict[str, str]
    ) -> ChatCompletion:
        """Make async request."""
        response = await self._client._http.post(
            f"{self._client._base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        )
        
        if response.status_code != 200:
            raise AIRSError(
                message=response.text,
                status_code=response.status_code,
                response=response,
            )
        
        return ChatCompletion.from_dict(response.json())
    
    async def _stream_response(
        self, payload: dict[str, Any], headers: dict[str, str]
    ) -> AsyncIterator[StreamChunk]:
        """Make async streaming request."""
        async with self._client._http.stream(
            "POST",
            f"{self._client._base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        ) as response:
            if response.status_code != 200:
                raise AIRSError(
                    message="Streaming request failed",
                    status_code=response.status_code,
                    response=response,
                )
            
            async for line in response.aiter_lines():
                if not line:
                    continue
                
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    
                    try:
                        chunk_data = json.loads(data)
                        yield StreamChunk.from_dict(chunk_data)
                    except json.JSONDecodeError:
                        continue


class AsyncChat:
    """Async chat API interface."""
    
    def __init__(self, client: "AsyncAIRSClient"):
        self.completions = AsyncChatCompletions(client)


class AsyncAIRSClient:
    """
    Async AIRS-CP SDK Client.
    
    Example:
        >>> async with AsyncAIRSClient() as client:
        ...     response = await client.chat.completions.create(
        ...         model="llama3.2:1b",
        ...         messages=[{"role": "user", "content": "Hello!"}],
        ...     )
    """
    
    def __init__(
        self,
        airs_endpoint: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 120.0,
        default_session_id: Optional[str] = None,
    ):
        self._base_url = airs_endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._default_session_id = default_session_id
        
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(timeout))
        self.chat = AsyncChat(self)
    
    def _build_headers(
        self,
        session_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Session-ID": session_id or self._default_session_id or str(uuid.uuid4()),
            "X-Trace-ID": str(uuid.uuid4()),
        }
        
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        
        if tags:
            headers["X-Tags"] = ",".join(tags)
        
        return headers
    
    async def health(self) -> dict[str, Any]:
        response = await self._http.get(f"{self._base_url}/health")
        response.raise_for_status()
        return response.json()
    
    async def close(self):
        await self._http.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()
