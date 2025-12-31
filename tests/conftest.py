"""
AIRS-CP Test Configuration and Fixtures
"""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock

# Set test environment variables before importing modules
os.environ["AIRS_MODE"] = "observe"
os.environ["AIRS_PROVIDER"] = "ollama"
os.environ["AIRS_MODEL"] = "llama3.2:1b"
os.environ["OLLAMA_HOST"] = "http://localhost:11434"


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    from airs_cp.config.settings import Settings
    
    settings = Settings(
        mode="observe",
        provider="ollama",
        model="llama3.2:1b",
        host="0.0.0.0",
        port=8080,
        kill_switch=False,
        ollama_host="http://localhost:11434",
    )
    return settings


@pytest.fixture
def sample_chat_request():
    """Sample chat request for testing."""
    from airs_cp.adapters.base import ChatRequest, Message
    
    return ChatRequest(
        model="llama3.2:1b",
        messages=[
            Message(role="user", content="Hello, how are you?")
        ],
        temperature=0.7,
        max_tokens=100,
    )


@pytest.fixture
def sample_chat_response():
    """Sample chat response for testing."""
    import time
    from airs_cp.adapters.base import ChatResponse, Choice, Message, Usage
    
    return ChatResponse(
        id="test-response-123",
        model="llama3.2:1b",
        created=int(time.time()),
        choices=[
            Choice(
                index=0,
                message=Message(role="assistant", content="I'm doing well, thank you!"),
                finish_reason="stop"
            )
        ],
        usage=Usage(prompt_tokens=10, completion_tokens=8, total_tokens=18),
    )


@pytest.fixture
def mock_ollama_adapter():
    """Mock Ollama adapter."""
    from airs_cp.adapters.base import BaseAdapter
    
    adapter = AsyncMock(spec=BaseAdapter)
    adapter.provider = "ollama"
    adapter.health_check = AsyncMock(return_value=True)
    adapter.list_models = AsyncMock(return_value=["llama3.2:1b", "mistral"])
    return adapter


@pytest.fixture
def mock_httpx_client():
    """Mock httpx async client."""
    client = AsyncMock()
    client.post = AsyncMock()
    client.get = AsyncMock()
    return client


# Mark tests that require external services
requires_ollama = pytest.mark.skipif(
    os.environ.get("SKIP_INTEGRATION_TESTS", "1") == "1",
    reason="Integration test - requires Ollama running"
)

requires_openai = pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="Integration test - requires OPENAI_API_KEY"
)

requires_anthropic = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="Integration test - requires ANTHROPIC_API_KEY"
)
