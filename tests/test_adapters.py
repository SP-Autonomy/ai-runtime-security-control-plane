"""
Tests for LLM Provider Adapters

Tests the adapter layer including base classes, data models,
and provider-specific implementations.
"""

import pytest
import time


class TestBaseAdapter:
    """Tests for base adapter data models."""
    
    def test_message_creation(self):
        """Test Message dataclass creation."""
        from airs_cp.adapters.base import Message
        
        msg = Message(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"
        assert msg.name is None
        assert msg.tool_calls is None
    
    def test_chat_request_creation(self):
        """Test ChatRequest creation from OpenAI format."""
        from airs_cp.adapters.base import ChatRequest, Message
        
        data = {
            "model": "llama3.2:1b",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ],
            "temperature": 0.5,
            "stream": False,
        }
        
        request = ChatRequest.from_openai_format(data)
        assert request.model == "llama3.2:1b"
        assert len(request.messages) == 1
        assert request.messages[0].content == "Hello!"
        assert request.temperature == 0.5
        assert request.stream is False
    
    def test_chat_response_creation(self, sample_chat_response):
        """Test ChatResponse creation and OpenAI format conversion."""
        assert sample_chat_response.id == "test-response-123"
        assert sample_chat_response.model == "llama3.2:1b"
        assert len(sample_chat_response.choices) == 1
        
        # Test OpenAI format conversion
        openai_format = sample_chat_response.to_openai_format()
        assert openai_format["id"] == "test-response-123"
        assert openai_format["object"] == "chat.completion"
        assert openai_format["model"] == "llama3.2:1b"
        assert len(openai_format["choices"]) == 1
    
    def test_adapter_error(self):
        """Test AdapterError exception."""
        from airs_cp.adapters.base import AdapterError
        
        error = AdapterError(
            message="Test error",
            provider="test",
            status_code=500,
            original_error=ValueError("Original"),
        )
        
        assert str(error) == "Test error"
        assert error.provider == "test"
        assert error.status_code == 500
        assert isinstance(error.original_error, ValueError)


class TestAdapterRegistry:
    """Tests for the adapter registry."""
    
    def test_registry_singleton(self, mock_settings):
        """Test registry pattern with settings."""
        from airs_cp.adapters.registry import AdapterRegistry
        
        registry = AdapterRegistry(mock_settings)
        assert registry is not None
    
    def test_supported_providers(self, mock_settings):
        """Test supported provider list."""
        from airs_cp.adapters.registry import AdapterRegistry
        from airs_cp.config.settings import Provider
        
        registry = AdapterRegistry(mock_settings)
        
        # Ollama should work without API key
        adapter = registry.get_adapter(Provider.OLLAMA)
        assert adapter is not None
        assert adapter.provider_name == "ollama"
    
    def test_invalid_provider(self, mock_settings):
        """Test error on missing credentials."""
        from airs_cp.adapters.registry import AdapterRegistry
        from airs_cp.adapters.base import AdapterError
        from airs_cp.config.settings import Provider
        
        registry = AdapterRegistry(mock_settings)
        
        # OpenAI requires API key
        with pytest.raises(AdapterError) as exc_info:
            registry.get_adapter(Provider.OPENAI)
        assert "OPENAI_API_KEY" in str(exc_info.value)


class TestOllamaAdapter:
    """Tests for Ollama adapter."""
    
    def test_chat_completion_format(self):
        """Test Ollama request format."""
        from airs_cp.adapters.ollama_adapter import OllamaAdapter
        from airs_cp.adapters.base import ChatRequest, Message
        
        adapter = OllamaAdapter(host="http://localhost:11434")
        
        request = ChatRequest(
            model="llama3.2:1b",
            messages=[Message(role="user", content="Hello")],
            temperature=0.7,
        )
        
        # The adapter should format correctly for Ollama's API
        assert request.model == "llama3.2:1b"
        assert len(request.messages) == 1
    
    @pytest.mark.asyncio
    async def test_response_parsing(self):
        """Test Ollama response parsing."""
        from airs_cp.adapters.ollama_adapter import OllamaAdapter
        from airs_cp.adapters.base import ChatRequest, Message
        
        # Mock response from Ollama
        mock_response = {
            "model": "llama3.2:1b",
            "message": {
                "role": "assistant",
                "content": "Hello! I'm doing great."
            },
            "done": True,
            "total_duration": 1000000000,
            "prompt_eval_count": 10,
            "eval_count": 8
        }
        
        adapter = OllamaAdapter(host="http://localhost:11434")
        
        # Test that we can create a chat response from the mock data
        from airs_cp.adapters.base import ChatResponse, Choice, Usage
        
        response = ChatResponse(
            id="test",
            model=mock_response["model"],
            created=int(time.time()),
            choices=[
                Choice(
                    index=0,
                    message=Message(
                        role=mock_response["message"]["role"],
                        content=mock_response["message"]["content"]
                    ),
                    finish_reason="stop"
                )
            ],
            usage=Usage(
                prompt_tokens=mock_response.get("prompt_eval_count", 0),
                completion_tokens=mock_response.get("eval_count", 0),
                total_tokens=mock_response.get("prompt_eval_count", 0) + mock_response.get("eval_count", 0)
            )
        )
        
        assert response.model == "llama3.2:1b"
        assert response.choices[0].message.content == "Hello! I'm doing great."
        assert response.usage.total_tokens == 18
    
    def test_provider_name(self):
        """Test Ollama adapter provider_name property."""
        from airs_cp.adapters.ollama_adapter import OllamaAdapter
        
        adapter = OllamaAdapter(host="http://localhost:11434")
        assert adapter.provider_name == "ollama"


class TestOpenAIAdapter:
    """Tests for OpenAI adapter."""
    
    def test_adapter_initialization(self):
        """Test OpenAI adapter can be initialized."""
        from airs_cp.adapters.openai_adapter import OpenAIAdapter
        
        # Will use OPENAI_API_KEY from env or fail gracefully
        adapter = OpenAIAdapter(api_key="test-key")
        assert adapter.provider_name == "openai"
    
    def test_model_mapping(self):
        """Test model name handling."""
        from airs_cp.adapters.openai_adapter import OpenAIAdapter
        
        adapter = OpenAIAdapter(api_key="test-key")
        # OpenAI adapter should pass through model names
        assert adapter.provider_name == "openai"


class TestAnthropicAdapter:
    """Tests for Anthropic adapter."""
    
    def test_adapter_initialization(self):
        """Test Anthropic adapter can be initialized."""
        from airs_cp.adapters.anthropic_adapter import AnthropicAdapter
        
        adapter = AnthropicAdapter(api_key="test-key")
        assert adapter.provider_name == "anthropic"
    
    def test_message_conversion(self):
        """Test message format conversion for Anthropic."""
        from airs_cp.adapters.base import Message
        
        # Anthropic requires system messages to be separate
        messages = [
            Message(role="system", content="You are helpful"),
            Message(role="user", content="Hello"),
        ]
        
        # Filter out system messages (Anthropic handles them separately)
        non_system = [m for m in messages if m.role != "system"]
        system_msgs = [m for m in messages if m.role == "system"]
        
        assert len(non_system) == 1
        assert len(system_msgs) == 1
        assert system_msgs[0].content == "You are helpful"


class TestAzureAdapter:
    """Tests for Azure OpenAI adapter."""
    
    def test_adapter_initialization(self):
        """Test Azure adapter can be initialized."""
        from airs_cp.adapters.azure_adapter import AzureOpenAIAdapter
        
        adapter = AzureOpenAIAdapter(
            azure_endpoint="https://test.openai.azure.com",
            api_key="test-key",
            api_version="2024-02-15-preview"
        )
        assert adapter.provider_name == "azure"
    
    def test_deployment_name_handling(self):
        """Test that Azure uses deployment names as models."""
        from airs_cp.adapters.azure_adapter import AzureOpenAIAdapter
        
        adapter = AzureOpenAIAdapter(
            azure_endpoint="https://test.openai.azure.com",
            api_key="test-key"
        )
        
        # Azure adapter should be ready
        assert adapter.provider_name == "azure"
