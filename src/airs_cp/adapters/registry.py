"""
Adapter Registry

Factory for creating and managing LLM provider adapters.
Provides a unified interface to get the appropriate adapter based on configuration.
"""

from typing import Optional

from airs_cp.adapters.anthropic_adapter import AnthropicAdapter
from airs_cp.adapters.azure_adapter import AzureOpenAIAdapter
from airs_cp.adapters.base import AdapterError, BaseAdapter
from airs_cp.adapters.ollama_adapter import OllamaAdapter
from airs_cp.adapters.openai_adapter import OpenAIAdapter
from airs_cp.config.settings import Provider, Settings


class AdapterRegistry:
    """
    Registry for LLM provider adapters.
    
    Manages adapter lifecycle and provides factory methods
    for creating adapters based on configuration.
    """
    
    def __init__(self, settings: Settings):
        """
        Initialize the adapter registry.
        
        Args:
            settings: Application settings.
        """
        self._settings = settings
        self._adapters: dict[Provider, BaseAdapter] = {}
    
    def get_adapter(self, provider: Optional[Provider] = None) -> BaseAdapter:
        """
        Get an adapter for the specified provider.
        
        Args:
            provider: Provider to get adapter for. Defaults to settings.provider.
            
        Returns:
            BaseAdapter instance for the provider.
            
        Raises:
            AdapterError: If adapter cannot be created.
        """
        provider = provider or self._settings.provider
        
        # Return cached adapter if available
        if provider in self._adapters:
            return self._adapters[provider]
        
        # Create new adapter
        adapter = self._create_adapter(provider)
        self._adapters[provider] = adapter
        return adapter
    
    def _create_adapter(self, provider: Provider) -> BaseAdapter:
        """Create a new adapter instance."""
        if provider == Provider.OPENAI:
            if not self._settings.openai_api_key:
                raise AdapterError(
                    message="OPENAI_API_KEY is required for OpenAI provider",
                    provider="openai",
                )
            return OpenAIAdapter(
                api_key=self._settings.openai_api_key,
                timeout=self._settings.request_timeout,
            )
        
        elif provider == Provider.ANTHROPIC:
            if not self._settings.anthropic_api_key:
                raise AdapterError(
                    message="ANTHROPIC_API_KEY is required for Anthropic provider",
                    provider="anthropic",
                )
            return AnthropicAdapter(
                api_key=self._settings.anthropic_api_key,
                timeout=self._settings.request_timeout,
            )
        
        elif provider == Provider.AZURE:
            if not self._settings.azure_openai_endpoint:
                raise AdapterError(
                    message="AZURE_OPENAI_ENDPOINT is required for Azure provider",
                    provider="azure",
                )
            if not self._settings.azure_openai_key:
                raise AdapterError(
                    message="AZURE_OPENAI_KEY is required for Azure provider",
                    provider="azure",
                )
            return AzureOpenAIAdapter(
                azure_endpoint=self._settings.azure_openai_endpoint,
                api_key=self._settings.azure_openai_key,
                api_version=self._settings.azure_openai_api_version,
                timeout=self._settings.request_timeout,
            )
        
        elif provider == Provider.OLLAMA:
            return OllamaAdapter(
                host=self._settings.ollama_host,
                timeout=self._settings.request_timeout,
            )
        
        else:
            raise AdapterError(
                message=f"Unknown provider: {provider}",
                provider=str(provider),
            )
    
    async def health_check_all(self) -> dict[str, bool]:
        """
        Check health of all configured adapters.
        
        Returns:
            Dict mapping provider name to health status.
        """
        results = {}
        for provider, adapter in self._adapters.items():
            try:
                results[provider.value] = await adapter.health_check()
            except Exception:
                results[provider.value] = False
        return results
    
    async def close_all(self) -> None:
        """Close all adapter connections."""
        for adapter in self._adapters.values():
            if hasattr(adapter, "close"):
                await adapter.close()
        self._adapters.clear()


# Global registry instance (initialized with settings)
_registry: Optional[AdapterRegistry] = None


def get_registry(settings: Optional[Settings] = None) -> AdapterRegistry:
    """
    Get the global adapter registry.
    
    Args:
        settings: Optional settings to use. Defaults to global settings.
        
    Returns:
        AdapterRegistry instance.
    """
    global _registry
    if _registry is None:
        if settings is None:
            from airs_cp.config.settings import settings as default_settings
            settings = default_settings
        _registry = AdapterRegistry(settings)
    return _registry


def get_adapter(provider: Optional[Provider] = None) -> BaseAdapter:
    """
    Convenience function to get an adapter.
    
    Args:
        provider: Provider to get adapter for.
        
    Returns:
        BaseAdapter instance.
    """
    return get_registry().get_adapter(provider)
