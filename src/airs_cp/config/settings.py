"""
AIRS-CP Configuration Settings

Centralized configuration management using Pydantic Settings.
Supports environment variables and .env files.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeMode(str, Enum):
    """Runtime enforcement mode."""
    OBSERVE = "observe"
    ENFORCE = "enforce"


class Provider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    OLLAMA = "ollama"


class Settings(BaseSettings):
    """
    AIRS-CP Configuration.
    
    All settings can be configured via environment variables with the AIRS_ prefix.
    Example: AIRS_MODE=enforce, AIRS_PROVIDER=openai
    """
    
    model_config = SettingsConfigDict(
        env_prefix="AIRS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # Core settings
    mode: RuntimeMode = Field(
        default=RuntimeMode.OBSERVE,
        description="Runtime mode: observe (log only) or enforce (block/sanitize)"
    )
    provider: Provider = Field(
        default=Provider.OLLAMA,
        description="Default LLM provider"
    )
    model: str = Field(
        default="llama3.2:1b",
        description="Default model to use"
    )
    
    # Server settings
    host: str = Field(default="0.0.0.0", description="Gateway host")
    port: int = Field(default=8080, description="Gateway port")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # Kill switch
    kill_switch: bool = Field(
        default=False,
        description="Emergency kill switch - disables all enforcement"
    )
    
    # Provider API keys (from environment)
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key",
        alias="OPENAI_API_KEY"
    )
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key",
        alias="ANTHROPIC_API_KEY"
    )
    azure_openai_endpoint: Optional[str] = Field(
        default=None,
        description="Azure OpenAI endpoint",
        alias="AZURE_OPENAI_ENDPOINT"
    )
    azure_openai_key: Optional[str] = Field(
        default=None,
        description="Azure OpenAI API key",
        alias="AZURE_OPENAI_KEY"
    )
    azure_openai_api_version: str = Field(
        default="2024-02-15-preview",
        description="Azure OpenAI API version"
    )
    ollama_host: str = Field(
        default="http://localhost:11434",
        description="Ollama host URL",
        alias="OLLAMA_HOST"
    )
    
    # Database settings
    db_path: str = Field(
        default=os.environ.get("AIRS_DB_PATH", str(Path.home() / ".airs-cp" / "evidence.db")),
        description="SQLite database path"
    )
    
    # ML Model settings (Phase 2)
    models_dir: str = Field(
        default="./models",
        description="Directory for ML model files"
    )
    ml_enabled: bool = Field(
        default=True,
        description="Enable ML-based detection"
    )
    anomaly_threshold: float = Field(
        default=0.5,
        description="Anomaly score threshold (0-1)"
    )
    injection_threshold: float = Field(
        default=0.5,
        description="Injection confidence threshold (0-1)"
    )
    
    # Security settings (Phase 2)
    pii_detection_enabled: bool = Field(
        default=True,
        description="Enable PII detection"
    )
    injection_detection_enabled: bool = Field(
        default=True,
        description="Enable injection detection"
    )
    taint_tracking_enabled: bool = Field(
        default=True,
        description="Enable taint tracking"
    )
    
    # Explainability settings (Phase 2)
    explanations_enabled: bool = Field(
        default=True,
        description="Enable explanation generation"
    )
    llm_narratives_enabled: bool = Field(
        default=True,
        description="Use LLM for narrative generation"
    )
    narrative_model: str = Field(
        default="llama3.2:1b",
        description="Model for narrative generation"
    )
    
    # Timeouts
    request_timeout: float = Field(
        default=120.0,
        description="Request timeout in seconds"
    )
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper
    
    def get_effective_mode(self) -> RuntimeMode:
        """Get effective runtime mode (considering kill switch)."""
        if self.kill_switch:
            return RuntimeMode.OBSERVE
        return self.mode
    
    def validate_provider_config(self) -> list[str]:
        """Validate that required provider credentials are present."""
        errors = []
        
        if self.provider == Provider.OPENAI and not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required for OpenAI provider")
        
        if self.provider == Provider.ANTHROPIC and not self.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY is required for Anthropic provider")
        
        if self.provider == Provider.AZURE:
            if not self.azure_openai_endpoint:
                errors.append("AZURE_OPENAI_ENDPOINT is required for Azure provider")
            if not self.azure_openai_key:
                errors.append("AZURE_OPENAI_KEY is required for Azure provider")
        
        # Ollama doesn't require API keys
        
        return errors


# Global settings instance
settings = Settings()
