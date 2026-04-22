"""Single configurable LLM provider (grok, claude, groq, openai)."""

import os
import json
import tiktoken
from typing import Optional
from pydantic import BaseModel


class ProviderConfig(BaseModel):
    """Provider configuration."""

    provider: str  # grok, claude, groq, openai
    model: str
    api_key: str
    base_url: Optional[str] = None  # for local Ollama or custom endpoints


class Provider:
    """Single LLM provider interface supporting multiple backends."""

    def __init__(self, config_path: str = "config/config.yaml"):
        """Initialize provider from config."""
        self.config = self._load_config(config_path)
        self.provider = self.config.provider
        self.model = self.config.model
        self.api_key = self.config.api_key
        self.base_url = self.config.base_url

        self._initialize_client()

    def _load_config(self, config_path: str) -> ProviderConfig:
        """Load provider config from YAML or environment."""
        # For now, read from environment variables
        provider = os.getenv("LLM_PROVIDER", "claude")
        model = os.getenv("LLM_MODEL", "claude-opus-4-6")
        api_key = os.getenv(f"{provider.upper()}_API_KEY", "")
        base_url = os.getenv("LLM_BASE_URL", None)

        if not api_key:
            raise ValueError(f"No API key found for provider: {provider}")

        return ProviderConfig(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
        )

    def _initialize_client(self) -> None:
        """Initialize the appropriate client based on provider."""
        if self.provider == "claude":
            from anthropic import Anthropic

            self.client = Anthropic(api_key=self.api_key)
        elif self.provider == "grok":
            from openai import OpenAI  # Grok uses OpenAI-compatible API

            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url or "https://api.x.ai/v1",
            )
        elif self.provider == "groq":
            from groq import Groq

            self.client = Groq(api_key=self.api_key)
        elif self.provider == "openai":
            from openai import OpenAI

            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def create_completion(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> str:
        """Create a completion using the configured provider."""
        messages = []

        if system:
            messages.append({"role": "system", "content": system})

        messages.append({"role": "user", "content": prompt})

        if self.provider == "claude":
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=messages,
            )
            return response.content[0].text

        elif self.provider in ["grok", "groq", "openai"]:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content

        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def create_json_completion(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> dict:
        """Create a completion that returns valid JSON."""
        messages = []

        if system:
            messages.append({"role": "system", "content": system})

        messages.append({"role": "user", "content": prompt})

        if self.provider == "claude":
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=messages,
            )
            content = response.content[0].text
        elif self.provider in ["grok", "groq", "openai"]:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

        # Parse JSON from response
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
                return json.loads(json_str)
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]
                return json.loads(json_str)
            else:
                raise ValueError(f"Failed to parse JSON response: {content}")

    def tokenize_estimate(self, text: str) -> int:
        """Estimate token count for text."""
        try:
            encoding = tiktoken.encoding_for_model(self.model)
        except KeyError:
            # Fallback for unknown models
            encoding = tiktoken.get_encoding("cl100k_base")

        return len(encoding.encode(text))

    def estimate_completion_tokens(self, text: str) -> int:
        """Estimate tokens needed for completion response."""
        # Rough estimate: input tokens + 25% overhead
        input_tokens = self.tokenize_estimate(text)
        return int(input_tokens * 1.25)


def get_provider() -> Provider:
    """Get a singleton provider instance."""
    if not hasattr(get_provider, "_instance"):
        get_provider._instance = Provider()
    return get_provider._instance
