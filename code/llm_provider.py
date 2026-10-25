"""
LLM Provider interface and implementations for Ghost Data Still Exists challenge.
Supports multiple providers with unified interface and usage tracking.
"""
import os
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading


def _load_local_env() -> None:
    """Load simple KEY=VALUE entries from code/.env without logging values."""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                name = name.strip()
                value = value.strip().strip("\"'")
                if name and value:
                    os.environ[name] = value
    except OSError:
        return


_load_local_env()


@dataclass
class ModelUsage:
    """Track token usage for a single model call."""
    model_name: str
    provider: str
    input_tokens: int
    output_tokens: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    case_id: Optional[str] = None
    operation: Optional[str] = None


@dataclass
class UsageTracker:
    """Track all model usage across the session."""
    calls: List[ModelUsage] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, usage: ModelUsage) -> None:
        with self._lock:
            self.calls.append(usage)

    def get_total_tokens(self) -> Dict[str, int]:
        total_input = sum(c.input_tokens for c in self.calls)
        total_output = sum(c.output_tokens for c in self.calls)
        return {
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_input + total_output,
            "call_count": len(self.calls)
        }

    def get_by_model(self) -> Dict[str, Dict[str, int]]:
        result = {}
        for call in self.calls:
            key = f"{call.provider}/{call.model_name}"
            if key not in result:
                result[key] = {"input_tokens": 0, "output_tokens": 0, "calls": 0}
            result[key]["input_tokens"] += call.input_tokens
            result[key]["output_tokens"] += call.output_tokens
            result[key]["calls"] += 1
        return result

    def export_report(self) -> Dict[str, Any]:
        """Export usage report for usage_report.md generation."""
        total = self.get_total_tokens()
        by_model = self.get_by_model()

        # Calculate costs (approximate, will need actual pricing)
        cost_per_1k_input = 0.003  # placeholder
        cost_per_1k_output = 0.015  # placeholder

        model_costs = {}
        for model_key, stats in by_model.items():
            input_cost = (stats["input_tokens"] / 1000) * cost_per_1k_input
            output_cost = (stats["output_tokens"] / 1000) * cost_per_1k_output
            model_costs[model_key] = {
                "input_cost_usd": round(input_cost, 6),
                "output_cost_usd": round(output_cost, 6),
                "total_cost_usd": round(input_cost + output_cost, 6)
            }

        total_input_cost = sum(mc["input_cost_usd"] for mc in model_costs.values())
        total_output_cost = sum(mc["output_cost_usd"] for mc in model_costs.values())

        return {
            "summary": {
                "total_calls": total["call_count"],
                "total_input_tokens": total["input_tokens"],
                "total_output_tokens": total["output_tokens"],
                "total_tokens": total["total_tokens"],
                "estimated_total_cost_usd": round(total_input_cost + total_output_cost, 6)
            },
            "by_model": {
                model: {**stats, **model_costs.get(model, {})}
                for model, stats in by_model.items()
            },
            "calls": [
                {
                    "model": f"{c.provider}/{c.model_name}",
                    "input_tokens": c.input_tokens,
                    "output_tokens": c.output_tokens,
                    "timestamp": c.timestamp,
                    "case_id": c.case_id,
                    "operation": c.operation
                }
                for c in self.calls
            ]
        }


# Global usage tracker
_usage_tracker = UsageTracker()


def get_usage_tracker() -> UsageTracker:
    """Get the global usage tracker."""
    return _usage_tracker


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        pass

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Complete a prompt and return structured response with usage info."""
        pass

    def _record_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        case_id: Optional[str] = None,
        operation: Optional[str] = None
    ) -> None:
        """Record token usage."""
        usage = ModelUsage(
            model_name=self.model_name,
            provider=self.provider_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            case_id=case_id,
            operation=operation
        )
        _usage_tracker.record(usage)


class MockLLMProvider(LLMProvider):
    """Mock provider for testing without API calls."""

    def __init__(self, model_name: str = "mock-model"):
        self._model_name = model_name
        # Key → response dict. Keys are matched against both the prompt
        # string and an explicit case_id passed via the 'case_id' kwarg.
        self._responses: Dict[str, Dict[str, Any]] = {}
        self._queue: List[Dict[str, Any]] = []  # FIFO for sequential tests
        self._default_response: Dict[str, Any] = {
            "intent": "DELETION",
            "scope": "FULL_ACCOUNT_AND_DATA",
            "retention_exceptions": [],
            "ambiguity": "NONE",
            "confidence": 0.95,
            "reasoning": "Mock default",
        }

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return self._model_name

    def set_response(self, key: str, response: Dict[str, Any]) -> None:
        """Set a canned response matched by substring against the full prompt."""
        self._responses[key] = response

    def set_default_response(self, response: Dict[str, Any]) -> None:
        """Override the default (fallback) response."""
        self._default_response = response

    def enqueue_response(self, response: Dict[str, Any]) -> None:
        """Push a response that will be consumed once on the next call (FIFO)."""
        self._queue.append(response)

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a canned response.

        Lookup priority:
        1. FIFO queue (consumed once).
        2. Exact case_id match (when caller passes case_id kwarg).
        3. Substring match of any registered key in the full prompt.
        4. Default response.
        """
        self._record_usage(100, 50)

        # 1. FIFO queue
        if self._queue:
            return self._queue.pop(0)

        # 2. Exact case_id match
        if case_id and case_id in self._responses:
            return self._responses[case_id]

        # 3. Substring match in prompt
        for key, response in self._responses.items():
            if key in prompt:
                return response

        # 4. Default
        return dict(self._default_response)


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "claude-sonnet-5-5",
        max_retries: int = 3
    ):
        self._model_name = model_name
        self._max_retries = max_retries
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")

        # Lazy import to avoid dependency if not used
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self._api_key)
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model_name

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self._model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if response_format and response_format.get("type") == "json_object":
            kwargs["response_format"] = response_format

        last_error = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.messages.create(**kwargs)

                # Extract content
                content = ""
                for block in response.content:
                    if block.type == "text":
                        content += block.text

                # Parse JSON if response_format requested JSON
                if response_format and response_format.get("type") == "json_object":
                    try:
                        parsed = json.loads(content)
                    except json.JSONDecodeError:
                        # Try to extract JSON from markdown code block
                        import re
                        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                        if match:
                            parsed = json.loads(match.group(1))
                        else:
                            raise
                else:
                    parsed = {"text": content}

                # Record usage
                self._record_usage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens
                )

                return parsed

            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                continue

        raise RuntimeError(f"Failed after {self._max_retries} attempts: {last_error}")


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "gpt-4o",
        max_retries: int = 3
    ):
        self._model_name = model_name
        self._max_retries = max_retries
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise ValueError("OPENAI_API_KEY not set in environment")

        try:
            import openai
            self._client = openai.OpenAI(api_key=self._api_key)
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model_name

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self._model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if response_format and response_format.get("type") == "json_object":
            kwargs["response_format"] = {"type": "json_object"}

        last_error = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.chat.completions.create(**kwargs)

                content = response.choices[0].message.content or ""

                # Parse JSON if requested
                if response_format and response_format.get("type") == "json_object":
                    try:
                        parsed = json.loads(content)
                    except json.JSONDecodeError:
                        import re
                        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                        if match:
                            parsed = json.loads(match.group(1))
                        else:
                            raise
                else:
                    parsed = {"text": content}

                # Record usage
                self._record_usage(
                    input_tokens=response.usage.prompt_tokens,
                    output_tokens=response.usage.completion_tokens
                )

                return parsed

            except Exception as e:
                last_error = e
                if attempt < self._max_retries - 1:
                    time.sleep(2 ** attempt)
                continue

        raise RuntimeError(f"Failed after {self._max_retries} attempts: {last_error}")


class NvidiaProvider(OpenAIProvider):
    """NVIDIA NIM provider using its OpenAI-compatible API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "nvidia/nemotron-3.5-lightning-30b-a3b",
        max_retries: int = 3,
    ):
        self._model_name = model_name
        self._max_retries = max_retries
        self._api_key = api_key or os.environ.get("NVIDIA_API_KEY")
        if not self._api_key:
            raise ValueError("NVIDIA_API_KEY not set in environment")

        try:
            import openai
            self._client = openai.OpenAI(
                api_key=self._api_key,
                base_url="https://integrate.api.nvidia.com/v1",
            )
        except ImportError:
            raise ImportError("openai package not installed. Run: uv pip install openai")

    @property
    def provider_name(self) -> str:
        return "nvidia"


class OpenRouterProvider(OpenAIProvider):
    """OpenRouter provider using its OpenAI-compatible API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "google/gemma-4-26b-a4b-it:free",
        max_retries: int = 3,
    ):
        self._model_name = model_name
        self._max_retries = max_retries
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not self._api_key:
            raise ValueError("OPENROUTER_API_KEY not set in environment")

        try:
            import openai
            self._openai = openai
            self._client = openai.OpenAI(
                api_key=self._api_key,
                base_url="https://openrouter.ai/api/v1",
                timeout=120.0,
            )
        except ImportError:
            raise ImportError("openai package not installed. Run: uv pip install openai")

    @property
    def provider_name(self) -> str:
        return "openrouter"

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 256,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self._model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": min(max_tokens, 256),
            "extra_body": {"reasoning": {"enabled": False}},
        }
        if response_format and response_format.get("type") == "json_object":
            kwargs["response_format"] = {"type": "json_object"}

        last_error = None
        reasoning_fallback_used = False
        transient_statuses = {502, 503, 504}
        for attempt in range(self._max_retries):
            try:
                response = self._client.chat.completions.create(**kwargs)
                choices = getattr(response, "choices", None)
                if not choices:
                    raise ValueError("OpenRouter response did not contain choices")

                choice = choices[0]
                message = getattr(choice, "message", None)
                if message is None:
                    raise ValueError("OpenRouter response choice did not contain message")

                content = getattr(message, "content", None)
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("OpenRouter response message did not contain content")
                content = content.strip()

                if response_format and response_format.get("type") == "json_object":
                    try:
                        parsed = json.loads(content)
                    except json.JSONDecodeError:
                        import re
                        match = re.search(
                            r"```(?:json)?\s*(\{.*?\})\s*```",
                            content,
                            re.DOTALL,
                        )
                        if not match:
                            raise
                        parsed = json.loads(match.group(1))
                else:
                    parsed = {"text": content}

                usage = getattr(response, "usage", None)
                input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
                output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
                finish_reason = getattr(choice, "finish_reason", None)
                print(
                    "OPENROUTER status=200 finish_reason="
                    f"{finish_reason} input_tokens={input_tokens} "
                    f"output_tokens={output_tokens}"
                )
                self._record_usage(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    case_id=case_id,
                    operation="classification",
                )
                return parsed
            except self._openai.APIStatusError as error:
                status = getattr(error, "status_code", None)
                last_error = error
                message = str(error)
                if (
                    status == 400
                    and not reasoning_fallback_used
                    and "reason" in message.lower()
                ):
                    kwargs["extra_body"] = {"reasoning": {"effort": "minimal"}}
                    reasoning_fallback_used = True
                    print("OPENROUTER status=400 reasoning_fallback=minimal")
                    continue
                print(f"OPENROUTER status={status} error=API failure")
                if status not in transient_statuses or attempt >= self._max_retries - 1:
                    break
                time.sleep(2 ** attempt)
            except (ValueError, json.JSONDecodeError) as error:
                last_error = error
                print("OPENROUTER status=invalid_response error=response_validation")
                if attempt >= self._max_retries - 1:
                    break
                time.sleep(2 ** attempt)
            except Exception as error:
                last_error = error
                print("OPENROUTER status=unknown error=client failure")
                break

        raise RuntimeError(
            f"OpenRouter request failed after {self._max_retries} attempts: "
            f"{last_error}"
        )


class GroqProvider(LLMProvider):
    """Groq provider for compact JSON classifications."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "qwen/qwen3.8-27b",
        max_retries: int = 3,
    ):
        self._model_name = model_name
        self._max_retries = max_retries
        self._api_key = api_key or os.environ.get("GROQ_API_KEY")
        if not self._api_key:
            raise ValueError("GROQ_API_KEY not set in environment")

        try:
            from groq import Groq
            self._groq = __import__("groq")
            self._client = Groq(api_key=self._api_key)
        except ImportError:
            raise ImportError("groq package not installed. Run: uv pip install groq")

    @property
    def provider_name(self) -> str:
        return "groq"

    @property
    def model_name(self) -> str:
        return self._model_name

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 256,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        kwargs = {
            "model": self._model_name,
            "messages": messages,
            "temperature": 0,
            "max_completion_tokens": min(max_tokens, 256),
            "reasoning_effort": "none",
            "reasoning_format": "hidden",
            "stream": False,
        }
        if response_format and response_format.get("type") == "json_object":
            kwargs["response_format"] = {"type": "json_object"}

        transient_statuses = {408, 429, 500, 502, 503, 504}
        last_error = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.chat.completions.create(**kwargs)
                choices = getattr(response, "choices", None)
                if not choices:
                    raise ValueError("Groq response did not contain choices")
                choice = choices[0]
                message = getattr(choice, "message", None)
                content = getattr(message, "content", None) if message else None
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("Groq response did not contain content")
                content = content.strip()

                if response_format and response_format.get("type") == "json_object":
                    parsed = json.loads(content)
                else:
                    parsed = {"text": content}

                usage = getattr(response, "usage", None)
                input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
                output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
                self._record_usage(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    case_id=case_id,
                    operation="classification",
                )
                return parsed
            except Exception as error:
                last_error = error
                status = getattr(error, "status_code", None)
                if status not in transient_statuses or attempt >= self._max_retries - 1:
                    break
                time.sleep(2 ** attempt)

        raise RuntimeError(
            f"Groq request failed after {self._max_retries} attempts: {last_error}"
        )


class GeminiProvider(LLMProvider):
    """Google Gen AI provider for compact Gemma JSON responses."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "gemma-4-31b-it",
        max_retries: int = 3,
    ):
        self._model_name = model_name
        self._max_retries = max_retries
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self._api_key:
            raise ValueError("GEMINI_API_KEY not set in environment")

        try:
            from google import genai
            from google.genai import types
            self._genai = genai
            self._types = types
            self._client = genai.Client(api_key=self._api_key)
        except ImportError:
            raise ImportError(
                "google-genai package not installed. "
                "Run: uv pip install --python .\\venv\\Scripts\\python.exe google-genai"
            )

    @property
    def provider_name(self) -> str:
        return "google"

    @property
    def model_name(self) -> str:
        return self._model_name

    def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        response_format: Optional[Dict] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        contents = prompt
        config = self._types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=temperature,
            max_output_tokens=min(max_tokens, 512),
            response_mime_type=(
                "application/json"
                if response_format and response_format.get("type") == "json_object"
                else None
            ),
            thinking_config=self._types.ThinkingConfig(thinking_level="minimal"),
            tools=None,
        )

        last_error = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.models.generate_content(
                    model=self._model_name,
                    contents=contents,
                    config=config,
                )
                text = (response.text or "").strip()
                if not text:
                    raise ValueError("Google Gen AI returned an empty response")

                if response_format and response_format.get("type") == "json_object":
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        import re
                        match = re.search(
                            r"```(?:json)?\s*(\{.*?\})\s*```",
                            text,
                            re.DOTALL,
                        )
                        if not match:
                            raise
                        parsed = json.loads(match.group(1))
                else:
                    parsed = {"text": text}

                usage = getattr(response, "usage_metadata", None)
                input_tokens = int(
                    getattr(usage, "prompt_token_count", 0) or 0
                )
                output_tokens = int(
                    getattr(usage, "candidates_token_count", 0) or 0
                )
                self._record_usage(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    case_id=case_id,
                    operation="classification",
                )
                return parsed
            except Exception as error:
                last_error = error
                if attempt < self._max_retries - 1:
                    time.sleep(2 ** attempt)

        raise RuntimeError(
            f"Google Gen AI request failed after {self._max_retries} attempts: "
            f"{last_error}"
        )


def create_provider(
    provider: str = "auto",
    model_name: Optional[str] = None,
    **kwargs
) -> LLMProvider:
    """
    Factory function to create an LLM provider.

    Args:
        provider: "anthropic", "openai", "google", "nvidia", "openrouter", "groq", "mock", or "auto"
        model_name: Specific model name
        **kwargs: Additional provider-specific arguments

    Returns:
        LLMProvider instance
    """
    if provider == "mock":
        return MockLLMProvider(model_name or "mock-model")

    if provider == "anthropic":
        return AnthropicProvider(model_name=model_name or "claude-sonnet-5-5", **kwargs)

    if provider == "openai":
        return OpenAIProvider(model_name=model_name or "gpt-4o", **kwargs)

    if provider == "nvidia":
        return NvidiaProvider(
            model_name=model_name or "nvidia/nemotron-3.5-lightning-30b-a3b",
            **kwargs,
        )

    if provider == "openrouter":
        return OpenRouterProvider(
            model_name=model_name or "google/gemma-4-26b-a4b-it:free",
            **kwargs,
        )

    if provider == "groq":
        return GroqProvider(
            model_name=model_name or "qwen/qwen3.8-27b",
            **kwargs,
        )

    if provider == "google":
        return GeminiProvider(model_name=model_name or "gemma-4-31b-it", **kwargs)

    if provider == "auto":
        if os.environ.get("GROQ_API_KEY"):
            return GroqProvider(
                model_name=model_name or "qwen/qwen3.8-27b",
                **kwargs,
            )
        if os.environ.get("OPENROUTER_API_KEY"):
            return OpenRouterProvider(
                model_name=model_name or "google/gemma-4-26b-a4b-it:free",
                **kwargs,
            )
        if os.environ.get("NVIDIA_API_KEY"):
            return NvidiaProvider(
                model_name=model_name or "nvidia/nemotron-3.5-lightning-30b-a3b",
                **kwargs,
            )
        if os.environ.get("GEMINI_API_KEY"):
            return GeminiProvider(model_name=model_name or "gemma-4-31b-it", **kwargs)
        if os.environ.get("ANTHROPIC_API_KEY"):
            return AnthropicProvider(model_name=model_name or "claude-sonnet-5-5", **kwargs)
        if os.environ.get("OPENAI_API_KEY"):
            return OpenAIProvider(model_name=model_name or "gpt-4o", **kwargs)
        raise RuntimeError(
            "No configured LLM API access. Set GROQ_API_KEY, OPENROUTER_API_KEY, "
            "NVIDIA_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY "
            "before running the final pipeline. Use provider='mock' only in unit tests."
        )

    raise ValueError(f"Unknown provider: {provider}")