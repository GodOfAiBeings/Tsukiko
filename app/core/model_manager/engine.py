"""Tsukiko Local AI Brain — Inference Engine Abstraction and Implementations.

Provides unified runtime abstraction for llama-cpp-python and a deterministic
test double engine for comprehensive testing without external model weights.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

# Regex to detect and strip internal thinking/reasoning blocks
THINKING_REGEX = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def filter_reasoning_tokens(text: str) -> str:
    """Strips any internal model reasoning tokens (<think>...</think>) before delivery to user."""
    return THINKING_REGEX.sub("", text).strip()


class BaseInferenceEngine(ABC):
    """Abstract interface for local text inference engines."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Name of the inference backend ('cpu', 'cuda', 'fake_test')."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Whether the runtime dependencies are installed and available."""
        pass

    @abstractmethod
    def get_runtime_version(self) -> str:
        """Returns the runtime library version string."""
        pass

    @abstractmethod
    def load(
        self,
        model_path: Path,
        context_window: int = 4096,
        gpu_layers: int = 0,
        threads: int = 6,
    ) -> None:
        """Loads model weights into memory/VRAM."""
        pass

    @abstractmethod
    def unload(self) -> None:
        """Unloads model weights and releases all memory."""
        pass

    @abstractmethod
    def is_loaded(self) -> bool:
        """Whether a model is actively loaded and ready for inference."""
        pass

    @abstractmethod
    def is_generating(self) -> bool:
        """Whether an inference request is actively in progress."""
        pass

    @abstractmethod
    def generate(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.9,
        repeat_penalty: float = 1.1,
    ) -> str:
        """Synchronously generates a complete text response."""
        pass

    @abstractmethod
    def stream_chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.9,
        repeat_penalty: float = 1.1,
    ) -> Iterator[str]:
        """Streams response tokens incrementally."""
        pass

    @abstractmethod
    def cancel(self) -> None:
        """Cancels an active generation request."""
        pass


class LlamaCppInferenceEngine(BaseInferenceEngine):
    """Production local inference engine using llama-cpp-python."""

    def __init__(self, preferred_backend: str = "auto") -> None:
        self._preferred_backend = preferred_backend
        self._llm: Optional[Any] = None
        self._is_generating = False
        self._cancelled = False
        self._lock = threading.RLock()
        self._active_backend = "cpu"

    @property
    def backend_name(self) -> str:
        return self._active_backend

    def is_available(self) -> bool:
        try:
            import llama_cpp  # type: ignore # noqa: F401
            return True
        except (ImportError, Exception):
            return False

    def get_runtime_version(self) -> str:
        try:
            import llama_cpp  # type: ignore
            return getattr(llama_cpp, "__version__", "installed")
        except Exception:
            return "not_installed"

    def _unload_locked(self) -> None:
        """Internal helper to deallocate model while holding self._lock."""
        if self._llm is not None:
            logger.info("Unloading llama-cpp-python model and releasing memory...")
            try:
                del self._llm
            except Exception as e:
                logger.warning(f"Error during llama-cpp-python deallocation: {e}")
            self._llm = None
            import gc
            gc.collect()

    def load(
        self,
        model_path: Path,
        context_window: int = 4096,
        gpu_layers: int = 0,
        threads: int = 6,
    ) -> None:
        with self._lock:
            if self._llm is not None:
                self._unload_locked()

            try:
                import llama_cpp  # type: ignore
            except ImportError as e:
                raise RuntimeError(
                    "llama-cpp-python is not installed in the active Python environment. "
                    "Install via 'pip install -r requirements/ai.txt'."
                ) from e

            # Verify GPU capability
            has_gpu_offload = False
            if hasattr(llama_cpp, "llama_supports_gpu_offload"):
                has_gpu_offload = bool(llama_cpp.llama_supports_gpu_offload())

            effective_gpu_layers = gpu_layers
            if not has_gpu_offload or self._preferred_backend == "cpu":
                effective_gpu_layers = 0
                self._active_backend = "cpu"
            else:
                self._active_backend = "cuda" if effective_gpu_layers > 0 else "cpu"

            logger.info(
                f"Loading GGUF model via llama-cpp-python: {model_path.name} "
                f"(ctx={context_window}, gpu_layers={effective_gpu_layers}, threads={threads}, backend={self._active_backend})"
            )

            try:
                self._llm = llama_cpp.Llama(
                    model_path=str(model_path.resolve()),
                    n_ctx=context_window,
                    n_gpu_layers=effective_gpu_layers,
                    n_threads=threads,
                    verbose=False,
                )
            except Exception as e:
                self._llm = None
                self._active_backend = "cpu"
                raise RuntimeError(f"Failed to initialize llama.cpp model: {e}") from e

    def unload(self) -> None:
        with self._lock:
            self._unload_locked()

    def is_loaded(self) -> bool:
        return self._llm is not None

    def is_generating(self) -> bool:
        return self._is_generating

    def cancel(self) -> None:
        self._cancelled = True

    def generate(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.9,
        repeat_penalty: float = 1.1,
    ) -> str:
        tokens: List[str] = []
        for chunk in self.stream_chat(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            repeat_penalty=repeat_penalty,
        ):
            tokens.append(chunk)
        return "".join(tokens)

    def stream_chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.9,
        repeat_penalty: float = 1.1,
    ) -> Iterator[str]:
        if self._llm is None:
            raise RuntimeError("Cannot generate: Model is not loaded.")
        if self._is_generating:
            raise RuntimeError("Concurrent generation requests are forbidden.")

        self._is_generating = True
        self._cancelled = False
        in_thinking_block = False

        try:
            response = self._llm.create_chat_completion(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                repeat_penalty=repeat_penalty,
                stream=True,
            )

            for chunk in response:
                if self._cancelled:
                    logger.info("Generation cancelled by user.")
                    break

                choices = chunk.get("choices", [])
                if not choices:
                    continue
                delta = choices[0].get("delta", {})
                content = delta.get("content", "")
                if not content:
                    continue

                # Filter out internal reasoning / thinking tokens
                if "<think>" in content:
                    in_thinking_block = True
                    parts = content.split("<think>", 1)
                    if parts[0]:
                        yield parts[0]
                    content = parts[1] if len(parts) > 1 else ""

                if in_thinking_block:
                    if "</think>" in content:
                        in_thinking_block = False
                        parts = content.split("</think>", 1)
                        if len(parts) > 1 and parts[1]:
                            yield parts[1]
                    continue

                yield content
        finally:
            self._is_generating = False
            self._cancelled = False


class DeterministicFakeEngine(BaseInferenceEngine):
    """Deterministic test double engine for automated unit tests and CI.
    
    EXPLICIT DISCLAIMER:
    This is a test double used strictly for headless CI verification and automated testing.
    It is NOT actual AI inference and produces pre-configured deterministic responses.
    """

    def __init__(self, canned_response: Optional[str] = None) -> None:
        self._canned_response = canned_response or (
            "I am Tsukiko, your offline desktop companion. "
            "I operate completely local and respect your privacy."
        )
        self._is_loaded = False
        self._is_generating = False
        self._cancelled = False
        self._lock = threading.RLock()
        self.load_call_count = 0
        self.unload_call_count = 0
        self.last_loaded_path: Optional[Path] = None
        self.token_delay_seconds = 0.0
        self.fail_on_load = False
        self.fail_on_generate = False

    @property
    def backend_name(self) -> str:
        return "fake_test"

    def is_available(self) -> bool:
        return True

    def get_runtime_version(self) -> str:
        return "test-double-0.1.0"

    def set_canned_response(self, text: str) -> None:
        self._canned_response = text

    def load(
        self,
        model_path: Path,
        context_window: int = 4096,
        gpu_layers: int = 0,
        threads: int = 6,
    ) -> None:
        with self._lock:
            if self.fail_on_load:
                raise RuntimeError("Simulated model load failure for testing.")
            if self._is_loaded:
                self.unload()
            self.load_call_count += 1
            self.last_loaded_path = model_path
            self._is_loaded = True

    def unload(self) -> None:
        with self._lock:
            self.unload_call_count += 1
            self._is_loaded = False
            self.last_loaded_path = None

    def is_loaded(self) -> bool:
        return self._is_loaded

    def is_generating(self) -> bool:
        return self._is_generating

    def cancel(self) -> None:
        self._cancelled = True

    def generate(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.9,
        repeat_penalty: float = 1.1,
    ) -> str:
        tokens: List[str] = []
        for chunk in self.stream_chat(messages, max_tokens, temperature, top_p, repeat_penalty):
            tokens.append(chunk)
        return "".join(tokens)

    def stream_chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.7,
        top_p: float = 0.9,
        repeat_penalty: float = 1.1,
    ) -> Iterator[str]:
        if not self._is_loaded:
            raise RuntimeError("Cannot generate: Model is not loaded.")
        if self._is_generating:
            raise RuntimeError("Concurrent generation requests are forbidden.")
        if self.fail_on_generate:
            raise RuntimeError("Simulated generation failure for testing.")

        self._is_generating = True
        self._cancelled = False

        try:
            # Tokenize into words + whitespace chunks
            chunks = re.findall(r"\S+\s*|\s+", self._canned_response)
            for chunk in chunks:
                if self._cancelled:
                    logger.info("Fake generation cancelled by test request.")
                    break
                if self.token_delay_seconds > 0:
                    time.sleep(self.token_delay_seconds)
                yield chunk
        finally:
            self._is_generating = False
            self._cancelled = False
