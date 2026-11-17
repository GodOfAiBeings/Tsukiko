"""Tsukiko Local AI Brain — Brain Orchestrator.

Integrates the model lifecycle manager, personality directives,
in-memory session context pruning, and streaming inference execution.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Iterator, List, Optional

from app.core.config.settings import TsukikoConfig, get_config
from app.core.logging.logger import get_logger
from app.core.model_manager.engine import BaseInferenceEngine
from app.core.model_manager.lifecycle import ModelInfo, ModelLifecycleState
from app.core.model_manager.manager import ModelManager
from app.core.personality.engine import PersonalityEngine

logger = get_logger("BRAIN")


def estimate_tokens(text: str) -> int:
    """Heuristic token estimator (approx. 3.8 chars per token for English/code)."""
    return max(1, int(len(text) / 3.8))


class TsukikoBrain:
    """Central conversational intelligence orchestrator for Tsukiko."""

    def __init__(
        self,
        config: Optional[TsukikoConfig] = None,
        model_manager: Optional[ModelManager] = None,
        engine: Optional[BaseInferenceEngine] = None,
    ) -> None:
        self.config = config or get_config()
        self.model_manager = model_manager or ModelManager(config=self.config, engine=engine)
        self.personality = PersonalityEngine(custom_system_prompt=self.config.ai.system_prompt)
        self._history: List[Dict[str, str]] = []
        self._lock = threading.RLock()
        self._is_initialized = False

    def initialize(self) -> None:
        """Initializes brain state and inspects configured model."""
        with self._lock:
            if self._is_initialized:
                return
            logger.info("Initializing Tsukiko Local AI Brain...")
            self.model_manager.inspect_configured_model()
            self._is_initialized = True
            logger.info(
                f"Tsukiko Local AI Brain initialized. Model state: {self.model_manager.state.value}"
            )

    def load_model(self, force: bool = False) -> bool:
        """Explicitly loads the configured model into memory/VRAM."""
        return self.model_manager.load_model(force=force)

    def unload_model(self) -> bool:
        """Explicitly unloads the model from memory/VRAM."""
        return self.model_manager.unload_model()

    def get_history(self) -> List[Dict[str, str]]:
        """Returns a snapshot of current session in-memory conversation history."""
        with self._lock:
            return [dict(m) for m in self._history]

    def clear_conversation(self) -> None:
        """Clears temporary in-memory conversation history for this session."""
        with self._lock:
            self._history.clear()
            logger.info("In-memory conversation history cleared.")

    def _prune_history_to_fit_context(
        self,
        new_prompt: str,
        reserve_tokens_for_generation: int = 1024,
    ) -> List[Dict[str, str]]:
        """Prunes oldest conversation turns to prevent exceeding context window.
        
        Strict Phase 3 Rule: Maintains temporary in-memory context within limits
        without persisting to SQLite or files.
        """
        max_ctx = self.model_manager.info.context_window
        available_history_budget = max(512, max_ctx - reserve_tokens_for_generation)

        system_tokens = estimate_tokens(self.personality.get_system_prompt())
        prompt_tokens = estimate_tokens(new_prompt)
        remaining_budget = available_history_budget - (system_tokens + prompt_tokens)

        if remaining_budget <= 0:
            logger.warning("Prompt and system directive consume entire context window; truncating history.")
            return []

        # Iterate from newest to oldest turns to select what fits
        pruned_reversed: List[Dict[str, str]] = []
        current_tokens = 0

        for msg in reversed(self._history):
            t = estimate_tokens(msg.get("content", ""))
            if current_tokens + t > remaining_budget:
                break
            pruned_reversed.append(msg)
            current_tokens += t

        pruned = list(reversed(pruned_reversed))
        return pruned

    def generate_response(
        self,
        user_message: str,
        max_tokens: int = 1024,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        repeat_penalty: Optional[float] = None,
    ) -> str:
        """Generates a complete response synchronously."""
        tokens: List[str] = []
        for chunk in self.stream_response(
            user_message=user_message,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            repeat_penalty=repeat_penalty,
        ):
            tokens.append(chunk)
        return "".join(tokens)

    def stream_response(
        self,
        user_message: str,
        max_tokens: int = 1024,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        repeat_penalty: Optional[float] = None,
    ) -> Iterator[str]:
        """Streams response tokens incrementally, updating active session history upon completion."""
        clean_user = user_message.strip()
        if not clean_user:
            return

        with self._lock:
            pruned_history = self._prune_history_to_fit_context(
                clean_user,
                reserve_tokens_for_generation=max_tokens,
            )
            messages = self.personality.format_messages(pruned_history, clean_user)

        accumulated_chunks: List[str] = []

        try:
            for chunk in self.model_manager.stream(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                repeat_penalty=repeat_penalty,
            ):
                accumulated_chunks.append(chunk)
                yield chunk
        finally:
            full_response = "".join(accumulated_chunks).strip()
            if full_response:
                # Clean response (strip any internal reasoning tokens)
                clean_response = self.personality.clean_response(full_response)
                with self._lock:
                    self._history.append({"role": "user", "content": clean_user})
                    self._history.append({"role": "assistant", "content": clean_response})
                    logger.debug(
                        f"Turn appended to session history. Current turns: {len(self._history)}"
                    )

    def cancel_generation(self) -> None:
        """Cancels any running generation."""
        self.model_manager.cancel_generation()

    def get_brain_status(self) -> Dict[str, Any]:
        """Returns comprehensive real-time status of the local AI brain."""
        with self._lock:
            info = self.model_manager.info
            return {
                "state": info.state.value,
                "is_loaded": info.is_loaded,
                "is_generating": info.state == ModelLifecycleState.GENERATING,
                "model_name": info.model_name,
                "model_path": str(info.path) if info.path else None,
                "architecture": info.architecture,
                "quantization": info.quantization,
                "file_size_mb": info.file_size_mb,
                "context_window": info.context_window,
                "backend": info.backend,
                "gpu_layers": info.gpu_layers_offloaded,
                "runtime_version": info.runtime_version,
                "session_turns": len(self._history),
                "error_message": info.error_message,
                "estimated_vram_mb": info.estimated_vram_mb,
                "estimated_ram_mb": info.estimated_ram_mb,
            }

    def shutdown(self) -> None:
        """Releases model weights, stops background timers, and clears session history."""
        with self._lock:
            logger.info("Shutting down Tsukiko Local AI Brain...")
            self.model_manager.shutdown()
            self.clear_conversation()
            self._is_initialized = False
            logger.info("Tsukiko Local AI Brain stopped cleanly.")
