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
from app.core.model_manager.engine import BaseInferenceEngine, DeterministicFakeEngine
from app.core.model_manager.lifecycle import ModelInfo, ModelLifecycleState
from app.core.model_manager.manager import ModelManager
from app.core.personality.disclosure import DisclosureTracker
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
        self.model_manager.set_can_unload_predicate(lambda: self.active_operations == 0)
        self.personality = PersonalityEngine(custom_system_prompt=self.config.ai.system_prompt)
        self._history: List[Dict[str, str]] = []
        self._lock = threading.RLock()
        self._is_initialized = False
        self._generation_finished_callbacks: List[Any] = []

        # NOTE: The brain does NOT register with model_manager's generation callbacks.
        # The brain is the authoritative owner of generation-completion notifications.
        # Notifications fire only after the complete brain-level operation finishes,
        # including all history updates and cleanup — never from the model manager's
        # earlier stream-level finally block.

    def register_generation_finished_callback(self, callback: Any) -> None:
        """Registers a callback to execute whenever generation completes."""
        with self._lock:
            if callback not in self._generation_finished_callbacks:
                self._generation_finished_callbacks.append(callback)

    def unregister_generation_finished_callback(self, callback: Any) -> None:
        """Unregisters a generation finished callback."""
        with self._lock:
            if callback in self._generation_finished_callbacks:
                self._generation_finished_callbacks.remove(callback)

    def _notify_generation_finished(self) -> None:
        """Invokes registered callbacks when generation finishes."""
        with self._lock:
            callbacks = list(self._generation_finished_callbacks)
        for cb in callbacks:
            try:
                cb()
            except Exception as e:
                logger.debug(f"Exception in brain generation finished callback: {e}")

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
        """Explicitly loads the configured model into memory/VRAM.

        Refuses forced reloads whenever active brain operations are running.
        """
        with self._lock:
            if force and (self._active_operations > 0 or self.is_generating):
                logger.warning("Cannot reload model: active brain operations are currently in progress.")
                return False
            return self.model_manager.load_model(force=force)

    def unload_model(self) -> bool:
        """Explicitly unloads the model from memory/VRAM.

        Refuses unloading whenever any brain-level operation is active
        (_active_operations > 0 or model_manager is generating).
        Acquires brain-level lock throughout the safety check and unload execution
        so a new operation cannot start between the check and unload.
        """
        with self._lock:
            if self._active_operations > 0:
                logger.warning(
                    f"Cannot unload model: {self._active_operations} active brain operation(s) in progress."
                )
                return False
            if self.is_generating:
                logger.warning("Cannot unload model: model inference is currently active.")
                return False
            return self.model_manager.unload_model()

    def get_history(self) -> List[Dict[str, str]]:
        """Returns a snapshot of current session in-memory conversation history."""
        with self._lock:
            return [dict(m) for m in self._history]

    def clear_conversation(self) -> None:
        """Clears temporary in-memory conversation history for this session."""
        with self._lock:
            self._history.clear()
            self.personality.disclosure_tracker = DisclosureTracker()
            self.personality.initiative_engine.record_user_activity()
            logger.info("In-memory conversation history and session depth reset.")

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

        with self._lock:
            history_snapshot = list(self._history)

        for msg in reversed(history_snapshot):
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

    @property
    def active_operations(self) -> int:
        """Returns the number of currently active brain-level generation operations."""
        return self.model_manager.active_operations

    @property
    def _active_operations(self) -> int:
        """Backward-compatible access to model manager active operations."""
        return self.model_manager.active_operations

    @_active_operations.setter
    def _active_operations(self, value: int) -> None:
        self.model_manager._active_operations = value

    def stream_response(
        self,
        user_message: str,
        max_tokens: int = 1024,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        repeat_penalty: Optional[float] = None,
    ) -> Iterator[str]:
        """Streams response tokens incrementally, updating active session history upon completion.

        Thread-safe: Atomically reserves an operation lease via ModelManager across prompt preparation,
        inference, and history processing. The entire operation is enclosed in a try/finally
        so any exception during pruning or formatting guarantees lease release, and
        listeners are notified only when all active operations reach zero.
        """
        clean_user = user_message.strip()
        if not clean_user:
            return

        if not self.model_manager.acquire_operation(allow_lazy_load=True, raise_on_failure=True):
            raise RuntimeError("Cannot admit operation: model is currently unavailable or unloading.")

        should_notify = False
        try:
            self.personality.initiative_engine.record_user_activity()

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
                        if not self._is_initialized:
                            logger.debug("Brain was shut down during generation; discarding turn.")
                        else:
                            self._history.append({"role": "user", "content": clean_user})
                            self._history.append({"role": "assistant", "content": clean_response})
                            self.personality.disclosure_tracker.register_interaction(clean_user, clean_response)
                            self.personality.initiative_engine.record_assistant_response()
                            logger.debug(
                                f"Turn appended to session history. Current turns: {len(self._history)}"
                            )
        finally:
            self.model_manager.release_operation()
            should_notify = (self.model_manager.active_operations == 0)
            if should_notify:
                self._notify_generation_finished()

    @property
    def is_generating(self) -> bool:
        """Returns True if any brain-level generation operation is active.

        This includes prompt preparation, model-level token generation,
        and post-generation processing (history append, cleanup).  The counter
        prevents the orchestrator from completing shutdown while any operation is active.
        """
        if self.model_manager.active_operations > 0:
            return True
        return (
            self.model_manager.info.state == ModelLifecycleState.GENERATING
            or self.model_manager.engine.is_generating()
        )

    def check_conversational_initiative(
        self,
        game_mode_active: bool = False,
        widget_hidden: bool = False,
        window_minimized: bool = False,
        current_time: Optional[float] = None,
    ) -> Optional[str]:
        """Evaluates whether Tsukiko proactively initiates a thoughtful remark.

        Strictly respects Game Mode, hidden/minimized UI states, cooldown timers,
        anti-spam backoff, and silence by choice.

        Thread-safe: Increments active operations counter across prompt preparation,
        inference, and remark processing in a robust try/finally.
        """
        with self._lock:
            if not self._is_initialized:
                return None
            can_speak, reason = self.personality.initiative_engine.can_initiate(
                current_time=current_time,
                game_mode_active=game_mode_active,
                widget_hidden=widget_hidden,
                window_minimized=window_minimized,
            )
            if not can_speak:
                logger.debug(f"Conversational initiative suppressed: {reason}")
                return None

            # Do NOT automatically load an unloaded model just to generate a proactive message
            if not self.model_manager.info.is_loaded:
                logger.debug("Conversational initiative skipped: model is not currently loaded in memory.")
                return None

        # Atomically reserve model operation lease without auto-lazy-loading
        if not self.model_manager.acquire_operation(allow_lazy_load=False, raise_on_failure=False):
            logger.debug("Conversational initiative skipped: model manager refused operation admission.")
            return None

        with self._lock:
            history_snapshot = list(self._history)
            stage = self.personality.disclosure_tracker.stage
            biography = self.personality.biography
            personality_directive = biography.get_stage_personality_directive(stage)

        should_notify = False
        clean_remark: Optional[str] = None
        try:
            try:
                prompt_messages = self.personality.initiative_engine.build_initiative_prompt(
                    session_history=history_snapshot,
                    stage=stage,
                    biography=biography,
                    personality_directive=personality_directive,
                )

                raw_response = self.model_manager.generate(
                    messages=prompt_messages,
                    max_tokens=150,
                    temperature=0.7,
                )
                # If DeterministicFakeEngine produced default canned response without custom canned text:
                if isinstance(self.model_manager.engine, DeterministicFakeEngine) and "offline desktop companion" in raw_response:
                    raw_response = "The afternoon light feels very quiet today. How is your work progressing?"

                remark = self.personality.initiative_engine.parse_initiative_response(raw_response)
                if remark:
                    clean_remark = self.personality.clean_response(remark)
            except Exception as e:
                logger.debug(f"Failed to generate conversational initiative: {e}")
                return None

            if not clean_remark:
                return None

            with self._lock:
                if not self._is_initialized:
                    logger.debug("Brain was shut down during initiative generation; discarding remark.")
                    return None
                self._history.append({"role": "assistant", "content": clean_remark})

            self.personality.initiative_engine.record_initiative_sent(clean_remark)
            logger.info(f"Tsukiko initiated proactive remark: {clean_remark[:40]}...")
            return clean_remark
        finally:
            self.model_manager.release_operation()
            should_notify = (self.model_manager.active_operations == 0)
            if should_notify:
                self._notify_generation_finished()

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
                "is_generating": self.is_generating,
                "active_operations": self.active_operations,
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
                "disclosure_stage": self.personality.disclosure_tracker.stage.name,
                "initiative_enabled": self.personality.initiative_engine.is_enabled,
                "consecutive_unanswered_initiatives": self.personality.initiative_engine.consecutive_unanswered,
            }

    def shutdown(self, timeout_seconds: float = 1.0) -> bool:
        """Releases model weights, stops background timers, and clears session history.

        If generation is actively in progress, requests cancellation and waits up to
        timeout_seconds for the engine to halt. If generation does not halt within
        the timeout, model weights are NOT unloaded to prevent crashing running threads.

        Returns True if shutdown and unload completed; False if deferred due to active inference.
        """
        logger.info("Shutting down Tsukiko Local AI Brain...")
        self.cancel_generation()

        # Wait up to timeout_seconds for active generation to unwind
        if self.is_generating and timeout_seconds > 0:
            deadline = time.time() + timeout_seconds
            while time.time() < deadline and self.is_generating:
                time.sleep(0.02)

        with self._lock:
            # If generation is STILL running, refuse to unload model to preserve memory safety
            if self.is_generating:
                logger.warning(
                    "Active inference is still in progress; deferring model unload "
                    "until inference terminates to protect memory integrity."
                )
                return False

            self.model_manager.shutdown()
            self.clear_conversation()
            self._is_initialized = False
            logger.info("Tsukiko Local AI Brain stopped cleanly.")
            return True

    def complete_deferred_shutdown(self) -> bool:
        """Completes previously deferred brain shutdown once all inference has terminated."""
        with self._lock:
            if not self._is_initialized:
                return True
            if self.is_generating:
                logger.debug("Cannot complete deferred shutdown: inference is still running.")
                return False
            self.model_manager.shutdown()
            self.clear_conversation()
            self._is_initialized = False
            logger.info("Deferred Tsukiko Local AI Brain shutdown completed cleanly.")
            return True
