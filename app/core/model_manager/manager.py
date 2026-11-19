"""Tsukiko Local AI Brain — Model Manager.

Coordinates model validation, memory and VRAM budget verification,
safe GPU offloading, lazy loading, inactivity timeouts, and lifecycle states.
"""

from __future__ import annotations

from contextlib import contextmanager
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Union

from app.core.config.settings import AIConfig, TsukikoConfig, get_config
from app.core.logging.logger import get_logger
from app.core.model_manager.engine import (
    BaseInferenceEngine,
    DeterministicFakeEngine,
    LlamaCppInferenceEngine,
    filter_reasoning_tokens,
)
from app.core.model_manager.gguf_parser import (
    GGUFMetadata,
    GGUFValidationError,
    inspect_gguf_file,
)
from app.core.model_manager.lifecycle import ModelInfo, ModelLifecycleState
from app.core.resource_manager.hardware import (
    HardwareInspector,
    HardwareProfile,
    ModelMemoryEstimate,
)

logger = get_logger("MODEL_MGR")


class InsufficientMemoryError(RuntimeError):
    """Raised when available system RAM or VRAM cannot safely fit the model."""
    pass


class ModelManager:
    """Manages local LLM lifecycle, validation, hardware budgeting, and inference."""

    def __init__(
        self,
        config: Optional[TsukikoConfig] = None,
        engine: Optional[BaseInferenceEngine] = None,
    ) -> None:
        self._config = config or get_config()
        self._ai_config: AIConfig = self._config.ai
        self._engine = engine or LlamaCppInferenceEngine(preferred_backend=self._ai_config.backend)
        self._lock = threading.RLock()
        self._inactivity_timer: Optional[threading.Timer] = None
        self._last_activity = time.time()
        self._metadata: Optional[GGUFMetadata] = None

        self._info = ModelInfo(
            state=ModelLifecycleState.NOT_CONFIGURED,
            context_window=self._ai_config.context_window,
        )
        self._generation_finished_callbacks: List[Any] = []
        self._can_unload_predicate: Optional[Any] = None
        self._active_operations: int = 0

        # Initial inspection of configured model path
        self.inspect_configured_model()

    def set_can_unload_predicate(self, predicate: Optional[Any]) -> None:
        """Registers a predicate to verify whether external systems permit model unloading."""
        with self._lock:
            self._can_unload_predicate = predicate

    @property
    def active_operations(self) -> int:
        """Returns the number of active operations currently holding a lease on the model."""
        return self._active_operations

    def acquire_operation(
        self,
        allow_lazy_load: bool = True,
        raise_on_failure: bool = True,
    ) -> bool:
        """Atomically reserves model access across prompt prep, inference, and post-processing.

        Guarantees that while an operation holds this reservation:
        1. Model cannot be auto-unloaded by inactivity timers.
        2. Unload requests (forced or normal) are rejected while inference or active operations run.
        3. Model cannot be reloaded (force=True) while active operations run.
        4. Model cannot be unloaded while unloading transition is active.
        """
        with self._lock:
            if self._info.state == ModelLifecycleState.UNLOADING:
                if raise_on_failure:
                    raise RuntimeError("Cannot start operation: model is currently unloading.")
                return False

            if self._info.state in (
                ModelLifecycleState.NOT_CONFIGURED,
                ModelLifecycleState.NOT_INSTALLED,
                ModelLifecycleState.ERROR,
            ):
                if raise_on_failure:
                    raise RuntimeError(f"Cannot start operation: model state is {self._info.state.value}.")
                return False

            if not self._info.is_loaded:
                if allow_lazy_load and self._ai_config.lazy_load and self._info.is_ready_or_loaded:
                    loaded = self.load_model()
                    if not loaded:
                        if raise_on_failure:
                            raise RuntimeError(f"Lazy model load failed: {self._info.error_message}")
                        return False
                else:
                    if raise_on_failure:
                        raise RuntimeError("Model is not loaded. Call load_model() first.")
                    return False

            self._active_operations += 1
            self._touch_activity()
            self._cancel_inactivity_timer()
            return True

    def release_operation(self) -> None:
        """Releases an operation reservation on the model."""
        should_notify = False
        with self._lock:
            self._active_operations = max(0, self._active_operations - 1)
            if self._active_operations == 0 and self._info.state != ModelLifecycleState.GENERATING:
                self._schedule_inactivity_timer()
                should_notify = True
        if should_notify:
            self._notify_generation_finished()

    @contextmanager
    def reserve_operation(
        self,
        allow_lazy_load: bool = True,
        raise_on_failure: bool = True,
    ) -> Iterator[bool]:
        """Context manager for atomically reserving model access across an operation."""
        admitted = self.acquire_operation(
            allow_lazy_load=allow_lazy_load,
            raise_on_failure=raise_on_failure,
        )
        try:
            yield admitted
        finally:
            if admitted:
                self.release_operation()

    @property
    def info(self) -> ModelInfo:
        with self._lock:
            return self._info.model_copy()

    @property
    def state(self) -> ModelLifecycleState:
        with self._lock:
            return self._info.state

    @property
    def engine(self) -> BaseInferenceEngine:
        return self._engine

    def set_engine(self, engine: BaseInferenceEngine) -> None:
        """Injects custom inference engine (e.g. for testing)."""
        with self._lock:
            if self._info.is_loaded:
                self.unload_model()
            self._engine = engine
            self._info.backend = engine.backend_name

    def inspect_configured_model(self) -> ModelInfo:
        """Inspects and validates the currently configured model path."""
        with self._lock:
            model_path_str = self._ai_config.model_path
            if not model_path_str or not str(model_path_str).strip():
                self._info.state = ModelLifecycleState.NOT_CONFIGURED
                self._info.error_message = None
                self._info.model_name = "None"
                self._info.path = None
                return self.info

            path = Path(model_path_str).resolve()
            self._info.path = path

            if not path.exists():
                self._info.state = ModelLifecycleState.NOT_INSTALLED
                self._info.error_message = f"Model file not found: {path.name}"
                self._info.model_name = path.stem
                return self.info

            self._info.state = ModelLifecycleState.VALIDATING
            try:
                metadata = inspect_gguf_file(path)
                self._metadata = metadata
                self._info.model_name = metadata.model_name
                self._info.architecture = metadata.architecture
                self._info.quantization = metadata.quantization
                self._info.file_size_mb = metadata.file_size_mb
                self._info.context_window = min(self._ai_config.context_window, metadata.context_length)
                self._info.block_count = metadata.block_count
                self._info.state = ModelLifecycleState.READY
                self._info.error_message = None
                self._info.runtime_version = self._engine.get_runtime_version()
                logger.info(
                    f"Model validated successfully: {metadata.model_name} "
                    f"({metadata.quantization}, {metadata.file_size_mb} MB, {metadata.block_count} layers)"
                )
            except (GGUFValidationError, Exception) as e:
                self._info.state = ModelLifecycleState.ERROR
                self._info.error_message = f"GGUF validation failed: {e}"
                logger.warning(f"GGUF validation failed for {path.name}: {e}")

            return self.info

    def calculate_offload_strategy(
        self,
        hardware: Optional[HardwareProfile] = None,
    ) -> Dict[str, Any]:
        """Calculates safe GPU offload layers and memory allocations.

        Strictly enforces:
        1. Configured RAM ceiling (max_ram_mb, default 3500 MB).
        2. Available system RAM and safety headroom (minimum 500 MB margin).
        3. Configured safe VRAM ceiling (max_vram_mb, default 2800 MB) with >= 400 MB headroom.
        4. Explicit gpu_layers overrides MUST NEVER bypass the safe VRAM budget.
        5. Consistent memory estimation across CPU, Hybrid, and GPU modes.
        """
        profile = hardware or HardwareInspector.inspect()
        file_size_mb = self._info.file_size_mb
        ctx = self._info.context_window
        total_layers = self._info.block_count or 28

        mb_per_layer = max(1.0, file_size_mb / max(1, total_layers))
        kv_cache_mb = int((ctx / 4096.0) * 450)
        runtime_overhead_mb = 400

        # Safe VRAM Budget (honors profile headroom and configured max)
        safe_vram_budget = min(self._ai_config.max_vram_mb, profile.recommended_max_vram_mb)
        cuda_supported = (
            profile.frameworks.llama_cpp_cuda_supported or isinstance(self._engine, DeterministicFakeEngine)
        )

        # Calculate max safe GPU layers that can physically fit within safe VRAM
        if self._ai_config.backend == "cpu" or not cuda_supported or safe_vram_budget <= 0:
            max_safe_gpu_layers = 0
        else:
            usable_vram = max(0, safe_vram_budget - kv_cache_mb - runtime_overhead_mb)
            max_safe_gpu_layers = min(total_layers, int(usable_vram / mb_per_layer))

        # Determine effective GPU layers
        # Explicit configured gpu_layers MUST NEVER bypass safe VRAM!
        if self._ai_config.backend == "cpu" or not cuda_supported or safe_vram_budget <= 0:
            gpu_layers = 0
        elif self._ai_config.gpu_layers > 0:
            # Clamp user override to the safe maximum
            gpu_layers = min(self._ai_config.gpu_layers, max_safe_gpu_layers)
        elif self._ai_config.gpu_layers == -1:
            gpu_layers = max_safe_gpu_layers
        else:
            # Default auto: use max safe layers
            gpu_layers = max_safe_gpu_layers

        backend = "cuda" if gpu_layers > 0 else "cpu"

        # Harmonized Footprint Estimation
        if gpu_layers > 0:
            gpu_weight_mb = int((gpu_layers / max(1, total_layers)) * file_size_mb)
            estimated_vram_mb = gpu_weight_mb + kv_cache_mb + runtime_overhead_mb
        else:
            estimated_vram_mb = 0

        cpu_layers = max(0, total_layers - gpu_layers)
        cpu_weight_mb = int((cpu_layers / max(1, total_layers)) * file_size_mb)
        estimated_ram_mb = cpu_weight_mb + (kv_cache_mb if gpu_layers == 0 else 0) + runtime_overhead_mb

        # Enforce RAM Limits & System Safety Headroom
        configured_ram_ceiling = self._ai_config.max_ram_mb
        available_ram = profile.memory.available_ram_mb
        min_system_headroom = 500

        # Check 1: Configured RAM Ceiling (3500 MB)
        if estimated_ram_mb > configured_ram_ceiling:
            return {
                "safe_to_load": False,
                "reason": (
                    f"Estimated RAM footprint ({estimated_ram_mb} MB) exceeds configured RAM limit "
                    f"({configured_ram_ceiling} MB). Reduce model size or context window."
                ),
                "gpu_layers": 0,
                "backend": backend,
                "safe_vram_budget_mb": safe_vram_budget,
                "estimated_vram_mb": estimated_vram_mb,
                "estimated_ram_mb": estimated_ram_mb,
            }

        # Check 2: Available System RAM & Safety Headroom
        if available_ram - estimated_ram_mb < min_system_headroom:
            return {
                "safe_to_load": False,
                "reason": (
                    f"Insufficient system RAM headroom: Available RAM ({available_ram} MB) cannot "
                    f"safely accommodate estimated model RAM ({estimated_ram_mb} MB) with required "
                    f"{min_system_headroom} MB system safety margin."
                ),
                "gpu_layers": 0,
                "backend": backend,
                "safe_vram_budget_mb": safe_vram_budget,
                "estimated_vram_mb": estimated_vram_mb,
                "estimated_ram_mb": estimated_ram_mb,
            }

        return {
            "safe_to_load": True,
            "gpu_layers": gpu_layers,
            "backend": backend,
            "safe_vram_budget_mb": safe_vram_budget,
            "estimated_vram_mb": estimated_vram_mb,
            "estimated_ram_mb": estimated_ram_mb,
            "reason": (
                f"Safe allocation approved: {gpu_layers}/{total_layers} layers on GPU "
                f"({estimated_vram_mb} MB VRAM), {cpu_layers} layers on CPU ({estimated_ram_mb} MB RAM)."
            ),
        }

    def load_model(self, force: bool = False) -> bool:
        """Loads the model into memory/VRAM according to safe hardware constraints."""
        with self._lock:
            if self._info.is_loaded and not force:
                logger.debug("Model is already loaded.")
                return True

            if self._info.state == ModelLifecycleState.GENERATING or self._engine.is_generating():
                logger.warning("Cannot load or reload model while generation is active.")
                return False

            if force and self._active_operations > 0:
                logger.warning(
                    f"Cannot reload model: {self._active_operations} active operation(s) currently in progress."
                )
                return False

            if self._info.state == ModelLifecycleState.UNLOADING:
                logger.warning("Cannot load model while model is currently unloading.")
                return False

            if self._info.state in (ModelLifecycleState.NOT_CONFIGURED, ModelLifecycleState.NOT_INSTALLED):
                logger.warning(f"Cannot load model: state is {self._info.state}")
                return False

            if not self._info.path:
                return False

            # Inspect if not validated yet
            if self._info.state != ModelLifecycleState.READY:
                self.inspect_configured_model()
                if self._info.state != ModelLifecycleState.READY:
                    logger.warning(f"Model validation failed before load: {self._info.error_message}")
                    return False

            offload = self.calculate_offload_strategy()
            if not offload.get("safe_to_load", False):
                self._info.state = ModelLifecycleState.ERROR
                self._info.error_message = offload.get("reason", "Insufficient memory to load model.")
                logger.error(f"Model load rejected: {self._info.error_message}")
                return False

            self._info.state = ModelLifecycleState.LOADING
            gpu_layers = offload["gpu_layers"]
            backend = offload["backend"]
            self._info.gpu_layers_offloaded = gpu_layers
            self._info.backend = backend
            self._info.estimated_vram_mb = offload.get("estimated_vram_mb", 0)
            self._info.estimated_ram_mb = offload.get("estimated_ram_mb", 0)

            logger.info(
                f"Initiating model load for {self._info.model_name}: "
                f"layers={gpu_layers}, backend={backend}, threads={self._ai_config.threads}"
            )

            try:
                self._engine.load(
                    model_path=self._info.path,
                    context_window=self._info.context_window,
                    gpu_layers=gpu_layers,
                    threads=self._ai_config.threads,
                )
                self._info.state = ModelLifecycleState.LOADED
                self._info.error_message = None
                self._touch_activity()
                self._schedule_inactivity_timer()
                logger.info(f"Model {self._info.model_name} loaded successfully into memory.")
                return True
            except Exception as e:
                self._info.state = ModelLifecycleState.ERROR
                self._info.error_message = f"Model load failed: {e}"
                logger.error(f"Failed to load model {self._info.model_name}: {e}")
                return False

    def unload_model(self, force: bool = False) -> bool:
        """Unloads model weights from memory/VRAM cleanly."""
        with self._lock:
            if not self._info.is_loaded:
                return True

            if self._info.state == ModelLifecycleState.GENERATING or self._engine.is_generating():
                logger.warning("Cannot unload model while generation is active.")
                return False

            if not force:
                if self._active_operations > 0:
                    logger.warning(
                        f"Cannot unload model: {self._active_operations} active operation(s) in progress."
                    )
                    return False

                if self._can_unload_predicate is not None:
                    try:
                        if not self._can_unload_predicate():
                            logger.warning("Cannot unload model: external operations are still active.")
                            return False
                    except Exception as e:
                        logger.debug(f"Exception in can_unload_predicate: {e}")

            self._info.state = ModelLifecycleState.UNLOADING
            self._cancel_inactivity_timer()

            try:
                self._engine.unload()
                self._info.state = ModelLifecycleState.READY if self._info.path and self._info.path.exists() else ModelLifecycleState.NOT_CONFIGURED
                self._info.gpu_layers_offloaded = 0
                self._info.estimated_vram_mb = 0
                self._info.estimated_ram_mb = 0
                logger.info("Model unloaded successfully.")
                return True
            except Exception as e:
                self._info.state = ModelLifecycleState.ERROR
                self._info.error_message = f"Unload failed: {e}"
                logger.error(f"Error during model unload: {e}")
                return False

    def generate(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        repeat_penalty: Optional[float] = None,
    ) -> str:
        """Generates a complete response synchronously with lazy-load support."""
        tokens: List[str] = []
        for chunk in self.stream(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            repeat_penalty=repeat_penalty,
        ):
            tokens.append(chunk)
        return "".join(tokens)

    def stream(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1024,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        repeat_penalty: Optional[float] = None,
    ) -> Iterator[str]:
        """Streams response tokens with lazy-loading and concurrency protection."""
        own_lease = False
        with self._lock:
            if not self._info.is_loaded:
                if self._ai_config.lazy_load and self._info.is_ready_or_loaded:
                    loaded = self.load_model()
                    if not loaded:
                        raise RuntimeError(f"Lazy model load failed: {self._info.error_message}")
                else:
                    raise RuntimeError("Model is not loaded. Call load_model() first.")

            if self._info.state == ModelLifecycleState.GENERATING:
                raise RuntimeError("Concurrent generation requests are prohibited.")

            self._info.state = ModelLifecycleState.GENERATING
            if self._active_operations == 0:
                self._active_operations += 1
                own_lease = True
            self._touch_activity()
            self._cancel_inactivity_timer()

        temp = temperature if temperature is not None else self._ai_config.temperature
        p = top_p if top_p is not None else self._ai_config.top_p
        rep = repeat_penalty if repeat_penalty is not None else self._ai_config.repeat_penalty

        try:
            for chunk in self._engine.stream_chat(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temp,
                top_p=p,
                repeat_penalty=rep,
            ):
                self._touch_activity()
                yield chunk
        finally:
            should_notify = False
            with self._lock:
                if self._info.state == ModelLifecycleState.GENERATING:
                    self._info.state = ModelLifecycleState.LOADED
                if own_lease:
                    self._active_operations = max(0, self._active_operations - 1)
                if self._active_operations == 0:
                    self._schedule_inactivity_timer()
                    should_notify = True
            if should_notify:
                self._notify_generation_finished()

    def register_generation_finished_callback(self, callback: Any) -> None:
        """Registers a callback to execute whenever generation terminates."""
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
                logger.debug(f"Exception in manager generation finished callback: {e}")

    def cancel_generation(self) -> None:
        """Cancels any actively running generation."""
        logger.info("Cancelling active model generation...")
        self._engine.cancel()

    def shutdown(self, timeout_seconds: float = 0.0) -> bool:
        """Releases all resources, halts timers, and shuts down cleanly.

        Refuses to unload model weights while active generation is in progress,
        or while active operations still hold a reservation, to prevent memory corruption.
        Returns True if shutdown and unload completed; False if deferred.
        """
        logger.info("Shutting down ModelManager...")
        self.cancel_generation()

        if (self.state == ModelLifecycleState.GENERATING or self._engine.is_generating()) and timeout_seconds > 0:
            deadline = time.time() + timeout_seconds
            while time.time() < deadline and (self.state == ModelLifecycleState.GENERATING or self._engine.is_generating()):
                time.sleep(0.02)

        with self._lock:
            self._cancel_inactivity_timer()
            if self.state == ModelLifecycleState.GENERATING or self._engine.is_generating():
                logger.warning("Active generation still running; cannot unload model weights during shutdown.")
                return False
            if self._active_operations > 0:
                logger.warning(
                    f"Active operations ({self._active_operations}) still running; cannot unload model weights during shutdown."
                )
                return False
            return self.unload_model(force=True)

    def _touch_activity(self) -> None:
        self._last_activity = time.time()
        self._info.last_activity_timestamp = self._last_activity

    def _schedule_inactivity_timer(self) -> None:
        self._cancel_inactivity_timer()
        timeout = self._ai_config.unload_timeout_seconds
        if timeout <= 0 or not self._info.is_loaded:
            return

        def _on_timeout() -> None:
            with self._lock:
                if (
                    not self._info.is_loaded
                    or self._info.state == ModelLifecycleState.GENERATING
                    or self._active_operations > 0
                ):
                    return
                elapsed = time.time() - self._last_activity
                if elapsed >= timeout:
                    logger.info(f"Model inactive for {int(elapsed)}s (timeout={timeout}s). Auto-unloading...")
                    unloaded = self.unload_model()
                    if not unloaded:
                        # Reschedule if unload was refused (e.g. brain operation in progress)
                        self._schedule_inactivity_timer()
                else:
                    # Reschedule for remaining time
                    self._schedule_inactivity_timer()

        self._inactivity_timer = threading.Timer(timeout, _on_timeout)
        self._inactivity_timer.daemon = True
        self._inactivity_timer.start()

    def _cancel_inactivity_timer(self) -> None:
        if self._inactivity_timer is not None:
            self._inactivity_timer.cancel()
            self._inactivity_timer = None
