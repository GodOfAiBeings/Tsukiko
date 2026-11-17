"""Tsukiko Local AI Brain — Model Lifecycle States and Data Models.

Defines the explicit state machine and metadata representation for local LLMs.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import time
from typing import Optional
from pydantic import BaseModel, Field


class ModelLifecycleState(str, Enum):
    """Explicit model loading and operational states."""
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_INSTALLED = "NOT_INSTALLED"
    VALIDATING = "VALIDATING"
    READY = "READY"
    LOADING = "LOADING"
    LOADED = "LOADED"
    GENERATING = "GENERATING"
    UNLOADING = "UNLOADING"
    ERROR = "ERROR"


class ModelInfo(BaseModel):
    """Current snapshot of the local AI model status and resource usage."""
    path: Optional[Path] = None
    model_name: str = "None"
    architecture: str = "unknown"
    quantization: str = "unknown"
    file_size_mb: int = 0
    context_window: int = 4096
    block_count: int = 0
    state: ModelLifecycleState = ModelLifecycleState.NOT_CONFIGURED
    error_message: Optional[str] = None
    backend: str = "cpu"  # "cpu", "cuda", "fake_test"
    gpu_layers_offloaded: int = 0
    estimated_vram_mb: int = 0
    estimated_ram_mb: int = 0
    runtime_version: str = "N/A"
    last_activity_timestamp: float = Field(default_factory=time.time)

    @property
    def is_loaded(self) -> bool:
        return self.state in (ModelLifecycleState.LOADED, ModelLifecycleState.GENERATING)

    @property
    def is_ready_or_loaded(self) -> bool:
        return self.state in (
            ModelLifecycleState.READY,
            ModelLifecycleState.LOADED,
            ModelLifecycleState.GENERATING,
        )
