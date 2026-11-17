"""Tsukiko Local AI Brain — Model Manager Subsystem.

Provides GGUF validation, hardware-aware VRAM and RAM budgeting,
lifecycle management, and local model inference execution.
"""

from __future__ import annotations

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
from app.core.model_manager.manager import InsufficientMemoryError, ModelManager

__all__ = [
    "BaseInferenceEngine",
    "DeterministicFakeEngine",
    "LlamaCppInferenceEngine",
    "GGUFMetadata",
    "GGUFValidationError",
    "inspect_gguf_file",
    "ModelInfo",
    "ModelLifecycleState",
    "InsufficientMemoryError",
    "ModelManager",
    "filter_reasoning_tokens",
]
