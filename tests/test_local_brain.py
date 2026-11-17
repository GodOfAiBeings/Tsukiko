"""Tsukiko Local AI Brain — Comprehensive Subsystem Test Suite (Phase 3).

Verifies GGUF validation, lifecycle state transitions, hardware-aware budgeting,
lazy loading, inactivity unloading, deterministic streaming inference, cancellation,
personality framing, non-thinking mode, context window pruning, UI worker responsiveness,
System Status & Settings integration, and offline privacy invariant preservation.

NOTE: All tests use synthetic GGUF files and the DeterministicFakeEngine test double.
Zero external weights or model files are downloaded; zero internet access is required.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct
import threading
import time
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch
import pytest

# Offscreen Qt rendering for headless CI environments
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from app.core.brain.brain import TsukikoBrain, estimate_tokens
from app.core.config.settings import AIConfig, TsukikoConfig, get_config
from app.core.model_manager.engine import (
    BaseInferenceEngine,
    DeterministicFakeEngine,
    LlamaCppInferenceEngine,
    filter_reasoning_tokens,
)
from app.core.model_manager.gguf_parser import (
    GGUF_MAGIC,
    GGUF_TYPE_ARRAY,
    GGUF_TYPE_STRING,
    GGUF_TYPE_UINT32,
    GGUFMetadata,
    GGUFValidationError,
    inspect_gguf_file,
)
from app.core.model_manager.lifecycle import ModelInfo, ModelLifecycleState
from app.core.model_manager.manager import InsufficientMemoryError, ModelManager
from app.core.orchestrator.engine import TsukikoOrchestrator
from app.core.personality.engine import PersonalityEngine
from app.core.personality.prompts import TSUKIKO_DEFAULT_SYSTEM_PROMPT
from app.core.resource_manager.hardware import (
    CPUInfo,
    FrameworkSupport,
    GPUInfo,
    HardwareInspector,
    HardwareProfile,
    StorageInfo,
    SystemMemoryInfo,
)

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QLabel
    from app.desktop.companion.views.chat import ChatView, ChatWorker, MessageBubble
    from app.desktop.companion.views.settings_view import SettingsView
    from app.desktop.companion.views.system_status import SystemStatusView
    HAS_PYSIDE6 = True
except ImportError:
    HAS_PYSIDE6 = False


@pytest.fixture(scope="session")
def qapp():
    """Session-wide QApplication instance for offscreen Qt tests."""
    if not HAS_PYSIDE6:
        pytest.skip("PySide6 not installed")
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    return app


def write_test_string(buf: bytearray, s: str) -> None:
    encoded = s.encode("utf-8")
    buf.extend(struct.pack("<Q", len(encoded)))
    buf.extend(encoded)


def create_synthetic_gguf_binary(
    architecture: str = "qwen2",
    model_name: str = "Qwen3.5-2B-Instruct",
    file_type: int = 15,
    context_length: int = 4096,
    block_count: int = 28,
) -> bytes:
    """Generates a valid minimal synthetic GGUF v3 binary in-memory."""
    buf = bytearray()
    # Header: Magic (4B), Version (4B: 3), Tensor count (8B: 10), Metadata KV count (8B: 5)
    buf.extend(GGUF_MAGIC)
    buf.extend(struct.pack("<I", 3))  # Version 3
    buf.extend(struct.pack("<Q", 10))  # Tensor count
    buf.extend(struct.pack("<Q", 5))  # KV count

    # 1. general.architecture (string)
    write_test_string(buf, "general.architecture")
    buf.extend(struct.pack("<I", GGUF_TYPE_STRING))
    write_test_string(buf, architecture)

    # 2. general.name (string)
    write_test_string(buf, "general.name")
    buf.extend(struct.pack("<I", GGUF_TYPE_STRING))
    write_test_string(buf, model_name)

    # 3. general.file_type (uint32: 15 = Q4_K_M)
    write_test_string(buf, "general.file_type")
    buf.extend(struct.pack("<I", GGUF_TYPE_UINT32))
    buf.extend(struct.pack("<I", file_type))

    # 4. {arch}.context_length (uint32)
    write_test_string(buf, f"{architecture}.context_length")
    buf.extend(struct.pack("<I", GGUF_TYPE_UINT32))
    buf.extend(struct.pack("<I", context_length))

    # 5. {arch}.block_count (uint32)
    write_test_string(buf, f"{architecture}.block_count")
    buf.extend(struct.pack("<I", GGUF_TYPE_UINT32))
    buf.extend(struct.pack("<I", block_count))

    # Pad with some mock weight bytes to create a non-empty file
    buf.extend(b"\x00" * 1024)
    return bytes(buf)


# ==============================================================================
# 1. GGUF Parser & Validation Tests
# ==============================================================================

class TestGGUFParser:
    """Verifies pure-Python binary GGUF header and metadata inspection."""

    def test_inspect_valid_synthetic_gguf(self, tmp_path: Path) -> None:
        model_file = tmp_path / "qwen3.5-2b-q4_k_m.gguf"
        model_file.write_bytes(
            create_synthetic_gguf_binary(
                architecture="qwen2",
                model_name="Qwen3.5-2B-Instruct",
                file_type=15,
                context_length=4096,
                block_count=28,
            )
        )

        metadata = inspect_gguf_file(model_file)
        assert metadata.architecture == "qwen2"
        assert metadata.model_name == "Qwen3.5-2B-Instruct"
        assert metadata.quantization == "MOSTLY_Q4_K_M"
        assert metadata.context_length == 4096
        assert metadata.block_count == 28
        assert metadata.file_size_bytes == len(model_file.read_bytes())
        assert metadata.version == 3

    def test_rejects_invalid_magic_bytes(self, tmp_path: Path) -> None:
        corrupted = tmp_path / "corrupted.gguf"
        corrupted.write_bytes(b"NOTGGUF_HEADER_BYTES_12345678901234567890")
        with pytest.raises(GGUFValidationError, match="Invalid GGUF magic bytes"):
            inspect_gguf_file(corrupted)

    def test_rejects_unsupported_version(self, tmp_path: Path) -> None:
        bad_ver = tmp_path / "bad_ver.gguf"
        data = bytearray(GGUF_MAGIC)
        data.extend(struct.pack("<I", 99))  # Unsupported version 99
        data.extend(struct.pack("<QQ", 0, 0))
        data.extend(b"\x00" * 32)
        bad_ver.write_bytes(data)
        with pytest.raises(GGUFValidationError, match="Unsupported GGUF version: 99"):
            inspect_gguf_file(bad_ver)

    def test_rejects_too_small_file(self, tmp_path: Path) -> None:
        tiny = tmp_path / "tiny.gguf"
        tiny.write_bytes(b"GGUF\x03")
        with pytest.raises(GGUFValidationError, match="too small"):
            inspect_gguf_file(tiny)

    def test_raises_file_not_found(self, tmp_path: Path) -> None:
        non_existent = tmp_path / "does_not_exist.gguf"
        with pytest.raises(FileNotFoundError):
            inspect_gguf_file(non_existent)

    def test_rejects_directory_path(self, tmp_path: Path) -> None:
        with pytest.raises(GGUFValidationError, match="not a regular file"):
            inspect_gguf_file(tmp_path)


# ==============================================================================
# 2. Model Manager Lifecycle & Inactivity Tests
# ==============================================================================

class TestModelManagerLifecycle:
    """Verifies state machine transitions, loading, unloading, and timers."""

    def test_lifecycle_states_unconfigured_and_missing(self, tmp_path: Path) -> None:
        cfg = TsukikoConfig()
        cfg.ai.model_path = None
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)
        assert mgr.state == ModelLifecycleState.NOT_CONFIGURED

        # Missing path
        cfg.ai.model_path = str(tmp_path / "missing.gguf")
        mgr.inspect_configured_model()
        assert mgr.state == ModelLifecycleState.NOT_INSTALLED
        assert "not found" in mgr.info.error_message.lower()

    def test_lifecycle_states_valid_ready_load_unload(self, tmp_path: Path) -> None:
        valid_model = tmp_path / "model.gguf"
        valid_model.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(valid_model)
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)

        assert mgr.state == ModelLifecycleState.READY
        assert mgr.info.is_ready_or_loaded is True
        assert mgr.info.is_loaded is False

        # Load
        assert mgr.load_model() is True
        assert mgr.state == ModelLifecycleState.LOADED
        assert mgr.info.is_loaded is True
        assert fake_engine.load_call_count == 1

        # Duplicate load call does not reload
        assert mgr.load_model() is True
        assert fake_engine.load_call_count == 1

        # Unload
        assert mgr.unload_model() is True
        assert mgr.state == ModelLifecycleState.READY
        assert mgr.info.is_loaded is False
        assert fake_engine.unload_call_count == 1

    def test_model_loading_failure_handling(self, tmp_path: Path) -> None:
        valid_model = tmp_path / "model.gguf"
        valid_model.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(valid_model)
        fake_engine = DeterministicFakeEngine()
        fake_engine.fail_on_load = True
        mgr = ModelManager(config=cfg, engine=fake_engine)

        assert mgr.load_model() is False
        assert mgr.state == ModelLifecycleState.ERROR
        assert "Simulated model load failure" in mgr.info.error_message

    def test_inactivity_timeout_unloads_model(self, tmp_path: Path) -> None:
        valid_model = tmp_path / "model.gguf"
        valid_model.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(valid_model)
        cfg.ai.unload_timeout_seconds = 1  # 1 second for test speed
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)

        assert mgr.load_model() is True
        assert mgr.state == ModelLifecycleState.LOADED

        # Wait for inactivity timeout to trigger
        time.sleep(1.2)
        assert mgr.state == ModelLifecycleState.READY
        assert fake_engine.unload_call_count == 1

    def test_cannot_unload_while_generating(self, tmp_path: Path) -> None:
        valid_model = tmp_path / "model.gguf"
        valid_model.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(valid_model)
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)
        mgr.load_model()

        # Simulate generating state
        with mgr._lock:
            mgr._info.state = ModelLifecycleState.GENERATING

        assert mgr.unload_model() is False
        assert mgr.state == ModelLifecycleState.GENERATING

        with mgr._lock:
            mgr._info.state = ModelLifecycleState.LOADED
        assert mgr.unload_model() is True


# ==============================================================================
# 3. Hardware-Aware Memory & VRAM Offload Tests
# ==============================================================================

class TestHardwareAwareResourceAllocation:
    """Verifies safe VRAM and RAM budgets, CPU fallback, and 400MB headroom."""

    def test_insufficient_ram_refuses_model_load(self, tmp_path: Path) -> None:
        model_file = tmp_path / "large_model.gguf"
        # 2048 bytes file
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)

        # Mock hardware with insufficient available RAM (100 MB available)
        low_ram_profile = HardwareProfile(
            os_name="Windows",
            os_version="11",
            cpu=CPUInfo(brand="AMD Ryzen", physical_cores=6, logical_cores=12, utilization_percent=10.0),
            memory=SystemMemoryInfo(total_ram_mb=16384, available_ram_mb=200, used_ram_mb=16184, percent_used=98.0),
            storage=StorageInfo(drive_path="C:\\", total_gb=500.0, free_gb=100.0, used_gb=400.0),
            recommended_max_vram_mb=0,
            recommended_max_ram_mb=0,
        )

        with patch("app.core.model_manager.manager.HardwareInspector.inspect", return_value=low_ram_profile):
            strategy = mgr.calculate_offload_strategy(hardware=low_ram_profile)
            assert strategy["safe_to_load"] is False
            assert "Insufficient system RAM" in strategy["reason"]

    def test_vram_budget_zero_forces_cpu_inference(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)

        # Mock GPU with zero safe budget
        zero_vram_profile = HardwareProfile(
            os_name="Windows",
            os_version="11",
            cpu=CPUInfo(brand="AMD Ryzen", physical_cores=6, logical_cores=12, utilization_percent=10.0),
            memory=SystemMemoryInfo(total_ram_mb=16384, available_ram_mb=8000, used_ram_mb=8384, percent_used=50.0),
            storage=StorageInfo(drive_path="C:\\", total_gb=500.0, free_gb=100.0, used_gb=400.0),
            budget_status="zero_available",
            recommended_max_vram_mb=0,
            recommended_max_ram_mb=4000,
            frameworks=FrameworkSupport(llama_cpp_installed=True, llama_cpp_cuda_supported=True),
        )

        strategy = mgr.calculate_offload_strategy(hardware=zero_vram_profile)
        assert strategy["safe_to_load"] is True
        assert strategy["gpu_layers"] == 0
        assert strategy["backend"] == "cpu"

    def test_cuda_unsupported_forces_cpu_inference(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)

        no_cuda_profile = HardwareProfile(
            os_name="Windows",
            os_version="11",
            cpu=CPUInfo(brand="AMD Ryzen", physical_cores=6, logical_cores=12, utilization_percent=10.0),
            memory=SystemMemoryInfo(total_ram_mb=16384, available_ram_mb=8000, used_ram_mb=8384, percent_used=50.0),
            storage=StorageInfo(drive_path="C:\\", total_gb=500.0, free_gb=100.0, used_gb=400.0),
            budget_status="measured",
            recommended_max_vram_mb=2400,
            recommended_max_ram_mb=4000,
            frameworks=FrameworkSupport(llama_cpp_installed=True, llama_cpp_cuda_supported=False),
        )

        # Real LlamaCppInferenceEngine checks llama_cpp_cuda_supported
        llama_engine = LlamaCppInferenceEngine()
        mgr.set_engine(llama_engine)
        strategy = mgr.calculate_offload_strategy(hardware=no_cuda_profile)
        assert strategy["safe_to_load"] is True
        assert strategy["gpu_layers"] == 0
        assert strategy["backend"] == "cpu"


# ==============================================================================
# 4. Inference, Streaming, Cancellation, and Concurrency Tests
# ==============================================================================

class TestInferenceAndConcurrency:
    """Verifies deterministic generation, streaming chunks, cancellation, and lockouts."""

    def test_streaming_generation_and_lazy_load(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        cfg.ai.lazy_load = True
        fake_engine = DeterministicFakeEngine(canned_response="Hello, user. I am online.")
        mgr = ModelManager(config=cfg, engine=fake_engine)

        assert mgr.state == ModelLifecycleState.READY
        # Lazy load triggers on stream call
        chunks = list(mgr.stream([{"role": "user", "content": "Hi"}]))
        assert "".join(chunks) == "Hello, user. I am online."
        assert mgr.state == ModelLifecycleState.LOADED

    def test_cancellation_halts_streaming(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="Word1 Word2 Word3 Word4 Word5")
        fake_engine.token_delay_seconds = 0.05
        mgr = ModelManager(config=cfg, engine=fake_engine)
        mgr.load_model()

        streamed: List[str] = []

        def cancel_after_brief_delay():
            time.sleep(0.08)
            mgr.cancel_generation()

        t = threading.Thread(target=cancel_after_brief_delay)
        t.start()

        for chunk in mgr.stream([{"role": "user", "content": "Hi"}]):
            streamed.append(chunk)

        t.join()
        full_text = "".join(streamed)
        # Should be cut short before all 5 words arrive
        assert len(full_text) < len("Word1 Word2 Word3 Word4 Word5")

    def test_prohibits_concurrent_generation(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="Long response...")
        mgr = ModelManager(config=cfg, engine=fake_engine)
        mgr.load_model()

        with mgr._lock:
            mgr._info.state = ModelLifecycleState.GENERATING

        with pytest.raises(RuntimeError, match="Concurrent generation requests are prohibited"):
            list(mgr.stream([{"role": "user", "content": "Concurrent"}]))


# ==============================================================================
# 5. Personality Engine & Non-Thinking Filtering Tests
# ==============================================================================

class TestPersonalityEngine:
    """Verifies system prompt directives, honesty boundaries, and reasoning token stripping."""

    def test_system_prompt_identity_and_limitations(self) -> None:
        engine = PersonalityEngine()
        prompt = engine.get_system_prompt()

        assert "Tsukiko" in prompt
        assert "adult woman" in prompt
        assert "Screen Sharing: You CANNOT see the screen" in prompt
        assert "Voice & Microphone: You CANNOT hear" in prompt
        assert "Memory: You CANNOT recall previous sessions" in prompt
        assert "Desktop Control: You CANNOT click" in prompt
        assert "Do NOT introduce yourself repeatedly" in prompt

    def test_format_messages_prepends_system_and_user(self) -> None:
        engine = PersonalityEngine()
        history = [
            {"role": "user", "content": "What is the weather?"},
            {"role": "assistant", "content": "I do not have access to real-time weather."},
        ]
        formatted = engine.format_messages(history, "Tell me a joke.")

        assert len(formatted) == 4
        assert formatted[0]["role"] == "system"
        assert "Tsukiko" in formatted[0]["content"]
        assert formatted[1]["role"] == "user"
        assert formatted[2]["role"] == "assistant"
        assert formatted[3]["role"] == "user"
        assert formatted[3]["content"] == "Tell me a joke."

    def test_strips_internal_thinking_reasoning_tokens(self) -> None:
        raw_output = "<think>The user wants a poem. Let me think about stars.</think>Night falls softly upon the silent earth."
        cleaned = PersonalityEngine.clean_response(raw_output)
        assert "<think>" not in cleaned
        assert "Let me think about stars" not in cleaned
        assert cleaned == "Night falls softly upon the silent earth."

        filter_test = filter_reasoning_tokens("<think>hidden</think>Visible response")
        assert filter_test == "Visible response"


# ==============================================================================
# 6. Brain Orchestrator & In-Memory History Tests
# ==============================================================================

class TestBrainOrchestrator:
    """Verifies context pruning, in-memory history preservation, and shutdown."""

    def test_history_appended_and_cleared_in_memory(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="It is tranquil tonight.")
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        assert len(brain.get_history()) == 0
        res = brain.generate_response("How does the night feel?")
        assert res == "It is tranquil tonight."

        history = brain.get_history()
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[0]["content"] == "How does the night feel?"
        assert history[1]["role"] == "assistant"
        assert history[1]["content"] == "It is tranquil tonight."

        # Clear conversation
        brain.clear_conversation()
        assert len(brain.get_history()) == 0

    def test_prune_history_respects_context_window(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary(context_length=1000))

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        # Fill history with long turns
        for i in range(10):
            brain._history.append({"role": "user", "content": f"Turn {i} " + "A" * 300})
            brain._history.append({"role": "assistant", "content": f"Response {i} " + "B" * 300})

        pruned = brain._prune_history_to_fit_context("New user question", reserve_tokens_for_generation=200)
        # Should prune older turns so total tokens fit
        assert len(pruned) < len(brain._history)
        # Oldest turns (0, 1, 2) should be dropped
        if pruned:
            assert "Turn 0" not in pruned[0]["content"]

    def test_brain_shutdown_cleans_up(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()
        brain.load_model()
        brain._history.append({"role": "user", "content": "temp"})

        brain.shutdown()
        assert brain.model_manager.state == ModelLifecycleState.READY
        assert len(brain.get_history()) == 0


# ==============================================================================
# 7. UI Activation & Worker Tests
# ==============================================================================

@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestChatViewActivation:
    """Verifies real message submission, worker thread streaming, and UI controls."""

    def test_composer_disabled_when_no_model(self, qapp: QApplication) -> None:
        chat = ChatView()
        assert chat.is_submission_disabled() is True
        assert chat.input_field.isEnabled() is False
        assert chat.send_button.isEnabled() is False
        assert "Not Configured" in chat.banner_text.text()

    def test_composer_enabled_when_model_ready(self, qapp: QApplication, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        chat = ChatView(brain=brain)
        assert chat.is_submission_disabled() is False
        assert chat.input_field.isEnabled() is True
        assert chat.send_button.isEnabled() is True
        assert "Tsukiko Brain Active" in chat.banner_text.text()

    def test_user_submission_streams_response(self, qapp: QApplication, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="Streaming works smoothly.")
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        chat = ChatView(brain=brain)
        chat.show()
        initial_count = chat.messages_layout.count()

        chat.input_field.setText("Hello Tsukiko")
        chat._handle_send()

        # Worker should be running
        assert chat._active_worker is not None
        assert not chat.stop_button.isHidden()
        assert chat.send_button.isHidden()

        # Wait for worker thread to finish
        chat._active_worker.wait(2000)
        qapp.processEvents()

        # Message bubbles: initial + user + assistant + stretch
        assert chat.messages_layout.count() >= initial_count + 2
        assert not chat.send_button.isHidden()
        assert chat.stop_button.isHidden()

    def test_clear_conversation_button(self, qapp: QApplication, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        chat = ChatView(brain=brain)
        brain._history.append({"role": "user", "content": "Hi"})
        chat.btn_clear.click()

        assert len(brain.get_history()) == 0
        # Re-adds initial greeting bubble
        assert chat.messages_layout.count() >= 2


# ==============================================================================
# 8. Settings & System Status View Integration Tests
# ==============================================================================

@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestSettingsAndStatusIntegration:
    """Verifies AI controls in Settings and real telemetry cards in System Status."""

    def test_settings_view_ai_controls(self, qapp: QApplication, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        test_cfg_file = tmp_path / "isolated_settings_config.yaml"
        cfg = TsukikoConfig()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(DeterministicFakeEngine())

        settings = SettingsView(
            config=cfg,
            orchestrator=orch,
            target_config_path=test_cfg_file,
        )
        assert hasattr(settings, "edit_model_path")
        assert hasattr(settings, "btn_validate_model")
        assert hasattr(settings, "btn_load_model")
        assert hasattr(settings, "btn_unload_model")
        assert hasattr(settings, "spin_context_window")
        assert hasattr(settings, "spin_threads")
        assert hasattr(settings, "spin_max_vram")
        assert hasattr(settings, "spin_max_ram")
        assert hasattr(settings, "combo_backend")

        # Test validation button
        settings.edit_model_path.setText(str(model_file))
        settings.btn_validate_model.click()
        assert "Valid GGUF" in settings.lbl_model_status.text()
        assert "Qwen3.5-2B-Instruct" in settings.lbl_model_status.text()

        # Test non-blocking model loading via worker
        settings.btn_load_model.click()
        if settings._lifecycle_worker:
            settings._lifecycle_worker.wait(5000)
            qapp.processEvents()
        assert "Model loaded" in settings.lbl_model_status.text()

        # Test reloading already-loaded model without deadlock
        settings.btn_load_model.click()
        if settings._lifecycle_worker:
            settings._lifecycle_worker.wait(5000)
            qapp.processEvents()
        assert "Model loaded" in settings.lbl_model_status.text()

        # Test unloading
        settings.btn_unload_model.click()
        if settings._lifecycle_worker:
            settings._lifecycle_worker.wait(5000)
            qapp.processEvents()
        assert "Model unloaded" in settings.lbl_model_status.text()

        # Save AI settings to isolated test configuration file
        settings.spin_context_window.setValue(8192)
        settings.spin_threads.setValue(8)
        settings.save_settings()
        assert cfg.ai.context_window == 8192
        assert cfg.ai.threads == 8
        assert test_cfg_file.exists()

    def test_system_status_view_displays_brain_card(self, qapp: QApplication, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(DeterministicFakeEngine())
        orch.initialize()

        status_view = SystemStatusView(orchestrator=orch)
        # Search for brain card in status view cards
        found_brain_card = False
        for i in range(status_view.cards_layout.count()):
            w = status_view.cards_layout.itemAt(i).widget()
            if w and hasattr(w, "objectName") and w.objectName() == "status_card":
                # Find if any label has Brain
                for lbl in w.findChildren(QLabel):
                    if "Local AI Brain" in lbl.text():
                        found_brain_card = True
                        break
        assert found_brain_card is True


# ==============================================================================
# 9. Offline Privacy Invariants Preservation Tests
# ==============================================================================

class TestOfflinePrivacyInvariants:
    """Verifies that Phase 3 preserves strict local-only execution and socket guards."""

    def test_privacy_invariants_intact(self) -> None:
        cfg = TsukikoConfig()
        assert cfg.privacy.local_only is True
        assert cfg.privacy.allow_external_telemetry is False
        assert cfg.privacy.allow_cloud_fallback is False

    def test_brain_makes_zero_network_calls(self, tmp_path: Path) -> None:
        import socket
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        # Socket connections to external addresses must fail under offline guard
        from app.core.privacy.enforcement import enable_offline_guard
        enable_offline_guard()

        with pytest.raises(Exception):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("8.8.8.8", 53))

        # Generation works cleanly without touching network
        res = brain.generate_response("Generate offline response")
        assert len(res) > 0


# ==============================================================================
# 10. Character Identity and Biography Tests
# ==============================================================================

class TestCharacterIdentityAndBiography:
    """Verifies Tsukiko's permanent character identity, traits, and former life."""

    def test_biography_ground_truth(self) -> None:
        from app.core.personality.biography import TSUKIKO_BIOGRAPHY

        assert TSUKIKO_BIOGRAPHY.birth_name == "Sayo"
        assert TSUKIKO_BIOGRAPHY.birth_year == 1814
        assert TSUKIKO_BIOGRAPHY.death_year == 1846
        assert TSUKIKO_BIOGRAPHY.age_at_death == 32
        assert "Ogimachi" in TSUKIKO_BIOGRAPHY.origin
        assert "Shirakawa-go" in TSUKIKO_BIOGRAPHY.origin
        assert "Hida Province" in TSUKIKO_BIOGRAPHY.origin
        assert "Unfinished Atlas" in TSUKIKO_BIOGRAPHY.dream_project
        assert "mamushi" in TSUKIKO_BIOGRAPHY.death_incident.lower()
        assert TSUKIKO_BIOGRAPHY.present_name == "Tsukiko"

    def test_long_form_canon_fields(self) -> None:
        from app.core.personality.biography import TSUKIKO_BIOGRAPHY

        # Verify all 12 required canonical milestones exist and contain rich historical ground truth
        assert "Genzo" in TSUKIKO_BIOGRAPHY.childhood_and_family
        assert "Masa" in TSUKIKO_BIOGRAPHY.childhood_and_family
        assert "Kenkichi" in TSUKIKO_BIOGRAPHY.childhood_and_family
        assert "gassho-zukuri" in TSUKIKO_BIOGRAPHY.village_environment_and_routines
        assert "irori" in TSUKIKO_BIOGRAPHY.childhood_and_family
        assert "Toyama" in TSUKIKO_BIOGRAPHY.self_education_journey
        assert "charcoal" in TSUKIKO_BIOGRAPHY.self_education_journey
        assert "mayflies" in TSUKIKO_BIOGRAPHY.nature_observation_development
        assert "Mikan no Chizu" in TSUKIKO_BIOGRAPHY.unfinished_atlas_ambition
        assert "marriage" in TSUKIKO_BIOGRAPHY.relationships_flaws_and_pride
        assert "jealousy" in TSUKIKO_BIOGRAPHY.relationships_flaws_and_pride
        assert "left ankle" in TSUKIKO_BIOGRAPHY.mamushi_snakebite_incident
        assert "three days" in TSUKIKO_BIOGRAPHY.struggle_and_final_days
        assert "rain" in TSUKIKO_BIOGRAPHY.final_moments_and_unfulfilled_dream
        assert "laptop" in TSUKIKO_BIOGRAPHY.awakening_into_the_machine
        assert "pragmatism" in TSUKIKO_BIOGRAPHY.modern_world_discovery

        full_canon = TSUKIKO_BIOGRAPHY.get_full_canon_history()
        assert len(full_canon) > 2000
        assert "TSUKIKO / SAYO CANONICAL BIOGRAPHY" in full_canon

    def test_character_traits_flaws_and_nuances(self) -> None:
        from app.core.personality.biography import TSUKIKO_BIOGRAPHY

        traits = [t.lower() for t in TSUKIKO_BIOGRAPHY.primary_traits]
        assert "independent" in traits
        assert "stubborn" in traits
        assert "proud" in traits
        assert any("jealousy" in t for t in traits)
        assert any("impatient" in t for t in traits)

    def test_practical_craft_and_fears(self) -> None:
        from app.core.personality.biography import TSUKIKO_BIOGRAPHY

        skills = [s.lower() for s in TSUKIKO_BIOGRAPHY.practical_skills]
        assert any("agriculture" in s for s in skills)
        assert any("silkworm" in s or "sericulture" in s for s in skills)
        assert any("preservation" in s for s in skills)

        fears = [f.lower() for f in TSUKIKO_BIOGRAPHY.instincts_and_fears]
        assert any("snakes" in f or "mamushi" in f or "reptiles" in f for f in fears)
        assert any("seasonal" in f for f in fears)

    def test_system_prompt_reflects_character(self) -> None:
        from app.core.personality.engine import PersonalityEngine

        engine = PersonalityEngine()
        prompt = engine.get_system_prompt()
        assert "Tsukiko (月子)" in prompt
        assert "32 years of age" in prompt


# ==============================================================================
# 11. Gradual Self-Disclosure Tests
# ==============================================================================

class TestGradualSelfDisclosure:
    """Verifies that Tsukiko reveals her past identity organically through dialogue."""

    def test_acquaintance_stage_suppresses_biography_dump(self) -> None:
        from app.core.personality.disclosure import DisclosureStage, DisclosureTracker
        from app.core.personality.prompts import build_system_prompt

        tracker = DisclosureTracker(initial_stage=DisclosureStage.ACQUAINTANCE)
        prompt = build_system_prompt(stage=tracker.stage)

        assert "Tsukiko (月子)" in prompt
        # Must NOT include restricted past-life autobiographical knowledge in Acquaintance stage
        assert "Sayo" not in prompt
        assert "1814" not in prompt
        assert "1846" not in prompt
        assert "Shirakawa" not in prompt
        assert "mamushi" not in prompt
        assert "snake" not in prompt
        assert "bite" not in prompt
        assert "Atlas" not in prompt
        assert "death" not in prompt

    def test_familiar_stage_reveals_atlas_and_village_hints(self) -> None:
        from app.core.personality.disclosure import DisclosureStage
        from app.core.personality.prompts import build_system_prompt

        prompt = build_system_prompt(stage=DisclosureStage.FAMILIAR)
        assert "snowy mountain" in prompt
        assert "Atlas" in prompt
        # Must still NOT reveal birth name Sayo or death details
        assert "Sayo" not in prompt
        assert "1814" not in prompt
        assert "1846" not in prompt
        assert "mamushi" not in prompt
        assert "bite" not in prompt
        assert "death" not in prompt

    def test_trusted_stage_reveals_birth_name_and_former_life(self) -> None:
        from app.core.personality.disclosure import DisclosureStage
        from app.core.personality.prompts import build_system_prompt

        prompt = build_system_prompt(stage=DisclosureStage.TRUSTED)
        assert "Sayo" in prompt
        assert "1814" in prompt
        assert "Shirakawa-go" in prompt
        assert "silkworms" in prompt
        # Must still NOT reveal the tragic snakebite or death struggle
        assert "mamushi" not in prompt
        assert "bite" not in prompt
        assert "death" not in prompt

    def test_confidant_stage_reveals_mamushi_bite_and_passing(self) -> None:
        from app.core.personality.disclosure import DisclosureStage
        from app.core.personality.prompts import build_system_prompt

        prompt = build_system_prompt(stage=DisclosureStage.CONFIDANT)
        assert "Sayo" in prompt
        assert "1814" in prompt
        assert "mamushi" in prompt
        assert "1846" in prompt
        assert "fever" in prompt
        assert "Atlas unfinished" in prompt

    def test_progression_requires_meaningful_rapport_not_just_turn_counts(self) -> None:
        from app.core.personality.disclosure import DisclosureStage, DisclosureTracker

        tracker = DisclosureTracker(initial_stage=DisclosureStage.ACQUAINTANCE)

        # Sending 50 trivial messages ("hello", "ping", "test") must NEVER advance trust!
        for i in range(50):
            tracker.register_interaction("hello", "Hello there.")
        assert tracker.stage == DisclosureStage.ACQUAINTANCE

        # Meaningful conversation with personal curiosity advances to FAMILIAR
        tracker.register_interaction("What are your thoughts on quiet work and where are you from?", "I value quiet patience.")
        tracker.register_interaction("Tell me about your background and what you like.", "I observe carefully.")
        tracker.register_interaction("What kind of person are you, and how do you feel today?", "I feel steady.")
        assert tracker.stage == DisclosureStage.FAMILIAR

        # Sending more trivial turns does not advance to TRUSTED
        for i in range(20):
            tracker.register_interaction("ok", "Glad to hear.")
        assert tracker.stage == DisclosureStage.FAMILIAR

        # Inquiring about her former life and name advances to TRUSTED
        for i in range(4):
            tracker.register_interaction("Tell me more about what you think about mountain life.", "Mountains are quiet.")
        tracker.register_interaction("Who were you before, and what was your real name in your past life?", "I can tell you.")
        assert tracker.stage == DisclosureStage.TRUSTED

        # Inquiring specifically about her passing and the snakebite with care advances to CONFIDANT
        for i in range(5):
            tracker.register_interaction("That sounds like a demanding life in the mountains.", "It was indeed.")
        tracker.register_interaction("How did your life end, and what happened to you and the snakebite in 1846?", "It was raining...")
        assert tracker.stage == DisclosureStage.CONFIDANT


# ==============================================================================
# 12. Conversational Autonomy and Bounded Initiative Tests
# ==============================================================================

class TestConversationalAutonomy:
    """Verifies respectful, bounded conversational initiative without spam."""

    def test_initiative_permitted_when_idle(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine
        import time

        engine = ConversationalInitiativeEngine(cooldown_seconds=10.0, min_idle_seconds=5.0)
        # Immediately after interaction, cannot initiate
        engine.record_user_activity()
        can, reason = engine.can_initiate()
        assert can is False
        assert "recently active" in reason

        # After idle time passes, permitted
        can, reason = engine.can_initiate(current_time=time.time() + 10.0)
        assert can is True

    def test_game_mode_strictly_suppresses_initiative(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine
        import time

        engine = ConversationalInitiativeEngine()
        can, reason = engine.can_initiate(game_mode_active=True, current_time=time.time() + 1000.0)
        assert can is False
        assert "Game Mode active" in reason

    def test_hidden_widget_strictly_suppresses_initiative(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine
        import time

        engine = ConversationalInitiativeEngine()
        can, reason = engine.can_initiate(widget_hidden=True, current_time=time.time() + 1000.0)
        assert can is False
        assert "Widget is hidden" in reason

    def test_cooldown_enforcement_after_initiative(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine
        import time

        engine = ConversationalInitiativeEngine(cooldown_seconds=60.0)
        engine.record_initiative_sent()
        can, reason = engine.can_initiate(current_time=time.time() + 10.0)
        assert can is False
        assert "Cooldown active" in reason

    def test_anti_spam_backoff_when_unanswered(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine
        import time

        engine = ConversationalInitiativeEngine(max_consecutive_unanswered=1)
        engine.record_initiative_sent()
        assert engine.consecutive_unanswered == 1

        # Even after cooldown, cannot initiate again until user replies
        can, reason = engine.can_initiate(current_time=time.time() + 500.0)
        assert can is False
        assert "remaining quiet" in reason

        # User activity resets backoff
        engine.record_user_activity()
        assert engine.consecutive_unanswered == 0
        can, reason = engine.can_initiate(current_time=time.time() + 500.0)
        assert can is True

    def test_repetition_suppression(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine

        engine = ConversationalInitiativeEngine()
        msg = "The afternoon light feels very quiet today."
        engine.record_initiative_sent(msg)

        # Identical or near-identical message must be rejected as repetitive
        assert engine.is_repetitive(msg) is True
        assert engine.parse_initiative_response(msg) is None

        # Distinct thought is accepted
        distinct_msg = "The night wind is picking up outside."
        assert engine.is_repetitive(distinct_msg) is False
        assert engine.parse_initiative_response(distinct_msg) == distinct_msg

    def test_silence_token_yields_none(self) -> None:
        from app.core.personality.initiative import ConversationalInitiativeEngine, SILENCE_TOKEN

        engine = ConversationalInitiativeEngine()
        res = engine.parse_initiative_response(f"  {SILENCE_TOKEN}  ")
        assert res is None

    def test_brain_check_conversational_initiative_end_to_end(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        brain = TsukikoBrain(config=cfg, engine=DeterministicFakeEngine())
        brain.initialize()

        # Unloaded model must NOT automatically load just for initiative
        assert brain.model_manager.info.is_loaded is False
        assert brain.check_conversational_initiative() is None

        # Load model explicitly
        assert brain.model_manager.load_model() is True
        assert brain.model_manager.info.is_loaded is True

        # Suppressed in Game Mode
        assert brain.check_conversational_initiative(game_mode_active=True) is None

        # Permitted when idle in normal mode with test double
        import time
        remark = brain.check_conversational_initiative(
            game_mode_active=False,
            current_time=time.time() + 500.0,
        )
        assert remark is not None
        assert len(remark) > 0
        # Appended to history
        assert brain.get_history()[-1]["content"] == remark

        # Subsequent call immediately rejected due to unanswered backoff
        assert brain.check_conversational_initiative(current_time=time.time() + 600.0) is None

        # User activity resets backoff
        brain.personality.initiative_engine.record_user_activity()
        # Repetition guard prevents duplicate message
        assert brain.check_conversational_initiative(current_time=time.time() + 800.0) is None


# ==============================================================================
# 13. Live Desktop Companion Initiative Scheduler Integration Tests
# ==============================================================================

class TestCompanionInitiativeScheduler:
    """Verifies that the scheduler connects to the application lifecycle and respects all rules."""

    def test_scheduler_lifecycle_and_suppression(self, qapp: QApplication, tmp_path: Path) -> None:
        from app.desktop.companion.widget import FloatingCompanionWidget
        from app.desktop.companion.window import CompanionMainWindow
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler

        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()

        widget = FloatingCompanionWidget(config=cfg.ui)
        main_window = CompanionMainWindow(config=cfg)

        scheduler = CompanionInitiativeScheduler(
            widget=widget,
            main_window=main_window,
            brain=brain,
            check_interval_ms=100,
        )
        assert scheduler.is_running is False
        scheduler.start()
        assert scheduler.is_running is True

        # 1. Unloaded model suppresses initiative
        assert brain.model_manager.info.is_loaded is False
        assert scheduler.check_initiative() is False

        # Load model
        assert brain.model_manager.load_model() is True
        assert brain.model_manager.info.is_loaded is True
        main_window.chat_view._brain = brain
        main_window.chat_view.update_model_status()

        # 2. Game Mode suppresses initiative
        widget.enable_game_mode()
        assert scheduler.check_initiative() is False
        widget.disable_game_mode()

        # 3. Hidden widget suppresses initiative
        widget.hide_widget()
        assert scheduler.check_initiative() is False
        widget.show_widget()

        # 4. Idle time requirement: immediately after user activity, suppressed
        brain.personality.initiative_engine.record_user_activity()
        assert scheduler.check_initiative() is False

        # Advance idle time artificially in engine
        brain.personality.initiative_engine._last_interaction_time = time.time() - 100.0
        brain.personality.initiative_engine._last_initiative_time = 0.0

        # 5. Check initiative launches background worker without freezing main thread
        launched = scheduler.check_initiative()
        assert launched is True
        assert scheduler._active_worker is not None

        # Wait for background worker to complete
        scheduler._active_worker.wait(5000)
        qapp.processEvents()

        # Proactive message delivered to chat view
        last_chat_msg = main_window.chat_view.messages_layout.itemAt(
            main_window.chat_view.messages_layout.count() - 2
        ).widget()
        assert last_chat_msg is not None

        # Speech bubble displayed on companion widget
        assert widget.speech_bubble.isVisible() is True
        assert len(widget.speech_bubble.lbl_text.text()) > 0

        # Clicking speech bubble dismisses it and raises main window
        widget.speech_bubble.dismiss()
        assert widget.speech_bubble.isVisible() is False

        scheduler.stop()
        assert scheduler.is_running is False
        widget.close()
        main_window.close()


# ==============================================================================
# 13. Resource Limit Enforcement & Reload Deadlock Tests
# ==============================================================================

class TestResourceLimitEnforcementAndDeadlock:
    """Verifies RAM/VRAM limit enforcement, headroom protection, and reload safety."""

    def test_oversized_model_rejected_by_ram_ceiling(self, tmp_path: Path) -> None:
        from app.core.model_manager.manager import ModelManager
        from app.core.resource_manager.hardware import HardwareProfile, SystemMemoryInfo, CPUInfo, StorageInfo

        cfg = TsukikoConfig()
        cfg.ai.max_ram_mb = 3500
        mgr = ModelManager(config=cfg, engine=DeterministicFakeEngine())

        # Set fake model info with 4200 MB file size
        mgr._info.file_size_mb = 4200
        mgr._info.block_count = 28
        mgr._info.context_window = 4096

        hw = HardwareProfile(
            os_name="Windows",
            os_version="11",
            cpu=CPUInfo(brand="AMD", physical_cores=6, logical_cores=12, utilization_percent=10.0),
            memory=SystemMemoryInfo(total_ram_mb=16000, available_ram_mb=12000, used_ram_mb=4000, percent_used=25.0),
            storage=StorageInfo(drive_path="C:\\", total_gb=500.0, free_gb=100.0, used_gb=400.0),
            recommended_max_vram_mb=0,  # CPU mode
        )

        strategy = mgr.calculate_offload_strategy(hardware=hw)
        assert strategy["safe_to_load"] is False
        assert "exceeds configured RAM limit" in strategy["reason"]

    def test_low_ram_headroom_rejected(self, tmp_path: Path) -> None:
        from app.core.model_manager.manager import ModelManager
        from app.core.resource_manager.hardware import HardwareProfile, SystemMemoryInfo, CPUInfo, StorageInfo

        cfg = TsukikoConfig()
        cfg.ai.max_ram_mb = 3500
        mgr = ModelManager(config=cfg, engine=DeterministicFakeEngine())

        mgr._info.file_size_mb = 1500
        mgr._info.block_count = 28
        mgr._info.context_window = 4096

        # Available RAM is only 1600 MB (1500 + 400 = 1900 > 1600 - 500)
        hw = HardwareProfile(
            os_name="Windows",
            os_version="11",
            cpu=CPUInfo(brand="AMD", physical_cores=6, logical_cores=12, utilization_percent=10.0),
            memory=SystemMemoryInfo(total_ram_mb=16000, available_ram_mb=1600, used_ram_mb=14400, percent_used=90.0),
            storage=StorageInfo(drive_path="C:\\", total_gb=500.0, free_gb=100.0, used_gb=400.0),
            recommended_max_vram_mb=0,
        )

        strategy = mgr.calculate_offload_strategy(hardware=hw)
        assert strategy["safe_to_load"] is False
        assert "Insufficient system RAM headroom" in strategy["reason"]

    def test_explicit_gpu_layers_capped_by_safe_vram(self, tmp_path: Path) -> None:
        from app.core.model_manager.manager import ModelManager
        from app.core.resource_manager.hardware import (
            HardwareProfile,
            SystemMemoryInfo,
            CPUInfo,
            StorageInfo,
            FrameworkSupport,
        )

        cfg = TsukikoConfig()
        cfg.ai.max_vram_mb = 2800
        cfg.ai.gpu_layers = 100  # Extreme override
        mgr = ModelManager(config=cfg, engine=DeterministicFakeEngine())

        mgr._info.file_size_mb = 1400
        mgr._info.block_count = 28
        mgr._info.context_window = 4096

        # Safe VRAM budget is only 800 MB (can only fit ~8 layers of 50MB each)
        hw = HardwareProfile(
            os_name="Windows",
            os_version="11",
            cpu=CPUInfo(brand="AMD", physical_cores=6, logical_cores=12, utilization_percent=10.0),
            memory=SystemMemoryInfo(total_ram_mb=16000, available_ram_mb=10000, used_ram_mb=6000, percent_used=37.5),
            storage=StorageInfo(drive_path="C:\\", total_gb=500.0, free_gb=100.0, used_gb=400.0),
            recommended_max_vram_mb=800,
            has_nvidia_gpu=True,
            frameworks=FrameworkSupport(llama_cpp_cuda_supported=True),
        )

        strategy = mgr.calculate_offload_strategy(hardware=hw)
        assert strategy["safe_to_load"] is True
        # Must be capped to safe layers, NEVER 100 or 28!
        assert strategy["gpu_layers"] <= 10
        assert strategy["gpu_layers"] < 28

    def test_repeated_model_reload_without_deadlock(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())

        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        mgr = ModelManager(config=cfg, engine=fake_engine)
        mgr.inspect_configured_model()

        # Load initially
        assert mgr.load_model() is True
        assert fake_engine.is_loaded() is True
        assert fake_engine.load_call_count == 1

        # Reload with force=True 5 times consecutively
        for _ in range(5):
            assert mgr.load_model(force=True) is True
            assert fake_engine.is_loaded() is True

        assert fake_engine.load_call_count == 6
