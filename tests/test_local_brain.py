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

    def test_proactive_prompt_includes_stage_isolated_personality(self) -> None:
        """Verifies that proactive initiative prompts include Tsukiko's personality and respect disclosure stages."""
        from app.core.personality.initiative import ConversationalInitiativeEngine, SILENCE_TOKEN
        from app.core.personality.disclosure import DisclosureStage

        engine = ConversationalInitiativeEngine()

        # 1. ACQUAINTANCE Stage:
        acq_msgs = engine.build_initiative_prompt(
            session_history=[],
            stage=DisclosureStage.ACQUAINTANCE,
        )
        assert len(acq_msgs) >= 2
        acq_system = acq_msgs[0]["content"]

        # Must include Tsukiko's personality and authentic traits
        assert "Tsukiko" in acq_system
        assert "independent" in acq_system
        assert "gentle" in acq_system
        assert "cheerful" in acq_system
        assert "stubborn" in acq_system
        assert "proud" in acq_system
        assert SILENCE_TOKEN in acq_system
        assert "No Hollow Greetings" in acq_system

        # Strictly ZERO leaks of restricted Sayo history in Acquaintance stage
        restricted_words = [
            "sayo", "佐代", "1814", "1846", "shirakawa", "ogimachi",
            "silkworm", "atlas", "mamushi", "viper", "snake", "bite", "fever", "death", "died",
        ]
        acq_lower = acq_system.lower()
        for restricted in restricted_words:
            assert restricted not in acq_lower, f"Restricted word '{restricted}' leaked in ACQUAINTANCE proactive prompt!"

        # 2. FAMILIAR Stage:
        fam_msgs = engine.build_initiative_prompt(
            session_history=[],
            stage=DisclosureStage.FAMILIAR,
        )
        fam_system = fam_msgs[0]["content"]
        fam_lower = fam_system.lower()
        assert "mountain" in fam_lower
        # Still strictly no birth name, snakebite, or death
        for restricted in ["sayo", "1814", "1846", "bite", "death", "died"]:
            assert restricted not in fam_lower, f"Restricted word '{restricted}' leaked in FAMILIAR proactive prompt!"

        # 3. TRUSTED Stage:
        trusted_msgs = engine.build_initiative_prompt(
            session_history=[],
            stage=DisclosureStage.TRUSTED,
        )
        trusted_system = trusted_msgs[0]["content"]
        trusted_lower = trusted_system.lower()
        assert "sayo" in trusted_lower
        assert "1814" in trusted_lower
        # Still strictly no snakebite or death
        for restricted in ["bite", "death", "died", "1846"]:
            assert restricted not in trusted_lower, f"Restricted word '{restricted}' leaked in TRUSTED proactive prompt!"

        # 4. CONFIDANT Stage:
        conf_msgs = engine.build_initiative_prompt(
            session_history=[],
            stage=DisclosureStage.CONFIDANT,
        )
        conf_system = conf_msgs[0]["content"]
        conf_lower = conf_system.lower()
        assert "sayo" in conf_lower
        assert "1846" in conf_lower
        assert "mamushi" in conf_lower

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

        # Fullscreen suppresses initiative
        from unittest.mock import patch
        from app.desktop.companion.fullscreen import FullscreenEvaluation
        fs_eval = FullscreenEvaluation(
            detection_available=True,
            is_fullscreen=True,
            safe_always_on_top=False,
            reason="Game is fullscreen",
        )
        safe_eval = FullscreenEvaluation(
            detection_available=True,
            is_fullscreen=False,
            safe_always_on_top=True,
            reason="Safe windowed desktop",
        )
        with patch.object(widget._fullscreen_detector, "evaluate_fullscreen", return_value=fs_eval):
            assert scheduler.check_initiative() is False

        # 4. Idle time requirement: immediately after user activity, suppressed
        brain.personality.initiative_engine.record_user_activity()
        assert scheduler.check_initiative() is False

        # Advance idle time artificially in engine
        brain.personality.initiative_engine._last_interaction_time = time.time() - 100.0
        brain.personality.initiative_engine._last_initiative_time = 0.0

        # 5. Check initiative launches background worker without freezing main thread (safe desktop)
        with patch.object(widget._fullscreen_detector, "evaluate_fullscreen", return_value=safe_eval):
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
# 12. Scheduler Lifecycle, Deterministic Shutdown, and QThread Safety Tests
# ==============================================================================

@pytest.mark.skipif(not HAS_PYSIDE6, reason="PySide6 is required for UI tests")
class TestCompanionSchedulerShutdownLifecycle:
    """Verifies deterministic shutdown, cancellation, and QThread lifecycle invariants."""

    def test_shutdown_when_no_worker_exists(self, qapp: QApplication) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler
        scheduler = CompanionInitiativeScheduler(
            widget=None,
            main_window=None,
            brain=None,
            check_interval_ms=100,
        )
        assert scheduler.active_worker is None
        assert scheduler.is_running is False
        scheduler.start()
        assert scheduler.is_running is True

        res = scheduler.stop()
        assert res is True
        assert scheduler.is_running is False
        assert scheduler.is_stopped is True
        assert scheduler.active_worker is None

    def test_shutdown_while_worker_running(self, qapp: QApplication, tmp_path: Path) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler, ProactiveInitiativeWorker

        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()
        brain.model_manager.load_model()

        cancel_called = []
        orig_cancel = brain.cancel_generation

        def tracking_cancel() -> None:
            cancel_called.append(True)
            orig_cancel()

        brain.cancel_generation = tracking_cancel

        scheduler = CompanionInitiativeScheduler(brain=brain, check_interval_ms=100)
        worker = ProactiveInitiativeWorker(brain=brain, parent=None)
        scheduler._active_worker = worker
        worker.start()

        res = scheduler.stop(wait_timeout_ms=3000)
        assert res is True
        assert scheduler.is_running is False
        assert scheduler.active_worker is None
        assert len(cancel_called) >= 1
        assert worker.is_aborted is True

    def test_worker_taking_longer_than_timeout(self, qapp: QApplication) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler, ProactiveInitiativeWorker
        import time

        class SlowWorker(ProactiveInitiativeWorker):
            def run(self) -> None:
                for _ in range(15):
                    if self.is_aborted:
                        # Continue slightly to simulate heavy work taking longer than wait timeout
                        time.sleep(0.04)
                    else:
                        time.sleep(0.02)

        brain = MagicMock()
        scheduler = CompanionInitiativeScheduler(brain=brain, check_interval_ms=100)
        slow_worker = SlowWorker(brain=brain, parent=None)
        scheduler._active_worker = slow_worker
        slow_worker.start()

        # Stop with short timeout so worker outlives wait
        res = scheduler.stop(wait_timeout_ms=50)
        assert res is False
        # Worker reference MUST be retained safely while running
        assert scheduler.active_worker is slow_worker
        assert slow_worker in scheduler.retained_workers
        assert slow_worker.is_aborted is True

        # Now wait for it to naturally finish
        slow_worker.wait(3000)
        qapp.processEvents()

        # After finishing, reference is cleaned up
        assert scheduler.active_worker is None
        assert slow_worker not in scheduler.retained_workers

    def test_timer_stopped_after_shutdown(self, qapp: QApplication) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler
        scheduler = CompanionInitiativeScheduler(brain=None, check_interval_ms=50)
        scheduler.start()
        assert scheduler.is_running is True
        assert scheduler._timer.isActive() is True

        scheduler.stop()
        assert scheduler.is_running is False
        assert scheduler._timer.isActive() is False
        assert scheduler.is_stopped is True

        # Calling check_initiative after stop returns False immediately
        assert scheduler.check_initiative() is False

    def test_worker_reference_retained_until_safe_cleanup(self, qapp: QApplication) -> None:
        from app.desktop.companion.scheduler import (
            CompanionInitiativeScheduler,
            ProactiveInitiativeWorker,
            _LIVING_WORKERS,
        )
        import time

        class RetainedWorker(ProactiveInitiativeWorker):
            def run(self) -> None:
                time.sleep(0.2)

        brain = MagicMock()
        scheduler = CompanionInitiativeScheduler(brain=brain)
        worker = RetainedWorker(brain=brain, parent=None)
        scheduler._active_worker = worker
        _LIVING_WORKERS.add(worker)
        worker.start()

        # Stop with short timeout
        scheduler.stop(wait_timeout_ms=20)
        # Worker is still running; references must be retained
        assert worker.isRunning() is True
        assert scheduler.active_worker is worker
        assert worker in scheduler.retained_workers
        assert worker in _LIVING_WORKERS

        # Wait for natural exit
        worker.wait(2000)
        qapp.processEvents()

        # Safe cleanup should have cleared references
        assert scheduler.active_worker is None
        assert worker not in scheduler.retained_workers
        assert worker not in _LIVING_WORKERS

    def test_repeated_shutdown_calls(self, qapp: QApplication) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler
        scheduler = CompanionInitiativeScheduler(brain=None, check_interval_ms=100)
        scheduler.start()

        # Call stop() multiple times consecutively
        for _ in range(5):
            res = scheduler.stop()
            assert res is True
            assert scheduler.is_running is False
            assert scheduler.is_stopped is True

    def test_qapplication_exit_with_active_proactive_worker(self, qapp: QApplication) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler, ProactiveInitiativeWorker
        import time

        class ActiveWorker(ProactiveInitiativeWorker):
            def run(self) -> None:
                for _ in range(30):
                    if self.is_aborted:
                        break
                    time.sleep(0.01)

        brain = MagicMock()
        scheduler = CompanionInitiativeScheduler(brain=brain)
        worker = ActiveWorker(brain=brain, parent=None)
        scheduler._active_worker = worker
        worker.start()

        # Connect to aboutToQuit signal as in launch_companion
        qapp.aboutToQuit.connect(scheduler.stop)
        try:
            qapp.aboutToQuit.emit()
            qapp.processEvents()

            assert scheduler.is_stopped is True
            assert worker.is_aborted is True
            worker.wait(2000)
            assert scheduler.active_worker is None
        finally:
            try:
                qapp.aboutToQuit.disconnect(scheduler.stop)
            except Exception:
                pass

    def test_no_qthread_destroyed_while_running_condition(self, qapp: QApplication, capsys: Any) -> None:
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler, ProactiveInitiativeWorker
        import gc
        import time

        class MonitoredWorker(ProactiveInitiativeWorker):
            def run(self) -> None:
                for _ in range(20):
                    if self.is_aborted:
                        break
                    time.sleep(0.01)

        brain = MagicMock()
        scheduler = CompanionInitiativeScheduler(brain=brain)
        worker = MonitoredWorker(brain=brain, parent=None)
        scheduler._active_worker = worker
        worker.start()

        scheduler.stop(wait_timeout_ms=1000)
        gc.collect()
        qapp.processEvents()

        captured = capsys.readouterr()
        assert "QThread: Destroyed while thread is still running" not in captured.err
        assert "QThread: Destroyed while thread is still running" not in captured.out

    def test_coordinated_shutdown_order(self) -> None:
        from app.core.orchestrator.engine import TsukikoOrchestrator
        order = []

        class MockScheduler:
            def __init__(self) -> None:
                self.has_running_workers = False

            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                order.append("scheduler")
                return True

        class MockBrain:
            def __init__(self) -> None:
                self.is_generating = False

            def shutdown(self, timeout_seconds: float = 1.0) -> bool:
                order.append("brain")
                return True

            def complete_deferred_shutdown(self) -> bool:
                return True

        orch = TsukikoOrchestrator()
        orch.brain = MockBrain()  # type: ignore[assignment]
        orch.initiative_scheduler = MockScheduler()
        orch._is_running = True
        orch._status["state"] = "running"

        orch.stop()
        assert order == ["scheduler", "brain"]
        assert orch.is_running is False
        assert orch._status["state"] == "stopped"

    def test_cancellation_during_simulated_slow_inference(self, tmp_path: Path) -> None:
        """Verifies cancellation responsiveness during slow streaming token generation."""
        import re
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="A very long story " * 30)
        fake_engine.token_delay_seconds = 0.08
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()
        brain.model_manager.load_model()

        received_chunks: List[str] = []

        def consume() -> None:
            for chunk in brain.stream_response("Tell me a story."):
                received_chunks.append(chunk)

        gen_thread = threading.Thread(target=consume)
        gen_thread.start()

        # Wait until generation has started and emitted at least one chunk
        deadline = time.time() + 2.0
        while time.time() < deadline and len(received_chunks) == 0:
            time.sleep(0.01)

        assert len(received_chunks) >= 1
        assert brain.is_generating is True

        # Cancel generation
        brain.cancel_generation()
        gen_thread.join(timeout=2.0)
        assert not gen_thread.is_alive()
        assert brain.is_generating is False

        # Verify generation halted without producing full canned response
        full_chunks = re.findall(r"\S+\s*|\s+", fake_engine._canned_response)
        assert len(received_chunks) < len(full_chunks)

    def test_orchestrator_behavior_when_scheduler_stop_returns_false(self, tmp_path: Path) -> None:
        """Verifies orchestrator enters deferred stopping state rather than destroying models over active inference."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class StubSlowScheduler:
            def __init__(self) -> None:
                self.has_running_workers = True
                self.deferred_cb = None

            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return False

            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                self.deferred_cb = cb

        slow_sched = StubSlowScheduler()
        orch.initiative_scheduler = slow_sched

        # Stop orchestrator with bounded timeout
        res = orch.stop(timeout_seconds=0.05)
        # Must return False because scheduler was not clean
        assert res is False
        # State transitions to "stopping" (deferred)
        assert orch.get_status()["state"] == "stopping"
        # Model remains loaded and protected while worker is executing
        assert orch.brain.model_manager.info.is_loaded is True
        assert fake_engine.is_loaded() is True
        assert slow_sched.deferred_cb is not None

    def test_brain_shutdown_never_races_active_inference(self, tmp_path: Path) -> None:
        """Verifies that brain.shutdown() refuses immediate model unload while inference is actively executing."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        fake_engine.token_delay_seconds = 0.05
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()
        brain.model_manager.load_model()

        # Start background generation that will continue for ~1 second unless cancelled
        gen_thread = threading.Thread(
            target=lambda: list(brain.stream_response("Please explain moonlight."))
        )
        gen_thread.start()

        # Wait until generation is actively in flight
        deadline = time.time() + 2.0
        while time.time() < deadline and not brain.is_generating:
            time.sleep(0.01)

        assert brain.is_generating is True

        # Attempt immediate shutdown with 0 timeout while inference is in flight
        res = brain.shutdown(timeout_seconds=0.0)
        # Must refuse immediate model unload while inference is running
        assert res is False
        assert brain.model_manager.info.is_loaded is True
        assert fake_engine.is_loaded() is True

        # Await thread cleanup (shutdown requested cancellation)
        gen_thread.join(timeout=2.0)
        assert brain.is_generating is False

        # Deferred completion now unloads safely
        assert brain.complete_deferred_shutdown() is True
        assert brain.model_manager.info.is_loaded is False
        assert fake_engine.is_loaded() is False

    def test_deferred_shutdown_completion_after_worker_exit(self, qapp: QApplication, tmp_path: Path) -> None:
        """Verifies deferred shutdown automatically completes once delayed workers finish."""
        from app.desktop.companion.scheduler import CompanionInitiativeScheduler, ProactiveInitiativeWorker
        import time

        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        scheduler = CompanionInitiativeScheduler(brain=orch.brain, check_interval_ms=100)
        orch.initiative_scheduler = scheduler

        class DelayedWorker(ProactiveInitiativeWorker):
            def run(self) -> None:
                time.sleep(0.2)

        worker = DelayedWorker(brain=orch.brain, parent=None)
        scheduler._active_worker = worker
        worker.start()

        # Stop with short 30ms timeout: worker will outlive it
        res = orch.stop(timeout_seconds=0.03)
        assert res is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True

        # Now wait for worker thread to naturally complete
        worker.wait(2000)
        qapp.processEvents()

        # Deferred shutdown hook will have executed cleanly
        assert orch.get_status()["state"] == "stopped"
        assert orch.brain.model_manager.info.is_loaded is False
        assert fake_engine.is_loaded() is False
        assert scheduler.active_worker is None

    def test_repeated_shutdown_requests_during_deferred_shutdown(self, tmp_path: Path) -> None:
        """Verifies that calling stop() repeatedly during deferred shutdown is idempotent and safe."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        orch = TsukikoOrchestrator(config=cfg)
        orch.initialize()
        orch._is_running = True
        orch._status["state"] = "running"

        class DummyScheduler:
            def __init__(self) -> None:
                self.has_running_workers = True
                self.calls = 0

            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                self.calls += 1
                return False

            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = DummyScheduler()

        # Call stop 5 times in a row while worker is running
        for _ in range(5):
            res = orch.stop(timeout_seconds=0.01)
            assert res is False
            assert orch.get_status()["state"] == "stopping"

        # Now worker completes
        orch.initiative_scheduler.has_running_workers = False
        res = orch.stop(timeout_seconds=0.01)
        assert res is True
        assert orch.get_status()["state"] == "stopped"

        # Calling again when already stopped returns True idempotently
        assert orch.stop() is True
        assert orch.get_status()["state"] == "stopped"

    def test_deterministic_delayed_cancellation_path(self, qapp: QApplication, tmp_path: Path) -> None:
        """Verifies that cancellation arriving mid-inference aborts worker cleanly without signal emissions."""
        from app.desktop.companion.scheduler import ProactiveInitiativeWorker

        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="Quiet afternoon remark with slow generation " * 10)
        fake_engine.token_delay_seconds = 0.08
        brain = TsukikoBrain(config=cfg, engine=fake_engine)
        brain.initialize()
        brain.model_manager.load_model()
        # Set idle time so conversational initiative is permitted
        brain.personality.initiative_engine._last_interaction_time = time.time() - 100.0
        brain.personality.initiative_engine._last_initiative_time = 0.0

        worker = ProactiveInitiativeWorker(brain=brain, parent=None)
        signals_received: List[Any] = []
        worker.initiative_ready.connect(lambda s: signals_received.append(("ready", s)))
        worker.initiative_silent.connect(lambda: signals_received.append(("silent",)))
        worker.error_occurred.connect(lambda e: signals_received.append(("error", e)))

        worker.start()

        # Wait briefly for worker to enter generation
        deadline = time.time() + 2.0
        while time.time() < deadline and not brain.is_generating:
            time.sleep(0.01)

        assert worker.isRunning() is True
        assert brain.is_generating is True

        # Cancel worker mid-generation
        worker.abort()
        assert worker.is_aborted is True

        # Wait for worker thread to finish
        worker.wait(3000)
        qapp.processEvents()

        assert worker.isFinished() is True
        # Signals must be suppressed when aborted
        assert len(signals_received) == 0
        assert brain.is_generating is False

    def test_normal_chat_generation_active_defers_orchestrator_shutdown(self, tmp_path: Path) -> None:
        """Verifies that active normal chat generation defers orchestrator shutdown even when scheduler has no workers."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="A lengthy answer " * 30)
        fake_engine.token_delay_seconds = 0.08
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class IdleScheduler:
            def __init__(self) -> None:
                self.has_running_workers = False
                self.deferred_cb = None

            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True

            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                self.deferred_cb = cb

        idle_sched = IdleScheduler()
        orch.initiative_scheduler = idle_sched

        received: List[str] = []
        gen_thread = threading.Thread(
            target=lambda: [received.append(c) for c in orch.brain.stream_response("Tell me a story.")]
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert orch.brain.is_generating is True
        assert idle_sched.has_running_workers is False

        # Attempt to stop orchestrator
        res = orch.stop(timeout_seconds=0.03)

        # Must NOT mark itself stopped because brain is still generating!
        assert res is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True
        assert fake_engine.is_loaded() is True

        gen_thread.join(timeout=3.0)
        assert orch.brain.is_generating is False

        # Now deferred shutdown completes cleanly
        completed = orch.complete_deferred_shutdown()
        assert completed is True
        assert orch.get_status()["state"] == "stopped"
        assert orch.brain.model_manager.info.is_loaded is False
        assert fake_engine.is_loaded() is False

    def test_scheduler_callback_during_chat_generation_does_not_stop_orchestrator(self, tmp_path: Path) -> None:
        """Verifies that invoking scheduler deferred callback while chat is generating refuses to stop orchestrator."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="Another quiet response " * 20)
        fake_engine.token_delay_seconds = 0.08
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class CallbackScheduler:
            def __init__(self) -> None:
                self.has_running_workers = False
                self.callback = None

            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True

            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                self.callback = cb
                if cb:
                    cb()

        sched = CallbackScheduler()
        orch.initiative_scheduler = sched

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Explain the night sky."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert orch.brain.is_generating is True

        res = orch.stop(timeout_seconds=0.03)
        assert res is False
        assert orch.get_status()["state"] == "stopping"

        # Explicitly invoke complete_deferred_shutdown while generation is active
        res2 = orch.complete_deferred_shutdown()
        assert res2 is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True

        gen_thread.join(timeout=3.0)
        assert orch.brain.is_generating is False

        # Once finished, complete_deferred_shutdown succeeds
        assert orch.complete_deferred_shutdown() is True
        assert orch.get_status()["state"] == "stopped"
        assert orch.brain.model_manager.info.is_loaded is False

    def test_immediate_brain_shutdown_refusal_enters_deferred_stopping(self) -> None:
        """Verifies orchestrator enters deferred stopping when brain.shutdown refuses immediate unload."""
        orch = TsukikoOrchestrator()
        orch._is_running = True
        orch._status["state"] = "running"

        class StubBrainRefusingImmediate:
            def __init__(self) -> None:
                self.is_generating = False
                self.shut_called = False
                self.deferred_called = False

            def cancel_generation(self) -> None:
                pass

            def shutdown(self, timeout_seconds: float = 0.0) -> bool:
                self.shut_called = True
                return False

            def complete_deferred_shutdown(self) -> bool:
                self.deferred_called = True
                return True

        orch.brain = StubBrainRefusingImmediate()  # type: ignore[assignment]

        class StubCleanScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = StubCleanScheduler()

        res = orch.stop(timeout_seconds=0.0)
        assert res is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.shut_called is True

        assert orch.complete_deferred_shutdown() is True
        assert orch.get_status()["state"] == "stopped"
        assert orch.brain.deferred_called is True

    def test_deferred_shutdown_retried_and_completes_after_chat_finishes(self, tmp_path: Path) -> None:
        """Verifies orchestrator background watcher automatically completes deferred shutdown when chat finishes."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine(canned_response="Gentle rain on moss. " * 15)
        fake_engine.token_delay_seconds = 0.05
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Describe the rain."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert orch.brain.is_generating is True

        res = orch.stop(timeout_seconds=0.02)
        assert res is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True

        gen_thread.join(timeout=3.0)
        assert orch.brain.is_generating is False

        # Wait briefly for background watcher to complete deferred shutdown
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.05)

        assert orch.get_status()["state"] == "stopped"
        assert orch.brain.model_manager.info.is_loaded is False
        assert fake_engine.is_loaded() is False

    def test_deferred_shutdown_continues_beyond_previous_fifteen_second_deadline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verifies deferred shutdown is monitored indefinitely without a 15-second deadline abandoning it."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()

        chat_unblock = threading.Event()

        def controlled_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "Starting token "
            chat_unblock.wait()
            yield "Closing token."

        fake_engine.stream_chat = controlled_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("A very long conversation."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert orch.brain.is_generating is True

        # Stop orchestrator with short timeout
        res = orch.stop(timeout_seconds=0.02)
        assert res is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True
        assert fake_engine.is_loaded() is True
        assert orch._deferred_watcher_thread is not None
        assert orch._deferred_watcher_thread.is_alive() is True

        # Advance simulated time by 30 seconds (far beyond the previous 15.0s watcher deadline)
        real_time = time.time
        simulated_time = real_time() + 30.0
        monkeypatch.setattr(time, "time", lambda: simulated_time)

        # Allow watcher thread several cycles under the advanced time
        time.sleep(0.1)

        # In the old code, watcher would have exited after 15s. In the new code, watcher MUST still be alive!
        assert orch._deferred_watcher_thread.is_alive() is True
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True
        assert fake_engine.is_loaded() is True

        # Now allow chat inference to finish
        chat_unblock.set()
        gen_thread.join(timeout=3.0)
        assert orch.brain.is_generating is False

        # Wait briefly for deferred shutdown completion
        wait_deadline = real_time() + 3.0
        while real_time() < wait_deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        # Orchestrator automatically reaches stopped
        assert orch.get_status()["state"] == "stopped"
        # Model weights are cleanly unloaded
        assert orch.brain.model_manager.info.is_loaded is False
        assert fake_engine.is_loaded() is False
        # Watcher thread cleanly terminates
        orch._deferred_watcher_thread.join(timeout=1.0)
        assert orch._deferred_watcher_thread.is_alive() is False

    def test_brain_shutdown_failure_does_not_produce_false_stopped_state(self, tmp_path: Path) -> None:
        """Verifies brain shutdown failure keeps orchestrator in stopping state and never marks stopped."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()

        # Brain whose complete_deferred_shutdown initially fails
        should_succeed = False
        orig_complete = orch.brain.complete_deferred_shutdown

        def failing_complete() -> bool:
            if not should_succeed:
                return False
            return orig_complete()

        orch.brain.complete_deferred_shutdown = failing_complete
        orch.brain.shutdown = lambda timeout_seconds=0.0: False

        # Start stop path: immediate shutdown fails, transitions to stopping, watcher starts
        res = orch.stop(timeout_seconds=0.02)
        assert res is False
        assert orch.get_status()["state"] == "stopping"

        # Calling complete_deferred_shutdown must fail
        assert orch.complete_deferred_shutdown() is False
        assert orch.get_status()["state"] == "stopping"
        assert orch.brain.model_manager.info.is_loaded is True
        assert fake_engine.is_loaded() is True
        assert orch._deferred_watcher_thread.is_alive() is True

        # Now allow brain shutdown to succeed
        should_succeed = True
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        assert orch.brain.model_manager.info.is_loaded is False
        assert fake_engine.is_loaded() is False
        orch._deferred_watcher_thread.join(timeout=1.0)
        assert orch._deferred_watcher_thread.is_alive() is False

    def test_repeated_shutdown_calls_do_not_create_duplicate_watchers(self, tmp_path: Path) -> None:
        """Verifies calling stop() repeatedly during deferred shutdown reuses the single watcher thread."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "holding "
            chat_hold.wait()
            yield "done."

        fake_engine.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Long chat."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        # Trigger stop -> enters stopping, starts watcher
        res = orch.stop(timeout_seconds=0.01)
        assert res is False
        assert orch.get_status()["state"] == "stopping"

        watcher_thread = orch._deferred_watcher_thread
        assert watcher_thread is not None
        assert watcher_thread.is_alive() is True

        # Call stop() 5 times while still generating
        for _ in range(5):
            res_repeat = orch.stop(timeout_seconds=0.01)
            assert res_repeat is False
            assert orch.get_status()["state"] == "stopping"
            assert orch._deferred_watcher_thread is watcher_thread

        # Call _start_deferred_shutdown_watcher directly
        orch._start_deferred_shutdown_watcher()
        assert orch._deferred_watcher_thread is watcher_thread

        # Release chat
        chat_hold.set()
        gen_thread.join(timeout=3.0)

        # Wait for watcher to finish
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        watcher_thread.join(timeout=1.0)
        assert watcher_thread.is_alive() is False

    def test_successful_shutdown_terminates_watcher(self, tmp_path: Path) -> None:
        """Verifies the watcher thread cleanly halts upon successful deferred shutdown."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        fake_engine = DeterministicFakeEngine()
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(fake_engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb: Any) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()

        chat_hold = threading.Event()

        def quick_hold_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "token "
            chat_hold.wait()
            yield "end."

        fake_engine.stream_chat = quick_hold_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Quick hold."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        orch.stop(timeout_seconds=0.01)
        assert orch.get_status()["state"] == "stopping"
        watcher = orch._deferred_watcher_thread
        assert watcher is not None
        assert watcher.is_alive() is True

        # Release chat and let completion happen
        chat_hold.set()
        gen_thread.join(timeout=3.0)

        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        watcher.join(timeout=1.0)
        assert watcher.is_alive() is False


# ==============================================================================
# 13a. Generation-Completion Callback Ordering Tests
# ==============================================================================

class TestGenerationCompletionCallbackOrdering:
    """Verifies that brain-level completion notifications fire only AFTER
    all history processing, preventing premature shutdown from clearing or
    racing with history updates."""

    def _make_orch(self, tmp_path: Path, engine: DeterministicFakeEngine) -> TsukikoOrchestrator:
        """Helper: creates a loaded, running orchestrator with an empty scheduler."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()
        return orch

    # ------------------------------------------------------------------ #
    # 1. Normal chat: callback fires only after history processing
    # ------------------------------------------------------------------ #
    def test_chat_callback_fires_after_history_append(self, tmp_path: Path) -> None:
        """Completion callback must observe fully-populated history."""
        fake = DeterministicFakeEngine(canned_response="Hello world")
        orch = self._make_orch(tmp_path, fake)

        callback_history_lens: List[int] = []

        def capture_history_len() -> None:
            callback_history_lens.append(len(orch.brain.get_history()))

        orch.brain.register_generation_finished_callback(capture_history_len)

        # Drive generation to completion
        list(orch.brain.stream_response("Hi"))

        assert len(callback_history_lens) == 1, "Exactly one callback expected"
        assert callback_history_lens[0] == 2, "Callback must see user+assistant turns in history"
        assert len(orch.brain.get_history()) == 2

    # ------------------------------------------------------------------ #
    # 2. Proactive initiative: callback fires only after remark in history
    # ------------------------------------------------------------------ #
    def test_initiative_callback_fires_after_remark_in_history(self, tmp_path: Path) -> None:
        """Proactive initiative completion callback must see the remark in history."""
        fake = DeterministicFakeEngine(canned_response="The evening breeze carries cherry blossoms.")
        orch = self._make_orch(tmp_path, fake)

        callback_history_lens: List[int] = []

        def capture_history_len() -> None:
            callback_history_lens.append(len(orch.brain.get_history()))

        orch.brain.register_generation_finished_callback(capture_history_len)

        # Mark enough activity to allow initiative
        engine = orch.brain.personality.initiative_engine
        engine._is_enabled = True
        engine._last_user_activity_time = time.time() - 300
        engine._last_initiative_time = 0
        engine._consecutive_unanswered = 0

        result = orch.brain.check_conversational_initiative(current_time=time.time() + 500.0)
        assert result is not None

        assert len(callback_history_lens) == 1, "Exactly one callback expected"
        assert callback_history_lens[0] >= 1, "Callback must see the remark already in history"

    # ------------------------------------------------------------------ #
    # 3. During deferred shutdown, model stays loaded until brain finishes
    # ------------------------------------------------------------------ #
    def test_model_stays_loaded_until_brain_operation_finishes(self, tmp_path: Path) -> None:
        """Model weights must not be unloaded while brain-level history processing is active."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "token "
            chat_hold.wait()
            yield "done."

        fake.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Hold."))
        )
        gen_thread.start()

        # Wait for brain to be generating
        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)
        assert orch.brain.is_generating is True

        # Trigger deferred shutdown
        res = orch.stop(timeout_seconds=0.01)
        assert res is False
        assert orch.get_status()["state"] == "stopping"

        # Model MUST still be loaded while brain is processing
        assert orch.brain.model_manager.info.is_loaded is True
        assert fake.is_loaded() is True

        # Release generation
        chat_hold.set()
        gen_thread.join(timeout=3.0)

        # Wait for auto-completion
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        assert fake.is_loaded() is False

    # ------------------------------------------------------------------ #
    # 4. After shutdown reaches stopped, history remains empty
    # ------------------------------------------------------------------ #
    def test_history_empty_after_shutdown_stopped(self, tmp_path: Path) -> None:
        """After deferred shutdown completes to 'stopped', conversation history
        must be empty and not repopulated by any late-arriving generator."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "word "
            chat_hold.wait()
            yield "end."

        fake.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Repopulation test."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        # Trigger stop
        orch.stop(timeout_seconds=0.01)
        assert orch.get_status()["state"] == "stopping"

        # Release chat and let generator finish
        chat_hold.set()
        gen_thread.join(timeout=3.0)

        # Wait for stopped
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"

        # History MUST be empty: shutdown cleared it after the brain finished
        assert orch.brain.get_history() == []

    # ------------------------------------------------------------------ #
    # 5. Joining generation thread after shutdown → no new history
    # ------------------------------------------------------------------ #
    def test_no_history_after_joining_generation_thread_post_shutdown(self, tmp_path: Path) -> None:
        """After shutdown and joining the generation thread, history stays empty."""
        fake = DeterministicFakeEngine(canned_response="Some tokens for history test.")
        orch = self._make_orch(tmp_path, fake)

        chat_hold = threading.Event()

        def delayed_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "tok1 "
            chat_hold.wait()
            yield "tok2."

        fake.stream_chat = delayed_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Post-shutdown join."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        # Trigger stop while generating
        orch.stop(timeout_seconds=0.01)
        assert orch.get_status()["state"] == "stopping"

        # Release and explicitly join the generation thread
        chat_hold.set()
        gen_thread.join(timeout=3.0)
        assert not gen_thread.is_alive()

        # Wait for shutdown completion
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        # Even after joining the generation thread, history is empty
        assert orch.brain.get_history() == []

    # ------------------------------------------------------------------ #
    # 6. Cancellation and exception still notify completion
    # ------------------------------------------------------------------ #
    def test_cancellation_still_notifies_completion(self, tmp_path: Path) -> None:
        """Cancelled generation must still fire the completion callback."""
        fake = DeterministicFakeEngine(canned_response="A " * 50)
        fake.token_delay_seconds = 0.1
        orch = self._make_orch(tmp_path, fake)

        notified = threading.Event()
        orch.brain.register_generation_finished_callback(notified.set)

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Cancel me."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        orch.brain.cancel_generation()
        gen_thread.join(timeout=3.0)

        assert notified.wait(timeout=2.0), "Callback must fire even on cancellation"

    def test_exception_during_generation_still_notifies_completion(self, tmp_path: Path) -> None:
        """Engine exception during generation must still fire the completion callback."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        notified = threading.Event()
        orch.brain.register_generation_finished_callback(notified.set)

        # Make the engine raise mid-stream
        def exploding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "partial "
            raise RuntimeError("Simulated engine failure")

        fake.stream_chat = exploding_stream

        # Consume the generator — it should propagate the exception but still notify
        with pytest.raises(RuntimeError, match="Simulated engine failure"):
            list(orch.brain.stream_response("Explode."))

        assert notified.wait(timeout=2.0), "Callback must fire even on exception"

    # ------------------------------------------------------------------ #
    # 7. Each operation produces exactly one notification
    # ------------------------------------------------------------------ #
    def test_exactly_one_notification_per_chat_operation(self, tmp_path: Path) -> None:
        """Normal chat generation must produce exactly one completion notification, not two."""
        fake = DeterministicFakeEngine(canned_response="Single notification test.")
        orch = self._make_orch(tmp_path, fake)

        count = {"n": 0}
        def increment() -> None:
            count["n"] += 1

        orch.brain.register_generation_finished_callback(increment)
        list(orch.brain.stream_response("Count check."))

        assert count["n"] == 1, f"Expected exactly 1 notification, got {count['n']}"

    def test_exactly_one_notification_per_initiative_operation(self, tmp_path: Path) -> None:
        """Proactive initiative must produce exactly one completion notification."""
        fake = DeterministicFakeEngine(canned_response="A quiet observation.")
        orch = self._make_orch(tmp_path, fake)

        count = {"n": 0}
        def increment() -> None:
            count["n"] += 1

        orch.brain.register_generation_finished_callback(increment)

        engine = orch.brain.personality.initiative_engine
        engine._is_enabled = True
        engine._last_user_activity_time = time.time() - 300
        engine._last_initiative_time = 0
        engine._consecutive_unanswered = 0

        orch.brain.check_conversational_initiative(current_time=time.time() + 500.0)

        assert count["n"] == 1, f"Expected exactly 1 notification, got {count['n']}"

    # ------------------------------------------------------------------ #
    # 8. Former 15s deadline test still passes (preserved regression)
    # ------------------------------------------------------------------ #
    # (covered by existing test_deferred_shutdown_continues_beyond_previous_fifteen_second_deadline)

    # ------------------------------------------------------------------ #
    # 9. brain_generating flag prevents premature shutdown during history append
    # ------------------------------------------------------------------ #
    def test_brain_generating_flag_prevents_premature_shutdown(self, tmp_path: Path) -> None:
        """While active_operations > 0, shutdown must be deferred even
        if the model-level generation has already finished."""
        fake = DeterministicFakeEngine(canned_response="Quick.")
        orch = self._make_orch(tmp_path, fake)

        # Intercept brain's stream_response to observe the active_operations lifecycle
        active_counts: List[int] = []
        orig_notify = orch.brain._notify_generation_finished

        def spy_notify() -> None:
            # At the moment notification fires, active_operations should already be 0
            active_counts.append(orch.brain.active_operations)
            orig_notify()

        orch.brain._notify_generation_finished = spy_notify

        list(orch.brain.stream_response("Flag lifecycle."))

        assert len(active_counts) == 1
        assert active_counts[0] == 0, "active_operations must be 0 when notification fires"
        assert orch.brain.active_operations == 0
        assert orch.brain.is_generating is False


# ==============================================================================
# 13b. Active Operation Concurrency and State Tracking Tests
# ==============================================================================

class TestActiveOperationConcurrencyAndStateTracking:
    """Verifies that active operation counter and prompt-preparation exception
    safety prevent concurrency races, state corruption, and premature shutdown."""

    def _make_orch(self, tmp_path: Path, engine: DeterministicFakeEngine) -> TsukikoOrchestrator:
        """Helper: creates a loaded, running orchestrator with an empty scheduler."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(create_synthetic_gguf_binary())
        cfg = TsukikoConfig()
        cfg.ai.model_path = str(model_file)
        orch = TsukikoOrchestrator(config=cfg)
        orch.brain.model_manager.set_engine(engine)
        orch.initialize()
        orch.brain.model_manager.load_model()
        orch._is_running = True
        orch._status["state"] = "running"

        class EmptyScheduler:
            has_running_workers = False
            def stop(self, wait_timeout_ms: int = 1000) -> bool:
                return True
            def set_deferred_shutdown_callback(self, cb) -> None:
                pass

        orch.initiative_scheduler = EmptyScheduler()
        return orch

    def test_chat_running_while_proactive_rejected_preserves_active_state(self, tmp_path: Path) -> None:
        """Proactive request rejected due to concurrent chat must not reset Chat A's active state."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "token1 "
            chat_hold.wait()
            yield "token2."

        fake.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Chat A ongoing."))
        )
        gen_thread.start()

        # Wait until Chat A is generating
        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert orch.brain.active_operations == 1
        assert orch.brain.is_generating is True

        # Now attempt proactive initiative B while Chat A is running
        result = orch.brain.check_conversational_initiative(current_time=time.time() + 500.0)

        # Proactive B must be rejected because ModelManager rejects concurrent generation
        assert result is None

        # CRITICAL: Chat A's active state must remain True and active_operations must still be 1!
        assert orch.brain.active_operations == 1
        assert orch.brain.is_generating is True
        assert fake.is_loaded() is True

        # Release Chat A
        chat_hold.set()
        gen_thread.join(timeout=3.0)

        assert orch.brain.active_operations == 0
        assert orch.brain.is_generating is False

    def test_chat_history_processing_cannot_race_with_deferred_shutdown(self, tmp_path: Path) -> None:
        """During Chat A's post-inference history processing, deferred shutdown cannot complete prematurely."""
        fake = DeterministicFakeEngine(canned_response="A thoughtful response.")
        orch = self._make_orch(tmp_path, fake)

        history_started = threading.Event()
        history_unblock = threading.Event()
        orig_clean = orch.brain.personality.clean_response

        def pausing_clean(raw: str) -> str:
            history_started.set()
            history_unblock.wait()
            return orig_clean(raw)

        orch.brain.personality.clean_response = pausing_clean

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Test history race."))
        )
        gen_thread.start()

        # Wait until history processing begins (tokens are already done yielding)
        assert history_started.wait(timeout=2.0)

        # ModelManager token generation has finished, but brain-level operation is still active!
        assert fake.is_generating() is False
        assert orch.brain.active_operations == 1
        assert orch.brain.is_generating is True

        # Orchestrator stop must NOT complete shutdown or clear history yet
        res = orch.stop(timeout_seconds=0.01)
        assert res is False
        assert orch.get_status()["state"] == "stopping"
        assert fake.is_loaded() is True
        assert orch.brain.model_manager.info.is_loaded is True

        # Release history processing
        history_unblock.set()
        gen_thread.join(timeout=3.0)

        # Wait for deferred watcher to complete shutdown
        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        assert fake.is_loaded() is False
        # Conversation history was cleanly cleared by shutdown and not repopulated
        assert orch.brain.get_history() == []

    def test_prompt_history_pruning_failure_releases_operation_tracking(self, tmp_path: Path) -> None:
        """Exception during history pruning in stream_response must release active operation count."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        def failing_prune(prompt: str, reserve_tokens_for_generation: int = 1024):
            raise RuntimeError("Injected pruning failure")

        orch.brain._prune_history_to_fit_context = failing_prune

        assert orch.brain.active_operations == 0
        with pytest.raises(RuntimeError, match="Injected pruning failure"):
            list(orch.brain.stream_response("Pruning test."))

        assert orch.brain.active_operations == 0
        assert orch.brain.is_generating is False

    def test_message_formatting_failure_releases_operation_tracking(self, tmp_path: Path) -> None:
        """Exception during message formatting in stream_response must release active operation count."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        def failing_format(history, user_text):
            raise RuntimeError("Injected format failure")

        orch.brain.personality.format_messages = failing_format

        assert orch.brain.active_operations == 0
        with pytest.raises(RuntimeError, match="Injected format failure"):
            list(orch.brain.stream_response("Format test."))

        assert orch.brain.active_operations == 0
        assert orch.brain.is_generating is False

    def test_proactive_prompt_construction_failure_releases_operation_tracking(self, tmp_path: Path) -> None:
        """Exception during initiative prompt construction must release active operation count."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        def failing_build_prompt(**kwargs):
            raise RuntimeError("Injected proactive prompt failure")

        orch.brain.personality.initiative_engine.build_initiative_prompt = failing_build_prompt

        assert orch.brain.active_operations == 0
        result = orch.brain.check_conversational_initiative(current_time=time.time() + 500.0)
        assert result is None

        assert orch.brain.active_operations == 0
        assert orch.brain.is_generating is False

    def test_multiple_rejected_requests_do_not_corrupt_active_operation_count(self, tmp_path: Path) -> None:
        """Multiple rejected concurrent requests must not decrement or corrupt active operation count."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "holding "
            chat_hold.wait()
            yield "done."

        fake.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Primary chat."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert orch.brain.active_operations == 1

        # Fire 5 rejected proactive calls
        for _ in range(5):
            res = orch.brain.check_conversational_initiative(current_time=time.time() + 500.0)
            assert res is None
            assert orch.brain.active_operations == 1

        # Fire 5 rejected chat calls
        def rejected_chat():
            try:
                list(orch.brain.stream_response("Concurrent attempt."))
            except RuntimeError:
                pass

        threads = [threading.Thread(target=rejected_chat) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Primary chat must still be unharmed with active_operations == 1
        assert orch.brain.active_operations == 1
        assert orch.brain.is_generating is True

        chat_hold.set()
        gen_thread.join(timeout=3.0)

        assert orch.brain.active_operations == 0
        assert orch.brain.is_generating is False

    def test_completion_listeners_called_only_after_all_operations_finish(self, tmp_path: Path) -> None:
        """Completion callbacks must not fire when a concurrent operation is rejected while another is active."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        callback_counts = {"n": 0}
        def count_callback():
            callback_counts["n"] += 1

        orch.brain.register_generation_finished_callback(count_callback)

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "token "
            chat_hold.wait()
            yield "end."

        fake.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Chat with listener."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        assert callback_counts["n"] == 0

        # Run proactive call that gets rejected
        res = orch.brain.check_conversational_initiative(current_time=time.time() + 500.0)
        assert res is None

        # Rejection must NOT trigger completion notification because Chat is still active!
        assert callback_counts["n"] == 0

        # Now finish Chat
        chat_hold.set()
        gen_thread.join(timeout=3.0)

        # Now exactly one notification must have fired
        assert callback_counts["n"] == 1

    def test_model_weights_remain_loaded_while_any_operation_is_active(self, tmp_path: Path) -> None:
        """Model weights cannot be unloaded via unload_model or stop while brain operation is active."""
        fake = DeterministicFakeEngine()
        orch = self._make_orch(tmp_path, fake)

        chat_hold = threading.Event()

        def holding_stream(messages, max_tokens=1024, temperature=0.7, top_p=0.9, repeat_penalty=1.1):
            yield "tok "
            chat_hold.wait()
            yield "fin."

        fake.stream_chat = holding_stream

        gen_thread = threading.Thread(
            target=lambda: list(orch.brain.stream_response("Weight safety test."))
        )
        gen_thread.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not orch.brain.is_generating:
            time.sleep(0.01)

        # Explicit unload_model must refuse
        unload_result = orch.brain.unload_model()
        assert unload_result is False
        assert fake.is_loaded() is True
        assert orch.brain.model_manager.info.is_loaded is True

        # Orchestrator stop must defer
        stop_result = orch.stop(timeout_seconds=0.01)
        assert stop_result is False
        assert orch.get_status()["state"] == "stopping"
        assert fake.is_loaded() is True

        chat_hold.set()
        gen_thread.join(timeout=3.0)

        deadline = time.time() + 3.0
        while time.time() < deadline and orch.get_status()["state"] != "stopped":
            time.sleep(0.02)

        assert orch.get_status()["state"] == "stopped"
        assert fake.is_loaded() is False


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
