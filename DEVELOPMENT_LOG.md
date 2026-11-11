# Tsukiko Development Log

## Phase 1: Foundation (Initial Build: 2026-11-11 | Audit & Repair: 2026-11-11)

### Status: Complete, Audited & Verified

---

### Audit & Defect Repair Ledger (2026-11-11)

An in-depth engineering audit was conducted on the Phase 1 codebase, identifying 10 defects that were investigated, repaired, and confirmed via 16 regression tests.

| Defect # | Component | Root Cause | Resolution | Regression Test |
|---|---|---|---|---|
| **1** | `app/main.py` | `Any` referenced in `handle_exit` without import from `typing`. | Added `from typing import Any` and safe signal wrapping. | `tests/test_entrypoint.py::test_main_module_exports_and_imports` |
| **2** | `app/core/orchestrator/engine.py` | Standard `threading.Lock()` caused reentrant deadlock when `start()` called `initialize()`. | Migrated to `threading.RLock()` and added idempotent state guards. | `tests/test_entrypoint.py::test_orchestrator_direct_start_reentrancy` |
| **3** | `app/core/config/settings.py` | `PrivacyConfig.validate_local_only()` had `pass` with no assertion. | Added strict `ValidationError` if `local_only=False`, `allow_external_telemetry=True`, or `allow_cloud_fallback=True`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **4** | `app/core/resource_manager/hardware.py` | Hardware inspection only checked `torch.cuda` rather than target runtime `llama.cpp`. | Implemented `check_framework_compatibility()` inspecting `llama_cpp`, `torch`, and `onnxruntime` distinctly. | `tests/test_hardware.py::test_framework_compatibility_distinguishes_llama_cpp_and_torch` |
| **5** | `tests/conftest.py` | Fixture `clean_env` failed to restore mutated environment variable values across tests. | Updated fixture to snapshot and fully restore `os.environ` and call `reset_config()`. | `tests/test_config.py::test_env_restoration_fixture_behavior` |
| **6** | `app/core/logging/logger.py` | Logging initialization did not reconfigure if destination directory changed, causing log contamination. | Replaced static boolean with directory tracking, clean handler re-routing, and `get_current_log_dir()`. | `tests/test_logging.py::test_logging_reconfiguration_different_destinations` |
| **7** | `app/core/config/settings.py` | Env overrides set raw strings into configuration dictionary without parsing booleans/numbers. | Implemented `_parse_env_value()` converting `true`/`false`/`1`/`0`/integers/floats. | `tests/test_config.py::test_config_env_variable_overrides_types` |
| **8** | `app/core/resource_manager/hardware.py` | `nvidia-smi` CSV parser crashed on `[N/A]`, `[Not Supported]`, or malformed non-numeric rows. | Implemented `_safe_parse_int()` and `_safe_parse_float()` with fallback defaults. | `tests/test_hardware.py::test_nvidia_smi_parsing_handles_missing_and_unexpected_metrics` |
| **9** | `app/core/resource_manager/hardware.py` | VRAM budget claimed model fits solely based on file size, ignoring KV cache and runtime overhead. | Implemented `estimate_model_vram_footprint()` adding KV cache (+450MB) and CUDA buffers (+500MB). | `tests/test_hardware.py::test_model_vram_estimation_accounts_for_kv_cache_and_overhead` |
| **10** | `app/main.py` | Qt application shutdown did not cleanly terminate the orchestrator lifecycle. | Connected `qt_app.aboutToQuit` directly to `orchestrator.stop` and added graceful headless fallback. | `tests/test_entrypoint.py::test_orchestrator_lifecycle` |

---

### Implementation Status Matrix

| Subsystem / Feature | Classification | Notes |
|---|---|---|
| Workstation Hardware Profiler | **Implemented & Tested** | Queries AMD Ryzen CPU, RAM, RTX 3050 VRAM, and storage with safe fallbacks. |
| Model Memory Footprint Estimator | **Implemented & Tested** | Accurately factors in GGUF weight size, context KV cache, and runtime overhead. |
| Pydantic Settings & YAML Loader | **Implemented & Tested** | Type-safe configuration with typed environment variable overrides. |
| Strict Privacy Contract | **Implemented & Tested** | Enforces zero telemetry, zero cloud fallback, and offline local-only operation. |
| Structured Logging (Console/JSONL) | **Implemented & Tested** | Thread-safe, rotating, color-coded, reconfigurable log system with Windows file unlock. |
| Orchestrator Composition Root | **Implemented & Tested** | Thread-safe reentrant lifecycle management (`initialize`, `start`, `stop`). |
| CLI Interface | **Implemented & Tested** | Flags `--version`, `--help`, `--check-hardware`, `--headless`, `--log-level`. |
| Automated Pytest Test Suite | **Implemented & Tested** | 16 unit and regression tests passing in 1.44s. |
| PySide6 Desktop Companion UI | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting approval. |
| llama.cpp Local Brain Engine | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No models downloaded yet. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
