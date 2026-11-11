# Tsukiko Development Log

## Phase 1: Foundation (Initial Build: 2026-11-11 | Audit & Repair: 2026-11-11 | Final Hardening: 2026-11-11)

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

### Final Security and Reliability Hardening Ledger (2026-11-11)

A third hardening cycle completed all remaining engineering corrections, expanding coverage to 37 passing unit, regression, packaging, and integration tests:

1. **Strict Offline Network Enforcement (`app/core/privacy/enforcement.py`):**
   * **Strict Allowlist**: Permits only IPv4 loopback (`127.0.0.0/8`), IPv6 loopback (`::1`), and loopback-resolved `localhost`.
   * **Unspecified Address Rejection**: Strictly rejects `0.0.0.0` and `::` (preventing interface-routing bypasses).
   * **Extended API Surface**: Hooked `socket.connect_ex`, `socket.sendto` (UDP datagrams), `socket.gethostbyname_ex`, `socket.gethostbyaddr`, and `socket.getnameinfo`. All unauthorized external calls raise `PrivacyViolationError`.
   * **Atomic Rollback & Persistent Lifecycle**: Added atomic rollback if hooking fails. Removed guard deactivation from orchestrator `stop()` so the process remains guarded for its entire lifetime.
2. **Windows Firewall Policy Strategy (`app/core/privacy/windows_firewall.py`):**
   * **Interpreter Safety Protection**: Prohibits creating Windows Firewall rules targeting shared Python interpreters (`python.exe`, `pythonw.exe`), preventing accidental disruption to workstation tooling.
   * **Dedicated Binary Integration**: Supports generating and managing rules targeting dedicated packaged binaries (`tsukiko.exe`).
   * **Honest Status Reporting**: Reports `in_process_only` when running in standard Python, `os_policy_not_configured` when binary lacks firewall rule, and `os_policy_active` when kernel-level rule is confirmed active.
3. **Fail-Safe VRAM Budgeting (`app/core/resource_manager/hardware.py` & `diagnostic.py`):**
   * Removed unsafe fallback `profile.recommended_max_vram_mb or 2800`.
   * Categorized GPU state into `budget_status`: `"measured"` (known positive free VRAM), `"zero_available"` (discrete GPU detected with 0MB free VRAM), and `"unavailable"` (no GPU or query failed).
   * Safe allocation budget is strictly 0 MB when VRAM is 0 or unavailable, automatically selecting CPU-only inference without crashing.
4. **Isolated Subprocess Deadlock Prevention Tests (`tests/test_entrypoint.py`):**
   * Replaced in-thread deadlock tests with subprocess execution under a bounded 5.0s timeout with automatic process reaping.
   * Covers direct `start()`, repeated `start()`, repeated `stop()`, initialization failure handling, and guard persistence.
5. **Real Package Installation Verification (`tests/test_packaging.py`):**
   * Successfully built wheel `tsukiko-0.1.0-py3-none-any.whl`.
   * Verified in an isolated temporary virtual environment outside repository checkout without `PYTHONPATH` using `tsukiko --check-hardware`.
   * Verified bundled `default_config.yaml` loads cleanly from package resources.
6. **Test Suite Expansion:**
   * 37 tests passing in ~9.9s with 0 errors and 0 warnings.

---

### Implementation Status Matrix

| Subsystem / Feature | Classification | Notes |
|---|---|---|
| Workstation Hardware Profiler | **Implemented & Tested** | Queries AMD Ryzen CPU, RAM, RTX 3050 VRAM, and storage with safe fallbacks and status categorization (`measured`/`zero_available`/`unavailable`). |
| Model Memory Footprint Estimator | **Implemented & Tested** | Accurately factors in GGUF weight size, context KV cache, and runtime overhead with approximate labeling. |
| Pydantic Settings & YAML Loader | **Implemented & Tested** | Type-safe configuration with typed environment variable overrides. |
| Strict Privacy Contract & Socket Guard | **Implemented & Tested** | Enforces zero telemetry, zero cloud fallback, and full low-level socket/DNS interception with atomic rollback. |
| Windows Firewall Policy Manager | **Implemented & Tested** | Refuses shared python interpreter rules; provides dedicated binary rules and honest status inspection. |
| Structured Logging (Console/JSONL) | **Implemented & Tested** | Thread-safe, rotating, color-coded, reconfigurable log system with Windows file unlock. |
| Orchestrator Composition Root | **Implemented & Tested** | Thread-safe reentrant lifecycle management (`initialize`, `start`, `stop`) tested via bounded subprocesses. |
| CLI Interface & Packaging | **Implemented & Tested** | Tested via wheel build, isolated venv installation, and `tsukiko --check-hardware`. |
| Automated Pytest Test Suite | **Implemented & Tested** | 37 unit, regression, and packaging tests passing. |
| PySide6 Desktop Companion UI | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting approval. |
| llama.cpp Local Brain Engine | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No models downloaded yet. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
