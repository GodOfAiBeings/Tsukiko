# Tsukiko Development Log

## Phase 1: Foundation (Initial Build: 2026-11-11 | Audit & Repair: 2026-11-11 | Acceptance Hardening: 2026-11-11)

### Status: Complete, Audited, Hardened & Ready for Acceptance

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

### Final Audit Corrections and Acceptance Hardening (2026-11-11)

A comprehensive hardening cycle resolved the four remaining audit areas, elevating automated coverage to 63 passing tests:

1. **Family-Aware Local IPC & Socket Interception (`app/core/privacy/enforcement.py`):**
   * **Family Awareness**: Evaluates socket family (`self.family`) before parsing destination addresses.
   * **Local IPC Preservation**: Permitted `AF_UNIX` filesystem paths and abstract socket names where supported, preventing local model server communication from being rejected as Internet hostnames.
   * **Expanded Interception Surface**: Intercepts `connect`, `connect_ex`, `create_connection`, `send`, `sendall`, `sendmsg`, and `sendto` (both signatures). Connected sockets inspect peer destination via `getpeername()`.
   * **Strict Allowlist**: Permits IPv4 loopback (`127.0.0.0/8`), IPv6 loopback (`::1`), and locally resolved `localhost` (using `AI_NUMERICHOST` to prevent network DNS leaks).
   * **Fail-Closed Policy**: Rejects unspecified addresses (`0.0.0.0`, `::`), empty strings, malformed tuples, and external destinations.
   * **Atomic Rollback**: Verified atomic restoration if activation fails.
   * **Verification**: 14 tests in `tests/test_privacy_enforcement.py`.
2. **Strict Windows Firewall Policy Management (`app/core/privacy/windows_firewall.py`):**
   * **Dedicated Binary Validation**: Requires target to exist, be a regular `.exe` file, match dedicated deployment binary (`tsukiko.exe`), and contain no control characters or shell injection vectors.
   * **Shared Interpreter Refusal**: Strictly rejects `python.exe`, `pythonw.exe`, `py.exe`, `pytest.exe`, shells, and arbitrary executables.
   * **Property-Level Verification**: Verifies rule properties: `Direction=Out`, `Action=Block`, `Enabled=Yes`, and exact program path match.
   * **4-State Security Model**: `in_process_only`, `os_policy_not_configured`, `os_policy_unverified`, and `os_policy_active`.
   * **User Authorization & Elevation**: Explicit user authorization (`user_authorized=True`) and administrator elevation required for creation and safe removal. Never runs automatically at application startup.
   * **Verification**: 13 tests in `tests/test_windows_firewall.py`.
3. **Fail-Safe VRAM Classification Matrix (`app/core/resource_manager/hardware.py`):**
   * **Optional Metric Preservation**: VRAM metrics are stored as `Optional[int]`, preserving `None` for missing, `[N/A]`, `[Not Supported]`, or malformed values.
   * **Three Honest States**:
     * `measured`: Total VRAM known positive, Free VRAM positive -> dynamic safe budget = `min(total - 1200, free - 400)`.
     * `zero_available`: Total VRAM known, Free VRAM confirmed 0 MB -> 0 MB safe budget, CPU-only fallback.
     * `unavailable`: No GPU, query failed/timed out, or metrics `[N/A]`/malformed -> 0 MB safe budget, CPU-only fallback.
   * **Diagnostic Reporting**: Never substitutes a positive default when budget is zero or unavailable. Displays explicit CPU inference notice.
   * **Verification**: 14 tests in `tests/test_hardware.py`.
4. **Genuine Wheel Packaging Verification (`tests/test_packaging.py`):**
   * **Demonstrated 4 Milestones**:
     1. Built real wheel `tsukiko-0.1.0-py3-none-any.whl` into temporary directory.
     2. Installed wheel into clean isolated virtual environment via `pip install`.
     3. Executed `tsukiko --check-hardware` outside source tree without `PYTHONPATH` (exit code 0).
     4. Verified packaged resources (`default_config.yaml`) load correctly without access to repository source tree, and verified no imports from `scripts/`.
   * **Verification**: 3 tests in `tests/test_packaging.py`.

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
| Automated Pytest Test Suite | **Implemented & Tested** | 63 unit, regression, packaging, and integration tests passing. |
| PySide6 Desktop Companion UI | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting approval. |
| llama.cpp Local Brain Engine | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No models downloaded yet. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
