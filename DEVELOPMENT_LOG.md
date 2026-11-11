# Tsukiko Development Log

## Phase 1: Foundation (Initial Build: 2026-11-11 | Audit & Repair: 2026-11-11 | Final Security Acceptance Pass: 2026-11-11)

### Status: Complete, Audited, Hardened & Verified for Phase 1 Acceptance Candidate

---

### Audit & Defect Repair Ledger (2026-11-11)

An in-depth engineering audit was conducted on the Phase 1 codebase, identifying 10 defects that were investigated, repaired, and confirmed via 16 regression tests.

| Defect # | Component | Root Cause | Resolution | Regression Test |
|---|---|---|---|---|
| **1** | `app/main.py` | `Any` referenced in `handle_exit` without import from `typing`. | Added `from typing import Any` and safe signal wrapping. | `tests/test_entrypoint.py::test_main_module_exports_and_imports` |
| **2** | `app/core/orchestrator/engine.py` | Standard `threading.Lock()` caused reentrant deadlock when `start()` called `initialize()`. | Migrated to `threading.RLock()` and added idempotent state guards. | `tests/test_entrypoint.py::test_orchestrator_direct_start_reentrancy` |
| **3** | `app/core/config/settings.py` | `PrivacyConfig.validate_local_only()` had `pass` with no assertion. | Added strict `ValidationError` if `local_only=False`, `allow_external_telemetry=True`, or `allow_cloud_fallback=True`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **4** | `app/core/resource_manager/hardware.py` | Hardware inspection only checked `torch.cuda` rather than target runtime `llama.cpp`. | Implemented `check_framework_compatibility()` inspecting `llama_cpp`, `torch`, and `onnxruntime` distinctly. | `tests/test_hardware.py::test_framework_compatibility_distinguishes_llama_cpp_and_torch` |
| **5** | `tests/conftest.py` | Fixture `clean_env` failed to restore mutated environment variable values across tests. | Updated fixture to snapshot and fully restore `os.environ` and call `reset_config()`. | `tests/test_config.py::test_clean_env_fixture_complete_restoration` |
| **6** | `app/core/logging/logger.py` | Logging initialization did not reconfigure if destination directory changed, causing log contamination. | Replaced static boolean with directory tracking, clean handler re-routing, and `get_current_log_dir()`. | `tests/test_logging.py::test_logging_reconfiguration_different_destinations` |
| **7** | `app/core/config/settings.py` | Env overrides set raw strings into configuration dictionary without parsing booleans/numbers. | Implemented `_parse_env_value()` converting `true`/`false`/`1`/`0`/integers/floats. | `tests/test_config.py::test_config_env_variable_overrides_types` |
| **8** | `app/core/resource_manager/hardware.py` | `nvidia-smi` CSV parser crashed on `[N/A]`, `[Not Supported]`, or malformed non-numeric rows. | Implemented `_safe_parse_int()` and `_safe_parse_float()` with fallback defaults. | `tests/test_hardware.py::test_nvidia_smi_parsing_preserves_optional_metrics` |
| **9** | `app/core/resource_manager/hardware.py` | VRAM budget claimed model fits solely based on file size, ignoring KV cache and runtime overhead. | Implemented `estimate_model_vram_footprint()` adding KV cache (+450MB) and CUDA buffers (+500MB). | `tests/test_hardware.py::test_model_vram_estimation_accounts_for_kv_cache_and_overhead` |
| **10** | `app/main.py` | Qt application shutdown did not cleanly terminate the orchestrator lifecycle. | Connected `qt_app.aboutToQuit` directly to `orchestrator.stop` and added graceful headless fallback. | `tests/test_entrypoint.py::test_orchestrator_guard_lifecycle_subprocess` |

---

### Final Security Acceptance Pass (2026-11-11)

A final security acceptance pass closed all remaining findings from the independent security audit, elevating the automated test suite to 71 tests (70 passing, 1 skipped on Windows due to platform AF_UNIX absence):

1. **Numeric Loopback Enforcement & Hostname Trust Elimination (`app/core/privacy/enforcement.py`):**
   * **Defect**: `is_valid_loopback_ip()` previously accepted the string `"localhost"` immediately without local numeric resolution, potentially trusting unverified hostnames.
   * **Fix**: Implemented `is_numeric_loopback_ip()` strictly requiring numeric loopback IPs (`127.0.0.0/8`, `::1`). Raw string `"localhost"` is rejected from numeric validation.
   * **Destination Normalization**: When a connection is initiated to `"localhost"`, destination addresses are converted deterministically to numeric loopback (`127.0.0.1` for AF_INET, `::1` for AF_INET6) before invoking low-level C `connect` / `connect_ex` routines, ensuring low-level system resolvers never initiate outbound network DNS queries.
   * **Tests**: `tests/test_privacy_enforcement.py::test_numeric_loopback_enforcement`.

2. **Fail-Closed Low-Level DNS Interception (`app/core/privacy/enforcement.py`):**
   * **Defect**: Fallthrough risks in resolver hooks when queries failed or when hostnames were unfamiliar.
   * **Fix**: `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo` fail closed with `PrivacyViolationError` on all non-loopback destinations. Zero unrestricted fallback to system resolvers. Deterministic local results for `localhost` and loopback reverse lookups.
   * **Tests**: `tests/test_privacy_enforcement.py::test_localhost_deterministic_dns_resolution`, `test_external_dns_requests_strictly_blocked`.

3. **Socket Family Restrictions (`app/core/privacy/enforcement.py`):**
   * **Defect**: `_is_allowed_destination` did not explicitly reject unsupported socket families (e.g., Bluetooth, Netlink, Packet) when given tuple-like arguments.
   * **Fix**: Explicitly validates socket family (`AF_INET`, `AF_INET6`, `AF_UNIX`). Unknown and unsupported socket families fail closed immediately (returns `False`).
   * **Tests**: `tests/test_privacy_enforcement.py::test_unsupported_socket_families_fail_closed`.

4. **`sendmsg` Argument Forwarding & Platform Compatibility (`app/core/privacy/enforcement.py`):**
   * **Defect**: `_guarded_socket_sendmsg` passed `address=None` explicitly to `_ORIGINAL_SOCKET_SENDMSG`, violating standard C socket signatures for connected sockets on platforms where `sendmsg` expects omitted arguments.
   * **Fix**: Evaluates `if address is not None:` and forwards `(self, buffers, ancdata, flags, norm_address)`. When `address is None`, validates connected socket peer and calls `(self, buffers, ancdata, flags)`.
   * **Tests**: `tests/test_privacy_enforcement.py::test_sendmsg_argument_forwarding_and_behavior`.

5. **Real AF_UNIX Local IPC Communication Test (`tests/test_privacy_enforcement.py`):**
   * **Enhancement**: Added `test_real_af_unix_ipc_exchange` testing genuine socket bind, listen, connect, bidirectional message exchange, and teardown. Gracefully skips with clear notice on Windows Python builds where `hasattr(socket, "AF_UNIX")` is false.
   * **Tests**: `tests/test_privacy_enforcement.py::test_real_af_unix_ipc_exchange`.

6. **Tsukiko Windows Firewall Ownership & Profile Verification (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Rules starting with "Tsukiko" were assumed to be owned by Tsukiko, risking deletion or acceptance of foreign rules. Profile applicability was uninspected.
   * **Fix**: Documented and enforced Tsukiko rule identity:
     * Rule Name: `Tsukiko Outbound Privacy Boundary`
     * Grouping: `Tsukiko Desktop Companion`
     * Description Marker: `[Tsukiko-Privacy-Core:Outbound-Block]`
     * Active Profiles: `Domain,Private,Public` (or `Any`)
   * Rule verification checks Grouping, Description marker, and Profile completeness. Foreign rules with Tsukiko prefix are rejected.
   * Safe removal requires verified Tsukiko ownership before deletion.
   * **Tests**: `tests/test_windows_firewall.py::test_verify_firewall_rule_rejects_unowned_or_foreign_rule`, `test_verify_firewall_rule_rejects_incomplete_profiles`, `test_remove_firewall_rule_enforces_authorization_prefix_and_ownership`.

7. **Deployment Binary PE Header Validation (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Test stubs containing plain text (`binary-stub`) were accepted as valid executables.
   * **Fix**: `is_safe_target_executable` reads the first 2 bytes of the target file and verifies the DOS/PE `MZ` binary magic header (`0x4D 0x5A`). Non-PE files and plain text stubs are strictly rejected.
   * **Documentation**: Documented that PE header verification confirms Windows executable binary format, but does not substitute for cryptographic code signing (e.g. Authenticode certificate verification).
   * **Tests**: `tests/test_windows_firewall.py::test_is_safe_target_executable_rejects_non_pe_binary_header`, `test_is_safe_target_executable_accepts_dedicated_tsukiko_binary`.

8. **Windows Continuous Integration Workflow (`.github/workflows/ci.yml`):**
   * **Feature**: Added `.github/workflows/ci.yml` targeting `windows-latest` with Python 3.11 x64.
   * **Workflow**: Installs dependencies, runs 71-test pytest suite, builds wheel distribution, and validates out-of-tree CLI installation outside repository checkout.

---

### Implementation Status Matrix

| Subsystem / Feature | Classification | Notes |
|---|---|---|
| Workstation Hardware Profiler | **Implemented & Tested** | Queries AMD Ryzen CPU, RAM, RTX 3050 VRAM, and storage with safe fallbacks and status categorization (`measured`/`zero_available`/`unavailable`). |
| Model Memory Footprint Estimator | **Implemented & Tested** | Accurately factors in GGUF weight size, context KV cache, and runtime overhead with approximate labeling. |
| Pydantic Settings & YAML Loader | **Implemented & Tested** | Type-safe configuration with typed environment variable overrides. |
| Strict Privacy Contract & Socket Guard | **Implemented & Tested** | Enforces zero telemetry, zero cloud fallback, and full low-level socket/DNS interception with atomic rollback, numeric loopback enforcement, and socket family restriction. |
| Windows Firewall Policy Manager | **Implemented & Tested** | Refuses shared python interpreter rules; provides dedicated binary rules with PE header validation, rule ownership verification, and honest status inspection. |
| Structured Logging (Console/JSONL) | **Implemented & Tested** | Thread-safe, rotating, color-coded, reconfigurable log system with Windows file unlock. |
| Orchestrator Composition Root | **Implemented & Tested** | Thread-safe reentrant lifecycle management (`initialize`, `start`, `stop`) tested via bounded subprocesses. |
| CLI Interface & Packaging | **Implemented & Tested** | Tested via wheel build, isolated venv installation, and `tsukiko --check-hardware`. |
| Automated Pytest Test Suite | **Implemented & Tested** | 71 unit, regression, packaging, and integration tests (70 passed, 1 skipped). |
| Continuous Integration (CI) | **Implemented & Tested** | GitHub Actions Windows CI workflow at `.github/workflows/ci.yml`. |
| PySide6 Desktop Companion UI | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting approval. |
| llama.cpp Local Brain Engine | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No models downloaded yet. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
