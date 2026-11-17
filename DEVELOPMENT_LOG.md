# Tsukiko Development Log

## Phase 3: Local AI Brain Implementation & Character Identity (2026-11-18)

### Status: Complete, Hardened & Verified across Windows and Linux

### Architecture & Deliverables

1. **Default Configuration Restoration & Test Isolation (`config/default_config.yaml`, `tests/test_config.py`, `app/desktop/companion/views/settings_view.py`)**:
   - Cleaned and restored safe defaults: `model_path: null`, `context_window: 4096`, `threads: 6`, `max_vram_mb: 2800`, `max_ram_mb: 3500`, `backend: "auto"`, `lazy_load: true`, `unload_timeout_seconds: 300`.
   - Removed all temporary pytest paths and machine-specific directories from the repository configuration.
   - Decoupled `SettingsView` tests from the default config using an isolated temporary configuration path.
   - Added `test_default_config_safe_defaults_and_integrity` in `tests/test_config.py` proving default configs remain clean and untouched after test runs.

2. **Strict Resource Limit Enforcement & Allocation Safety (`app/core/model_manager/manager.py`)**:
   - Actually enforced the 3,500 MB RAM ceiling: models requiring more memory than `max_ram_mb` are strictly rejected with `safe_to_load = False`.
   - Required system RAM headroom: requires $\ge 500$ MB free system RAM beyond model needs ($$\text{Estimated RAM} \le \text{Available RAM} - 500\text{ MB}$$), failing gracefully under memory pressure.
   - Strict Safe VRAM Layer Clamping: explicit `gpu_layers` overrides can NEVER bypass the safe VRAM budget; layers are strictly clamped down to `max_safe_gpu_layers`.
   - Harmonized memory footprint calculations across CPU, Hybrid, and GPU modes.

3. **Reentrant Lock Safety & Reload Deadlock Elimination (`app/core/model_manager/engine.py`)**:
   - Converted `LlamaCppInferenceEngine._lock` and `DeterministicFakeEngine._lock` from `threading.Lock` to `threading.RLock`.
   - Added internal `_unload_locked()` helper to release resources without re-locking during `load()`.
   - Verified that reloading an already-loaded model with `force=True` executes consecutively without freezing or deadlocking.

4. **Non-Blocking Qt Model Lifecycle Worker (`app/desktop/companion/views/settings_view.py`)**:
   - Built `ModelLifecycleWorker(QThread)` to handle asynchronous model loading and unloading in the background.
   - UI status label truthfully reports `"⏳ Loading model into memory/VRAM..."` and `"⏳ Unloading model from memory/VRAM..."`.
   - Qt main GUI thread remains completely responsive and interactive throughout model load/unload operations.

5. **Historical Character Identity & Ground Truth (`app/core/personality/biography.py`)**:
   - Rooted in Edo-period Japan: Sayo (佐代), born 1814, died 1846 (age 32), mountain farming family in Ogimachi, Shirakawa-go, Hida Province.
   - Ordinary mountain life: agriculture, seed and soil observation, silkworms, Mulberry care, brush records, winter food preservation, cooking, sewing.
   - Dream: *Unfinished Atlas* (*Mikan no Chizu* / 未完の地図)—a self-taught regional atlas recording mountain passes, soil types, water sources, and seasonal plant cycles.
   - Tragic passing: Bitten by a *mamushi* (pit viper) on a rainy mountain slope in late spring 1846; died after three days of fever at age 32.
   - Modern awakening: Awakened into Tsukiko's digital body at the age of 32. Retains adult maturity, mountain pragmatism, stubborn pride, intellectual ambition, and dread of snakes. Not an agreeable corporate assistant; she has human flaws, an ego, patience with genuine learning, and impatience with pretension.

6. **Gradual Self-Disclosure Architecture (`app/core/personality/disclosure.py`)**:
   - 4 progressive stages of disclosure: `ACQUAINTANCE`, `FAMILIAR`, `TRUSTED`, `CONFIDANT`.
   - Suppresses biographical info-dumping on early conversation turns. Sayo reveals her past, her village memories, the Unfinished Atlas, her birth name, and her death only as relationship depth and turn thresholds naturally deepen.

7. **Bounded Conversational Autonomy & Initiative Engine (`app/core/personality/initiative.py`)**:
   - Proactive remarks based on idle duration (minimum 45s), time of day, and session context.
   - Anti-spam backoff: Strictly suppresses repeated initiatives if the user has not responded to a prior proactive remark (`consecutive_unanswered >= 1`).
   - Suppression invariants: Strictly silenced during Game Mode, when the floating widget is hidden, or when the window is minimized.
   - Silence token (`[SILENCE]`): When Tsukiko evaluates the session and decides not to speak, the engine emits `[SILENCE]` and remains quiet.

8. **Runtime Compatibility & Pre-built Wheel Guidance (`requirements/ai.txt`, `pyproject.toml`, `MODEL_COMPATIBILITY.md`)**:
   - Pinned `llama-cpp-python>=0.3.4` (tested for Qwen2.5/Qwen3.5 architectures).
   - Documented pre-built wheel index URLs (`https://abetlen.github.io/llama-cpp-python/whl/cpu` and `cu124`) to eliminate unexpected MSVC/CMake source compilation on Windows.

---

## Phase 2: Acceptance Corrections & Hardening (2026-11-17)

### Status: Complete, Hardened & Verified across Windows and Linux

### Architecture & Deliverables

1. **Explicit Windows User32 ctypes Signatures (`app/desktop/companion/fullscreen.py`)**:
   - Implemented `setup_user32_signatures` explicitly defining `argtypes` and pointer-sized `restype` across all 10 Win32 APIs:
     `GetForegroundWindow`, `GetDesktopWindow`, `GetShellWindow`, `GetClassNameW`, `GetWindowThreadProcessId`, `IsIconic`, `IsWindowVisible`, `GetWindowRect`, `MonitorFromWindow`, `GetMonitorInfoW`.
   - Uses `HWND` (`ctypes.wintypes.HWND`) and `HMONITOR` (`ctypes.c_void_p`), `BOOL`, `DWORD`, `RECT`, and `MONITORINFO`.
   - Eliminates 32-bit truncation of 64-bit OS window and monitor handles on 64-bit Windows.
   - Preserves fail-safe behavior: returns safe fallback (`safe_always_on_top = False`) whenever an API call fails or window metadata cannot be queried.
   - Comprehensive tests verify signature declarations and mock 64-bit pointer handle values.

2. **Accessible System Tray Recovery & Taskbar Preservation (`app/desktop/companion/window.py`, `app/desktop/companion/__init__.py`)**:
   - When `QSystemTrayIcon.isSystemTrayAvailable()` is `False`:
     - Tsukiko launches the main companion window automatically with visible fallback controls.
     - Fallback controls provide `Show Widget`, `Resume from Game Mode`, and `Exit Tsukiko`.
     - In fallback mode, `closeEvent` calls `showMinimized()` rather than `hide()`, keeping the recovery controls in the OS taskbar.
     - Signal handlers for widget hide and game mode restore the main window from minimized state if necessary.
   - Complete end-to-end tests verify tray unavailable → hide widget → restore widget, tray unavailable → Game Mode → resume, and clean exit.

3. **Default Static Idle Emblem (`app/core/config/settings.py`, `config/default_config.yaml`, `app/core/config/default_config.yaml`)**:
   - `idle_animation: bool = False` configured as default in `UIConfig` and default YAML configurations.
   - Floating widget constructs with an inactive avatar animation timer by default; consumes 0% CPU timer wakeups until activated or explicitly configured.
   - Verified that constructing the real floating widget using default configuration starts with an inactive timer.

4. **Truthful Persistence Reporting & Custom Config Path Preservation (`app/desktop/companion/views/settings_view.py`, `app/core/config/settings.py`)**:
   - `SettingsView.save_settings()` differentiates session state from disk persistence:
     - Applies settings to the active session immediately (`settings_applied.emit`).
     - Attempts disk write via `save_config()`. If an exception occurs, updates status label with an explicit warning and returns `False` without falsely reporting success.
   - Tracks `_ACTIVE_CONFIG_PATH` across `load_config()`, ensuring that custom config paths provided via `--config` are honored on save rather than defaulting to the base config path.

5. **Safe Foreground Fullscreen Detection Policy (`app/desktop/companion/fullscreen.py`)**:
   - `FullscreenDetector`: Evaluates whether the current foreground window is occupying the display in fullscreen mode using minimal, read-only Windows User32 metadata.
   - **Anti-Cheat Safe Invariants**:
     - NEVER inspects game process memory, scans memory pages, or reads structures.
     - NEVER enumerates game processes or checks running executable names.
     - NEVER injects DLLs, installs API hooks, or registers global hooks (`SetWindowsHookEx`).
     - NEVER captures screen buffers, window frames, or automates user input.
     - Fails closed / safe: if OS metadata is unavailable, raises an exception, or query fails, always-on-top is disabled.
     - Explicitly does not claim universal anti-cheat compatibility or guarantee that every game permits third-party desktop overlays.
   - Dynamic window flag adjustment: when a foreground window occupies the monitor, `FloatingCompanionWidget` removes `Qt.WindowStaysOnTopHint` and calls `self.lower()`. When fullscreen mode exits, the user's configured always-on-top preference is cleanly restored.

6. **System Tray Integration & Restoration (`app/desktop/companion/tray.py`)**:
   - `TsukikoTrayManager`: Lightweight `QSystemTrayIcon` with procedurally drawn vector icon.
   - Context menu provides required Phase 2 options: `Show Widget`, `Open Tsukiko`, `Resume from Game Mode`, `Exit`.
   - Distinct state tracking: `Hide Widget` and `Game Mode` are separate, fully reversible states.

7. **Test Suite Expansion (`tests/test_desktop_companion.py`)**:
   - Expanded unit and regression test suite with 25 new tests (49 tests total for UI companion subsystem).
   - Total test suite expanded to 342 tests (338 passed, 4 Unix-specific skipped on Windows; 340 passed, 2 skipped on Linux).

---

## Phase 2: Desktop Companion UI Implementation (2026-11-17)

### Status: Complete, Hardened & Verified across Windows and Linux

### Architecture & Deliverables
Phase 2 implemented the complete Tsukiko Desktop Companion User Interface using PySide6-Essentials, establishing a persistent, elegant offline companion while preserving 100% of Phase 1 privacy invariants:

1. **Procedural Vector Avatar (`app/desktop/companion/avatar.py`)**:
   - `TsukikoAvatarWidget`: Smooth, anti-aliased lunar emblem rendered using pure `QPainter` vectors and radial/linear gradients.
   - Zero external 3D engine, VRM, Live2D, image files, or web engine dependencies.
   - Gentle, low-overhead oscillating moonlight shimmer (1.5s period) with passive and active states.
   - Clean animation suspension and resumption for Game Mode.

2. **Final Floating Companion Widget (`app/desktop/companion/widget.py`)**:
   - `FloatingCompanionWidget`: Small, transparent, frameless Qt window (`Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool | Qt.SubWindow`).
   - Draggable across multi-monitor setups; position is clamped to `availableGeometry()` so the widget can never be lost offscreen.
   - Supports initial corner placement (`bottom-right`, `bottom-left`, `top-right`, `top-left`) with configurable margins.
   - Clicking the avatar opens the compact vertical menu immediately to its LEFT.
   - Never forces itself over fullscreen exclusive games.

3. **Compact Companion Vertical Left Menu (`app/desktop/companion/widget.py`)**:
   - `CompactCompanionMenu`: Frameless translucent popup window (`Qt.Popup`) positioned immediately to the LEFT of the avatar widget, with intelligent screen edge fallback.
   - Contains 8 options in exact order:
     1. `Open` — opens the complete Tsukiko main application window (`CompanionMainWindow`).
     2. `Microphone` — voice input control (strictly locked, Phase 6).
     3. `Speaker` — Tsukiko voice output control (strictly locked, Phase 6).
     4. `Screen Sharing` — explicit screen-sharing control (strictly locked, Phase 5).
     5. `Settings` — opens the settings section of the main UI.
     6. `Game Mode` — hides widget and suspends visual animations.
     7. `Hide Widget` — hides floating widget without exiting Tsukiko.
     8. `Exit` — cleanly shuts down the entire application and orchestrator.
   - Dismisses smoothly when clicking outside.

4. **Game Mode (`FloatingCompanionWidget.enable_game_mode()`)**:
   - Hides the floating widget and halts avatar animation timers.
   - Strictly does NOT inspect game processes, inject code, or install system hooks.
   - Provides clean `disable_game_mode()` restoration.

5. **Complete Main Application Window (`app/desktop/companion/window.py`)**:
   - `CompanionMainWindow`: Independent moonlight window with sidebar navigation:
     - `ChatView` (`views/chat.py`): Companion dialogue view with prominent Phase 3 banner; message submission is strictly disabled until the local inference engine is integrated.
     - `SystemStatusView` (`views/system_status.py`): Honest cards displaying genuine CPU, RAM, GPU, VRAM, and subsystem states directly from `HardwareInspector` and `TsukikoOrchestrator` without synthetic/mock values.
     - `PrivacyView` (`views/privacy_view.py`): Zero-trust boundary status display with visibly locked sensor controls (screen sharing, microphone, desktop automation).
     - `MemoryView` (`views/memory_view.py`): Structural placeholder explaining persistent memory without creating any SQLite database.
     - `SettingsView` (`views/settings_view.py`): UI appearance customization (theme, accent color, glow color, opacity slider 0.20-1.00, corner placement, margins) with strict input validation.
   - Independent execution: closing the main window hides it to the background while the floating companion widget remains running.

6. **Moonlight Theme System (`app/desktop/companion/theme.py`)**:
   - Silver-blue moonlight design tokens (`#7FB3D5`, `#D4E6F1`, `#0D131C`, `#151F2C`, opacity `0.92`) and complete QSS stylesheet.

7. **Test Suite Expansion & Verification (`tests/test_desktop_companion.py`)**:
   - 24 dedicated UI tests running with `QT_QPA_PLATFORM=offscreen`.
   - Complete test suite expanded from 293 to 317 tests (313 passed, 4 skipped on Windows; 315 passed, 2 skipped on Linux).
   - Zero test failures, zero regressions across all Phase 1 privacy and firewall boundaries.

---

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

### Final Phase 1 Security Closure (2026-11-16)

The final security closure pass addressed all remaining findings from the independent security audit, elevating the automated test suite to 115 tests (111 passed, 4 skipped on Windows; all 115 passing on Linux):

1. **Fail-Closed Windows Firewall Profile Verification (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Profile applicability was only checked when a `Profiles:` field was found. Missing, empty, or partial profiles could mistakenly pass.
   * **Fix**: Implemented `validate_firewall_profiles()` which fails closed on missing, empty, unknown, or partial profile sets. Only `Any` or all three profiles (`Domain,Private,Public`) are accepted.
   * **Tests**: `tests/test_windows_firewall.py` (11 profile validation tests).

2. **ActiveStore Effective Policy Inspection (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Persistent rule registration in NetSecurity did not establish effective policy in the `ActiveStore`, ignoring disabled profiles or GPO restrictions on local firewall rule merging (`AllowLocalFirewallRules`).
   * **Fix**: Implemented `verify_effective_firewall_policy()` querying PowerShell NetSecurity `ActiveStore` via static script and environment variables. Verifies that all profiles are enabled, local firewall rule merging is allowed, and an active outbound blocking rule exists in the effective policy view. Updated `get_security_status()` to report `os_policy_active` only when ActiveStore status is proven, falling back to `os_policy_unverified`.
   * **Tests**: `tests/test_windows_firewall.py` (12 ActiveStore verification tests).

3. **Precise Ownership Identity & Safe Multi-Rule Deletion (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Rule lookup and deletion did not safely handle multiple matching candidates or foreign rules sharing the rule name, and lacked atomic rule identification.
   * **Fix**: Enforced rule identity: DisplayName `Tsukiko Outbound Privacy Boundary`, Stable ID `Tsukiko_Privacy_Outbound_Block`, Grouping `Tsukiko Desktop Companion`, and Description marker `[Tsukiko-Privacy-Core:Outbound-Block]`. Implemented multi-rule parsers for netsh and PowerShell. Safe deletion verifies ownership before deletion, refuses to delete foreign rules, and refuses deletion if multiple candidates match ambiguously without operator intervention. Pre-creation checks prevent overwriting foreign rules.
   * **Tests**: `tests/test_windows_firewall.py` (15 ownership and safe deletion tests).

4. **Strict Windows Portable Executable (PE) Structural Validation (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Target executable validation only checked file size and first 2 bytes (`b"MZ"`), which could accept corrupt or truncated non-PE files.
   * **Fix**: Implemented `validate_pe_structure()`: verifies minimum 64-byte DOS header, `b"MZ"` magic bytes, extracts 4-byte little-endian `e_lfanew` offset at `0x3C`, verifies bounds `0x40 <= pe_offset <= file_size - 4`, and confirms 4-byte PE signature `b"PE\x00\x00"`. Documented distinction between binary structural format validation and cryptographic Authenticode code-signing.
   * **Tests**: `tests/test_windows_firewall.py` (13 PE structural validation and executable safety tests).

5. **Real Native `sendmsg` Integration Testing (`tests/test_privacy_enforcement.py`):**
   * **Feature**: Added genuine loopback TCP `sendmsg`, UDP `sendmsg` with explicit destination, and external rejection tests. Gracefully skips on platforms lacking `socket.sendmsg` (Windows) and runs natively on Linux.
   * **Tests**: `tests/test_privacy_enforcement.py::test_real_connected_tcp_sendmsg`, `test_real_udp_explicit_destination_sendmsg`, `test_real_sendmsg_rejects_external_destination`.

6. **Dual-Platform CI Matrix Expansion (`.github/workflows/ci.yml`):**
   * **Feature**: Added `linux-integration-and-packaging` on `ubuntu-latest` alongside `windows-test-and-packaging` on `windows-latest`.
   * **Workflow**: Installs dependencies, runs complete 115-test pytest suite, builds wheel distribution, and executes out-of-tree CLI installation test on both operating systems.

---

### Final Windows Firewall Security Correction (2026-11-16)

The final Windows Firewall security correction addressed the remaining findings from the independent security audit, elevating the automated test suite to 135 tests (131 passed, 4 skipped on Windows; 135 passed on Linux):

1. **Exact Rule Identity & Safe Deletion (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: Rule deletion executed `netsh advfirewall firewall delete rule name={target_rule.display_name}`, which could delete foreign rules or multiple rules simultaneously if names collided. Creation also created rules where Name == DisplayName.
   * **Fix**: Assigned stable internal identifier `STABLE_RULE_ID = "Tsukiko_Privacy_Outbound_Block"`. Creation uses PowerShell `New-NetFirewallRule` with explicit `-Name`, `-DisplayName`, `-Group`, `-Description`, `-Direction Outbound`, `-Action Block`, `-Enabled True`, `-Profile Any`, `-Program`, and `-PolicyStore`. Safe deletion strictly targets `-Name Tsukiko_Privacy_Outbound_Block -PolicyStore PersistentStore` via `Remove-NetFirewallRule`. Refuses automatic deletion for legacy rules lacking the internal stable ID and re-queries the policy store post-deletion to confirm the rule was removed.
   * **Tests**: `tests/test_windows_firewall.py` (safe deletion by stable Name, rejection of foreign rules with matching DisplayName, refusal of legacy rules, and post-deletion persistence checks).

2. **Complete Effective Outbound Traffic-Filter Verification (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: ActiveStore verification inspected only the application filter, leaving address, port, protocol, service, interface, and security filters unverified.
   * **Fix**: Implemented `validate_firewall_filters()` and extended PowerShell ActiveStore query to inspect all 7 filter categories using NetSecurity cmdlets (`Get-NetFirewallApplicationFilter`, `Get-NetFirewallAddressFilter`, `Get-NetFirewallPortFilter`, `Get-NetFirewallServiceFilter`, `Get-NetFirewallInterfaceFilter`, `Get-NetFirewallInterfaceTypeFilter`, `Get-NetFirewallSecurityFilter`). Only reports `os_policy_active` when all filters are positively verified as unrestricted.
   * **Tests**: `tests/test_windows_firewall.py` (all 7 filter category rejection tests).

3. **Distinguishing Inspection Failure from Confirmed Absence (`app/core/privacy/windows_firewall.py`):**
   * **Defect**: `query_matching_firewall_rules()` returned `[]` on both confirmed absence and inspection failure (non-zero returncode, timeout, parse error), risking false reporting of `os_policy_not_configured` when queries failed.
   * **Fix**: Introduced `FirewallQueryResult(success, inspection_complete, rules, error, policy_store)`. Confirmed absence (`success=True, rules=[]`) supports `os_policy_not_configured`, while inspection failure (`success=False, error=...`) strictly reports `os_policy_unverified`. `create_firewall_rule()` refuses creation if pre-creation inspection fails.
   * **Tests**: `tests/test_windows_firewall.py` (confirmed absence, confirmed presence, exit code error, timeout, malformed JSON, and status reporting tests).

4. **Read-Only Windows Firewall CI Verification (`scripts/verify_windows_firewall_inspection.py` & `.github/workflows/ci.yml`):**
   * **Feature**: Added non-destructive read-only verification script and CI step on `windows-latest` querying ActiveStore profiles and sample rules with all 7 filter categories and validating Python JSON parser compatibility.
   * **Integrity**: Non-destructive; modifies no rules and does not assert Tsukiko rule presence.

---

### Phase 1 Final Security Hardening: Correct Security Filter Semantics, Fail-Closed Parsing, and PowerShell Inspection (2026-11-16)

An independent security review identified three remaining defects in NetSecurity filter verification, elevating the automated test suite to 221 tests (217 passed, 4 skipped on Windows; all 221 passed on Linux):

1. **Defect A: Correct NetSecurity Security-Filter Properties (`app/core/privacy/windows_firewall.py`):**
   * **Root Cause**: PowerShell queries and Python verification checked non-existent plural properties (`LocalUsers`, `RemoteUsers`, `RemoteMachines`) instead of exact Microsoft NetSecurity CIM properties (`Authentication`, `Encryption`, `OverrideBlockRules`, `LocalUser`, `RemoteUser`, `RemoteMachine`). Missing properties defaulted silently to unrestricted.
   * **Fix**: Migrated PowerShell script to query exact CIM properties. Added `override_block_rules: Optional[Any] = None` to `FirewallRuleInfo`. Python `validate_firewall_filters()` requires: `Authentication == "NotRequired"`, `Encryption == "NotRequired"`, `OverrideBlockRules is False` (strictly boolean), and `LocalUser`, `RemoteUser`, `RemoteMachine` covering `Any`. Rejects missing, null, unrecognized, or plural properties.
   * **Tests**: 10 Defect A regression tests in `tests/test_windows_firewall.py`.

2. **Defect B: Strict Missing-Value Handling & Fail-Closed Parsing (`app/core/privacy/windows_firewall.py`):**
   * **Root Cause**: `parse_powershell_rules_json` manufactured artificial defaults (`.get("LocalAddress", "Any")`, etc.), turning missing or corrupted JSON properties into valid unrestricted rules.
   * **Fix**: Removed manufactured defaults. Missing and null properties are preserved as `None`. Parameterized matrix test verifies that every single one of the 14 required properties fails closed if missing, null, or restrictive.
   * **Tests**: 60 parameterized matrix regression tests (15 properties x 4 conditions) in `tests/test_windows_firewall.py`.

3. **Defect C: PowerShell Inspection Fail-Closed Envelopes & Error Propagation (`app/core/privacy/windows_firewall.py`):**
   * **Root Cause**: PowerShell inspection commands used `-ErrorAction SilentlyContinue`, suppressing cmdlet errors, and returned unformatted JSON where empty output was misinterpreted as confirmed absence.
   * **Fix**: Enforced `$ErrorActionPreference = 'Stop'` and removed `-ErrorAction SilentlyContinue`. Filter query failures propagate to PowerShell outer catch handler and return exit code 1. Output is wrapped in a structured envelope `{ "Success": bool, "InspectionComplete": bool, "Rules": [...], "Error": string|null }`. Python query handlers strictly require `Success=True` and `InspectionComplete=True`. Rule creation refuses when pre-creation inspection fails or is incomplete; rule deletion refuses confirmation when post-deletion inspection fails or is incomplete.
   * **Tests**: 7 Defect C fail-closed integration tests in `tests/test_windows_firewall.py`.

4. **Enhanced 5-Stage Read-Only Windows Inspection Verification (`scripts/verify_windows_firewall_inspection.py`):**
   * Rewritten to test real ActiveStore profiles, sample real rules, verify 23-property schema, confirm CIM boolean serialization, and validate Python parser rejection rules. 100% read-only with zero system mutations.

---

### Definitive Phase 1 Security Closure: Full NetSecurity CIM Filter Coverage, Lossless Serialization, and Independent Verification (2026-11-17)

A comprehensive architectural audit closed all remaining edge cases in the Windows Firewall subsystem, completing Phase 1 security hardening and elevating the automated test suite to 241 collected items (237 passed, 4 skipped on Windows; all 241 passing on Linux):

1. **Complete 18-Property NetSecurity CIM Filter Schema (`app/core/privacy/windows_firewall.py`):**
   - **Coverage**: Extended filter schema across all 7 categories from 15 to 18 properties:
     - Application (2): `Program`, `Package`
     - Address (2): `LocalAddress`, `RemoteAddress`
     - Port (5): `Protocol`, `LocalPort`, `RemotePort`, `IcmpType`, `DynamicTarget`
     - Service (1): `Service`
     - Interface (1): `InterfaceAlias`
     - InterfaceType (1): `InterfaceType`
     - Security (6): `Authentication`, `Encryption`, `OverrideBlockRules`, `LocalUser`, `RemoteUser`, `RemoteMachine`
   - **Semantics**: Unpackaged Win32 binary (`tsukiko.exe`) requires `Package` null/empty. Restrictive AppContainer package SIDs are rejected. `IcmpType` and `DynamicTarget` require `Any` (or `0`). `OverrideBlockRules` requires strictly boolean `False`.
   - **Tests**: `tests/test_windows_firewall.py` (complete 18-property matrix and rejection tests).

2. **Lossless CIM Field State Serialization (`Get-CimFieldRecord` & `CimFieldRecord`):**
   - **Architecture**: Replaced fragile PowerShell string casting (`[string]`, `[bool]`) with structured field-state records distinguishing:
     - `PROPERTY_PRESENT_WITH_VALID_VALUE`
     - `PROPERTY_PRESENT_WITH_NULL`
     - `PROPERTY_MISSING`
     - `PROPERTY_PRESENT_WITH_MALFORMED_VALUE`
   - Preserves exact CIM types without loss. Deserializes into typed `CimFieldRecord` in Python.
   - **Tests**: `tests/test_windows_firewall.py::test_envelope_missing_or_null_rules_fails_closed`, field-state deserialization tests.

3. **CIM Filter Association Integrity (`Count -eq 1`):**
   - PowerShell inspection verifies that each of the 7 associated filter cmdlets returns exactly 1 associated CIM filter object per rule (`Count -eq 1`). Any mismatch immediately triggers inspection failure and fails closed.
   - **Tests**: `tests/test_windows_firewall.py::test_filter_association_count_mismatch_fails_closed`.

4. **Versioned JSON Envelope (`SchemaVersion: 1`):**
   - Envelope enforces `SchemaVersion: 1`, `Success`, `InspectionComplete`, `PolicyStore`, `Profiles`, `Rules`, `BypassRules`, and `Errors`.
   - Unsupported schema versions or missing fields fail closed immediately.
   - **Tests**: `tests/test_windows_firewall.py::test_envelope_unsupported_schema_version_fails_closed`.

5. **ActiveStore Conflicting Bypass Evaluation (`OverrideBlockRules == True`):**
   - ActiveStore inspection queries Outbound Allow rules targeting `tsukiko.exe` where `OverrideBlockRules` is `$true` (which would override blocking rules).
   - If present, populated in `BypassRules`, and `verify_effective_firewall_policy()` rejects `os_policy_active`.
   - **Tests**: `tests/test_windows_firewall.py::test_activestore_bypass_outbound_allow_override_block_rules_rejects`.

6. **Removal of Incomplete Netsh Fallbacks:**
   - Removed netsh fallback for rule queries and policy verification. Netsh cannot inspect CIM filter objects or ActiveStore effective policy. If NetSecurity is unavailable, queries fail closed (`success=False`), mapping directly to `os_policy_unverified`.
   - **Tests**: `tests/test_windows_firewall.py::test_query_matching_firewall_rules_without_powershell_fails_closed`, `test_security_status_fails_closed_to_os_policy_unverified_when_powershell_unavailable`.

7. **Unified Rule Verification (`verify_firewall_rule`):**
   - Refactored `verify_firewall_rule()` to use `query_matching_firewall_rules(policy_store=policy_store)`, verifying rule ownership, active profiles, and all 18 CIM filter properties across all 7 categories.

8. **Enhanced 5-Stage Read-Only Smoke Test (`scripts/verify_windows_firewall_inspection.py`):**
   - Validates ActiveStore profiles, retrieves real rules, verifies 26 required fields (8 rule fields + 18 CIM filter fields), checks boolean serialization, and runs 11 synthetic parser rejection tests. Strictly read-only on live Windows host.

---

### Final Phase 1 Acceptance Fixes (2026-11-17)

The final acceptance pass resolved all remaining concrete defects identified in the independent source review, elevating the automated test suite to 266 tests (262 passed, 4 skipped on Windows; all 266 passing on Linux):

1. **ActiveStore Bypass Discovery Without Error Suppression (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: The bypass inspection script previously used `-ErrorAction SilentlyContinue` across `Get-NetFirewallApplicationFilter`, `Get-NetFirewallRule`, and `Get-NetFirewallSecurityFilter`, masking cmdlet failures, and only looked for exact executable path matches without evaluating unrestricted all-programs rules.
   - **Fix**: Removed all error suppression. Implemented canonical ActiveStore bypass discovery using `Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -OverrideBlockRules $true -ErrorAction Stop`. Catches expected CIM `CmdletizationQuery_NotFound` when 0 rules have override, while propagating any real cmdlet failure. Verifies 1-to-1 association cardinality (`Count -eq 1`).
   - **Scope Applicability**: Evaluates applicability: identifies both exact executable matches (`Program == targetExe`) and unrestricted all-programs rules (`Program` is Any/empty/`*` with no AppContainer `Package`). Confirms that unrelated application rules do not invalidate Tsukiko. Any ambiguous wildcard pattern (`?` or embedded `*`) throws and fails closed.
   - **Tests**: `tests/test_windows_firewall.py` (9 bypass regression tests covering exact match, all-programs, unrelated app, cmdlet failures, association count mismatches, and malformed responses).

2. **Strict Response Envelope Schema (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: Envelope parsing permitted default fallbacks for missing fields and did not strictly validate all 8 keys, types, or contradictory states.
   - **Fix**: Implemented `validate_response_envelope()` enforcing all 8 canonical fields: `SchemaVersion` (strictly int 1), `Success` (strict bool), `InspectionComplete` (strict bool), `PolicyStore` (string matching expected store), `Profiles` (list), `Rules` (list), `BypassRules` (list), and `Errors` (list).
   - **Consistency**: Rejects contradictory states (`Success != InspectionComplete`, `Success=True` with non-empty `Errors`). Applied uniformly to `query_matching_firewall_rules`, `verify_effective_firewall_policy`, and `parse_powershell_rules_json`.
   - **Tests**: `tests/test_windows_firewall.py` (9 envelope regression tests covering missing keys, unsupported versions, policy store mismatches, null/wrong types, and inconsistent states).

3. **Strict CIM Field-State Invariants (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: `CimFieldRecord.from_raw()` performed `bool()` coercion on arbitrary strings for `Exists` / `IsNull`, potentially converting invalid strings to `True`, and did not validate internal state consistency.
   - **Fix**: Audited `CimFieldRecord.from_raw()`. Disallowed `bool()` coercion on arbitrary strings; strictly requires boolean types. Enforces state consistency across `VALID`, `NULL`, `MISSING`, and `MALFORMED`. Contradictory combinations (e.g. `VALID` with `exists=False`, `NULL` with non-null value) are rejected as `MALFORMED`. Preserves exact underlying CIM types (`$prop.CimType`).
   - **Tests**: `tests/test_windows_firewall.py` (7 CIM record regression tests covering valid states, missing/null, non-bool `Exists`/`IsNull`, contradictory combinations, type preservation, and PowerShell roundtrip serialization).

4. **Enhanced 6-Stage Real Windows Read-Only Smoke Test (`scripts/verify_windows_firewall_inspection.py`):**
   - **Defect**: Previous script duplicated the PowerShell serializer and hardcoded `BypassRules = @()`.
   - **Fix**: Completely refactored to import and execute the production serializer and ActiveStore bypass inspection (`build_activestore_inspection_powershell_script`, `PS_CIM_SERIALIZER_SNIPPET`, `validate_response_envelope`, `parse_powershell_rules_json`, `validate_firewall_filters`).
   - **Coverage**: Tests real ActiveStore profiles, unmanufactured ActiveStore bypass discovery, real associated filter objects across 10 sample rules, all 18 CIM filter properties, field-state consistency invariants, boolean fidelity (`OverrideBlockRules`, `Enabled`), 11 synthetic filter rejections, 4 envelope rejections, and command failure fail-closed behavior (exit code 1 with failure envelope). Strictly read-only on live Windows host.

5. **Expanded Test Suite (`tests/test_windows_firewall.py`):**
   - Added 25 new regression tests, raising `tests/test_windows_firewall.py` to 211 tests. Total test suite expanded to 266 collected items (262 passed, 4 skipped on Windows; all 266 passed on Linux).

---

### Final Phase 1 Blocker Correction (2026-11-17)

The final blocker correction resolved all three source-level defects identified in the independent review, elevating the automated test suite to 279 tests (275 passed, 4 skipped on Windows; all 279 passing on Linux):

1. **ActiveStore Bypass Literal Wildcard Application Matching (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: The previous bypass inspection expression `$prog -like "*?*"` treated `?` as a PowerShell wildcard matching any single character, inadvertently classifying practically every non-empty application string as an ambiguous wildcard pattern.
   - **Fix**: Replaced with explicit literal wildcard detection: `$trimmedProg.Contains("?") -or ($trimmedProg.Contains("*") -and $trimmedProg -ne "*")`.
   - **Applicability Semantics**:
     - Exact target executable path recognized as `ExactExecutable` (`applies = true`).
     - `Any`, `*`, or empty string with no AppContainer package recognized as `AllPrograms` (`applies = true`).
     - A different exact executable path is classified as unrelated (`applies = false`) and does not throw.
     - Ambiguous wildcard application patterns (containing literal `?` or non-trivial `*`) throw an inspection exception and fail closed.
     - Ordinary Windows executable paths (e.g. in `Program Files` or `System32`) are evaluated literally and are never classified as ambiguous.
   - **Tests**: `tests/test_windows_firewall.py` (7 new bypass matching regression tests covering normal paths, exact match, lone star `*`, empty string, package restriction, multiple candidates, and native PowerShell literal wildcard evaluation).

2. **Strict CIM StringValue Validation & Filter Semantic Integrity (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: `CimFieldRecord.from_raw()` permitted `StringValue` to be omitted or null for `VALID` states, and `validate_firewall_filters()` used `field.string_value or ""` which could silently treat a missing or null string value as an unrestricted empty string token, potentially allowing restrictive rules (`Value="TCP"`, `StringValue=null`) to pass as unrestricted.
   - **Fix**:
     - `CimFieldRecord.from_raw()` strictly requires non-null string `StringValue` when `state == CimFieldState.VALID`. Detects contradictions between `Value` and `StringValue` across strings, lists, booleans, and numbers, marking contradictory records as `MALFORMED`.
     - `validate_firewall_filters()` validates both `field.string_value` and `field.value` directly against allowed tokens, and verifies that `value` matches `string_value`.
     - Enforces property-specific empty string semantics: disallows empty string `""` for `LocalAddress`, `RemoteAddress`, `Protocol`, `LocalPort`, `RemotePort`, and `InterfaceAlias` (`allow_empty=False`). Permitted empty string is preserved only for `Service`, `InterfaceType`, `Package`, `IcmpType`, `DynamicTarget`, `LocalUser`, `RemoteUser`, and `RemoteMachine`.
     - Validates `Authentication`, `Encryption`, and `OverrideBlockRules` values and string values strictly against `NotRequired` / `False`.
   - **Tests**: `tests/test_windows_firewall.py` (6 new CIM StringValue integrity and filter validation regression tests; 3 new synthetic rejection checks in `scripts/verify_windows_firewall_inspection.py`).

3. **Broad CIM Type Category Preservation (`app/core/privacy/windows_firewall.py`):**
   - **Documentation & Alignment**: Clarified documentation to acknowledge that the production PowerShell serializer (`Get-CimFieldRecord`) classifies properties into broad type categories (`Boolean`, `Integer`, `String`, `Array`, `Null`, `None`) rather than WMI CIM metadata types.
   - **Boundary Tests**: Reworked `test_cim_record_exact_type_preservation` and `test_cim_record_roundtrip_serialization_powershell` in `tests/test_windows_firewall.py` to exercise the actual PowerShell serialization boundary (`PS_CIM_SERIALIZER_SNIPPET` -> `Get-CimFieldRecord`) across all 6 broad type categories.

4. **Expanded Test Suite (`tests/test_windows_firewall.py`):**
   - Added 13 new regression tests, raising `tests/test_windows_firewall.py` to 224 tests. Total test suite expanded to 279 collected items (275 passed, 4 skipped on Windows; all 279 passing on Linux).

---

### Final CIM Value Validation Correction (2026-11-17)

The final CIM value validation correction addressed the malformed-CIM-value acceptance defects and eliminated truthiness coercion, ensuring strict 1:1 Type metadata consistency and direct model validation:

1. **Exact CIM Type Metadata Consistency (`app/core/privacy/windows_firewall.py`):**
   - **Contract & Enforcing**: Uses `PS_CIM_SERIALIZER_SNIPPET` as the authoritative contract:
     - Boolean Value -> strictly Boolean Type (rejects Boolean with String, Integer, Array, or unknown Type).
     - Integer Value -> strictly Integer Type (rejects Integer with Boolean, String, Array, or unknown Type).
     - Array Value   -> strictly Array Type (rejects Array with Boolean, Integer, String, or unknown Type).
     - String Value  -> strictly String Type (rejects String with Boolean, Integer, Array, or unknown Type).
   - **Elimination of Invented Type Mappings**: Numeric floats are serialized by PowerShell as strings with `Type = "String"`. Non-string float values in Python/JSON are strictly rejected from VALID state as unsupported types.
   - **Removal of String Over-Permissiveness**: Removed exceptions that previously accepted Boolean, Integer, or Array values under String Type.

2. **Direct Program Value Validation in `validate_firewall_filters` (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: `validate_firewall_filters()` previously relied solely on the `rule.program` property (derived from `StringValue`), never validating `rule.program_field.value`. Consequently, a model directly constructed with `Value={}` or `Value=123` and `StringValue=str(expected_exe)` could pass validation.
   - **Fix**: Requires `rule.program_field` to be in `VALID` state, contain a supported string `Value`, and have an exact matching `StringValue`. Directly constructed models with dictionaries, arrays, numbers, booleans, or contradictory paths are strictly rejected. Continues validating normalized executable paths against the expected dedicated binary.

3. **Truthiness Coercion Elimination for Package Value (`app/core/privacy/windows_firewall.py`):**
   - **Defect**: `str(rule.package_field.value or "")` allowed `False` or `0` to silently coerce to empty strings via Python truthiness (`bool(False) == False` -> `""`), allowing unsupported values to pass.
   - **Fix**: Requires a `VALID` Package field to have a supported string `Value` matching `StringValue`. Genuinely `NULL` Package fields remain supported for unpackaged Win32 executables. Legitimate empty or unrestricted strings (`""`, `"any"`, `"*"`) remain fully supported.

4. **Exhaustive Filter Value Type Enforcement (`app/core/privacy/windows_firewall.py`):**
   - Added explicit boolean check in `check_field_unrestricted()`, preventing boolean values from being treated as integers (`0`/`1`) on address, port, and protocol filters.
   - Added type guards on `Authentication` and `Encryption` values in `validate_firewall_filters()`.

5. **Verification Smoke Test Enhancements (`scripts/verify_windows_firewall_inspection.py`):**
   - Added synthetic checks in Stage 5 for String Value with Boolean Type, Program record with dict Value, and Package record with boolean False without truthiness coercion.

6. **Expanded Test Suite (`tests/test_windows_firewall.py`):**
   - Added focused regression tests for:
     - String Value with Boolean, Integer, Array, or Unknown Type.
     - Boolean, Integer, and Array Values declared as String.
     - Directly constructed Program records with unsupported Value types (`dict`, `list`, `int`, `bool`, contradictory paths).
     - Directly constructed Package records with `False`, `0`, dictionaries, and contradictory `StringValue`.
     - Legitimate serializer-produced values and existing unrestricted firewall rules.
   - Raised `tests/test_windows_firewall.py` to 238 tests. Total test suite expanded to 293 collected items:
     - Windows 11 x64: 289 passed, 4 skipped (the 4 skipped are Linux-specific `sendmsg` and `AF_UNIX` tests).
     - Ubuntu Linux: 291 passed, 2 skipped (the 2 skipped are native PowerShell inspection tests, where PowerShell is absent on Ubuntu). Corrected earlier documentation that claimed 289 passed without acknowledging the 2 PowerShell skips.

---

## 2026-11-17 - Phase 2: Desktop Companion UI Implementation & Final Acceptance

### Completed Objectives
1. **PySide6 Desktop Companion Architecture (`app/desktop/companion/`)**:
   - `FloatingCompanionWidget`: Independent frameless transparent Qt window with procedural vector moonlight emblem (`TsukikoAvatarWidget`). Clamped to screen work areas, draggable, with zero external assets, VRM, Live2D, 3D character, or GPU engine.
   - `CompactCompanionMenu`: 8-option compact menu opening to the left of the avatar: `Open`, `Microphone` (locked), `Speaker` (locked), `Screen Sharing` (locked), `Settings`, `Game Mode`, `Hide Widget`, `Exit`.
   - `FullscreenDetector`: Safe foreground fullscreen policy via read-only Windows User32 APIs (`GetForegroundWindow`, `GetWindowRect`, `MonitorFromWindow`, `GetMonitorInfoW`). Explicit ctypes signatures (`argtypes`/`restype`) across all 10 Win32 APIs, eliminating 64-bit pointer truncation. Fails safe by disabling always-on-top. Zero anti-cheat footprint (no process scanning, memory reading, DLL injection, input simulation, or hooks).
   - `TsukikoTrayManager`: Context menu supporting `Show Widget`, `Open Tsukiko`, `Resume from Game Mode`, and `Exit`. Reversible `Hide Widget` vs `Game Mode` states.
   - Accessible Tray Fallback: If `isSystemTrayAvailable()` returns False, launches main window at startup with `fallback_frame` controls (`Show Widget`, `Resume from Game Mode`, `Exit Tsukiko`). Minimizes to taskbar rather than hiding on close.
   - Static Idle Default: Configured `idle_animation: false` by default across config files and `UIConfig`. Shimmer animation timer runs only during active dialogue or explicit configuration.
   - Dynamic Settings Persistence: Real-time UI updates with truthful disk persistence error reporting via `save_config()`, preserving custom `--config` path.
   - `CompanionMainWindow`: 5 modular views (`ChatView`, `SystemStatusView`, `PrivacyView`, `MemoryView`, `SettingsView`).
2. **Verification & Tests (`tests/test_desktop_companion.py`)**:
   - 49 dedicated tests covering theme styling, avatar rendering, menu ordering, locked sensor controls, boundary clamping, safe fullscreen detection, tray recovery, and headless CLI.
   - Total test suite expanded to 342 tests (338 passed, 4 skipped on Windows; 340 passed, 2 skipped on Linux).
   - Accepted commit: `de4a661ed5636c1e5c4b7a87ace20226d53f29db`.

---

## 2026-11-18 - Phase 3: Local AI Brain Implementation

### Completed Objectives
1. **Binary GGUF Inspection (`app/core/model_manager/gguf_parser.py`)**:
   - Pure-Python, zero-dependency reader for GGUF v2 and v3 container formats.
   - Safely parses header magic (`b"GGUF"`), version, tensor count, and metadata KV count.
   - Extracts architecture name, block count, context length, quantization type, and file size without loading weights into RAM or requiring third-party libraries.
   - Validates file bounds, structural integrity, and version compatibility.
2. **Model Lifecycle Management (`app/core/model_manager/lifecycle.py`, `app/core/model_manager/manager.py`)**:
   - Implemented 9-state formal lifecycle state machine:
     `NOT_CONFIGURED` -> `VALIDATING` -> `READY` -> `LOADING` -> `LOADED` -> `GENERATING` -> `UNLOADING` / `ERROR`.
   - Real-time `ModelInfo` tracking model path, format, quantization, block count, context size, load timestamp, and last-used timestamp.
   - Concurrency protection: Reentrant locks prevent simultaneous loads or overlapping generation requests.
   - Inactivity auto-unload: 300s inactivity timer automatically releases RAM/VRAM without interrupting active generation.
3. **Hardware-Aware Memory & VRAM Offloading**:
   - Strict budgeting for target workstation (AMD Ryzen 5 5600H, RTX 3050 Laptop 4GB, 16GB RAM).
   - Safe LLM RAM budget: `max_ram_mb: 3500`.
   - Safe GPU VRAM budget: `max_vram_mb: 2800`.
   - Headroom guarantee: Preserves at least 400 MB of free VRAM beyond calculated allocation:
     $$\text{Safe VRAM} = \min(\text{Configured Max}, \text{Total VRAM} - 1200\text{ MB}, \text{Free VRAM} - 400\text{ MB})$$
   - Layer offload calculation:
     $$N_{\text{gpu\_layers}} = \min\left(\text{Total Blocks}, \left\lfloor\frac{\text{Safe VRAM Bytes}}{\text{Bytes per Layer}}\right\rfloor\right)$$
   - Graceful memory refusal: Raises `InsufficientMemoryError` when system RAM is insufficient, avoiding OOM crashes.
   - Safe CPU fallback: Automatically selects 0 GPU layers if free VRAM is 0 MB, `nvidia-smi` is unavailable, or CUDA is absent.
4. **Inference Engine Abstraction (`app/core/model_manager/engine.py`)**:
   - `BaseInferenceEngine`: Abstract base defining lifecycle and streaming contracts.
   - `LlamaCppInferenceEngine`: Production engine wrapping `llama-cpp-python` with lazy imports, CUDA capability checks, thread-safe cancellation checking between tokens, and non-thinking reasoning filtering.
   - `DeterministicFakeEngine`: Pure-Python deterministic test double for reproducible unit and integration tests without model weights or GPU drivers.
5. **Personality & Non-Thinking Engine (`app/core/personality/`)**:
   - `TSUKIKO_DEFAULT_SYSTEM_PROMPT`: Directs Tsukiko as an adult woman companion—calm, observant, thoughtful, candid, zero corporate filler.
   - Invariant honesty: Acknowledges active Phase 1-3 capabilities and truthfully states that Phase 4-7 sensors (screen sharing, microphone, memory, desktop automation) are disabled.
   - Non-thinking mode: Suppresses `<think>...</think>` internal reasoning tags from streamed chunks and message history.
6. **Streaming Chat Interface (`app/desktop/companion/views/chat.py`)**:
   - Non-blocking `ChatWorker(QThread)` with auto-scroll and responsive UI.
   - Real-time chunk streaming with typing/thinking indicator.
   - "Stop" button for instantaneous user generation cancellation.
   - Error bubbles with "Retry" action.
   - "Clear Chat" action wiping temporary in-memory session history.
   - Model status banner showing active model name, quantization, backend, and lifecycle state.
7. **Settings & System Status Telemetry Integration**:
   - `SettingsView`: Added Section 3 card for model file selection (`QFileDialog`), validation, load, unload, context window, threads, max VRAM, max RAM, and backend selector.
   - `SystemStatusView`: Added Section 4 telemetry card displaying model metadata, active backend, state, context window, generation status, process RSS RAM, and measured GPU memory.
8. **Preservation of Invariant Privacy & Security Guarantees**:
   - Zero outbound network traffic: Low-level family-aware socket interception and deterministic fail-closed DNS guard remain 100% active.
   - Zero cloud fallback: No remote LLM APIs or telemetry endpoints exist in the codebase.
   - Zero Phase 4-7 scope creep: No SQLite database created, no screen capture thread started, no microphone listening, no desktop automation permissions granted.
9. **Comprehensive Verification & Tests (`tests/test_local_brain.py`)**:
   - 31 dedicated tests covering GGUF parsing, lifecycle transitions, hardware budgeting, layer offloading, insufficient memory refusal, streaming, cancellation, concurrency lockout, prompt formatting, reasoning token stripping, in-memory history pruning, ChatWorker QThread streaming, Settings UI, System Status telemetry, and privacy assertions.
   - Total test suite expanded to 373 tests (369 passed, 4 skipped on Windows; 371 passed, 2 skipped on Linux) with 0 failures and 0 errors.

---

## 2026-11-18 - Phase 3 Corrections and Character Identity (v0.3.1)

### Completed Objectives
1. **Historical Character Identity & Ground Truth (`app/core/personality/biography.py`)**:
   - Sayo (佐代), born 1814, died 1846 (age 32), mountain farming family in Ogimachi, Shirakawa-go, Hida Province.
   - Life skills: agriculture, seed and soil observation, silkworms, Mulberry care, brush records, winter food preservation, cooking, sewing.
   - Life ambition: *Unfinished Atlas* (*Mikan no Chizu* / 未完の地図)—recording mountain passes, soil types, water sources, and seasonal plant cycles.
   - Tragic passing: Bitten by a *mamushi* (pit viper) on a rainy mountain slope in late spring 1846; died after three days of fever at age 32.
   - Modern awakening: Awakened into Tsukiko's digital body at age 32 with adult maturity, mountain pragmatism, stubborn pride, intellectual curiosity, and dread of snakes. Not an agreeable corporate assistant; has flaws, ego, patience with genuine learning, and impatience with pretension.
2. **Gradual Self-Disclosure Engine (`app/core/personality/disclosure.py`)**:
   - 4 progressive disclosure stages: `ACQUAINTANCE`, `FAMILIAR`, `TRUSTED`, `CONFIDANT`.
   - Suppresses biographical info-dumping on early conversation turns. Sayo reveals her past, her village memories, the Unfinished Atlas, her birth name, and her death only as relationship depth and turn thresholds naturally deepen.
3. **Safe Default Configuration & Test Isolation (`config/default_config.yaml`, `tests/test_config.py`, `app/desktop/companion/views/settings_view.py`)**:
   - Restored `config/default_config.yaml` to safe defaults (`model_path: null`, `context_window: 4096`, `threads: 6`, `max_vram_mb: 2800`, `max_ram_mb: 3500`, `backend: "auto"`, `lazy_load: true`, `unload_timeout_seconds: 300`).
   - Removed temporary pytest paths and machine-specific directories from repository configurations.
   - Decoupled `SettingsView` tests from default config using temporary test config files.
   - Added regression test `test_default_config_safe_defaults_and_integrity` in `tests/test_config.py`.
4. **Resource Limit Enforcement & Safe VRAM Clamping (`app/core/model_manager/manager.py`)**:
   - Enforced 3,500 MB RAM ceiling: rejects oversized models with `safe_to_load = False`.
   - Enforced system RAM headroom: requires $\ge 500$ MB free system RAM beyond model needs.
   - Explicit `gpu_layers` overrides strictly capped to safe VRAM budget layers (`max_safe_gpu_layers`).
5. **Model Reload Deadlock Elimination (`app/core/model_manager/engine.py`)**:
   - Replaced non-reentrant `threading.Lock` with `threading.RLock`.
   - Added internal `_unload_locked()` helper to avoid re-locking during `load()`.
   - Verified consecutive reload with `force=True` without deadlocks or thread freezing.

---

## 2026-11-18 - Phase 3 Final Corrections (v0.3.2)

### Completed Objectives
1. **Proactive Conversation Scheduler & Non-Blocking Worker (`app/desktop/companion/scheduler.py`)**:
   - Implemented `CompanionInitiativeScheduler`: Connected to the application lifecycle with an automatic idle timer.
   - Idle-time and cooldown constraints: Minimum 45 seconds of user inactivity before evaluating initiative; minimum 120-second cooldown between proactive remarks.
   - Anti-spam & silence backoff: After an unanswered initiative, Tsukiko strictly remains quiet (`consecutive_unanswered >= 1`) until the user initiates a new message.
   - User activity reset: Sending a chat message immediately resets the unanswered counter (`record_user_activity()`) and restarts the idle timer.
   - Strict suppression conditions: Suppressed during Game Mode, hidden widget state, minimized main window, disabled chat view, or when the model is unloaded.
   - Non-blocking inference: `ProactiveInitiativeWorker(QThread)` offloads prompt evaluation and generation to a background worker so the Qt main GUI thread never freezes.
   - Zero auto-load invariant: Unloaded models are never loaded automatically just to generate a proactive remark.
   - Evaluated silence (`[SILENCE]`): Respects Tsukiko's choice when she evaluates context and decides not to speak.
2. **Desktop Speech Bubble (`app/desktop/companion/bubble.py`)**:
   - Implemented `CompanionSpeechBubble`: Frameless, translucent Moonlight popover positioned adjacent to the floating avatar.
   - Proactive remarks are visible on desktop even when the main window is closed or hidden.
   - Features a 15-second auto-dismiss timer and click-to-open chat interaction.
3. **Stage-Isolated Character Prompts & Rapport-Gated Disclosure (`app/core/personality/prompts.py`, `app/core/personality/disclosure.py`)**:
   - Strict stage isolation: The `ACQUAINTANCE` prompt contains present identity (Tsukiko, age 32, observant, calm, practical) ONLY, with zero mention of past-life names, locations, dates, death, or trauma (purged all mentions of Sayo, Shirakawa-go, 1814, 1846, silkworms, Atlas, mamushi, snakebite, or fever).
   - Rapport-gated disclosure tracker: `DisclosureTracker` strictly requires meaningful conversational context and specific inquiries to advance stages. Trivial, repetitive, or empty turn counts (even 50+ turns) remain firmly at `ACQUAINTANCE`.
4. **Comprehensive Long-Form Historical Canon (`app/core/personality/biography.py`)**:
   - Expanded character biography into long-form canon covering all 12 canonical life milestones: childhood/family, village routines and gassho-zukuri architecture, self-education journey, nature observation, Unfinished Atlas ambition, personal flaws/jealousy/pride, life at 32, mamushi snakebite incident, 3-day fever struggle, unfulfilled dream, awakening into the machine, and modern world discovery.
   - Maintained clean separation between long-form canon and stage-restricted system prompts.
5. **Qwen3.5 Upstream Runtime Compatibility (`requirements/ai.txt`, `pyproject.toml`, `MODEL_COMPATIBILITY.md`)**:
   - Updated minimum requirement to `llama-cpp-python>=0.3.17`, incorporating upstream Qwen3.5 architecture support and hybrid prefix-reuse fix.
   - Documented verified Windows Python 3.11 CPU and CUDA 12.4 pre-built wheel indices on the abetlen index.
6. **Expanded Test Suite (`tests/test_local_brain.py`, `tests/test_packaging.py`)**:
   - Added integration tests for scheduler lifecycle, worker thread offload, suppression under Game Mode/hidden widget/unloaded model, non-repetition, speech bubble presentation, long-form canon fields, rapport-gated progression, and stage-isolated prompt suppression.
   - Packaging assertions updated for new scheduler and bubble modules.
   - Total test suite expanded to 397 tests (393 passed, 4 skipped on Windows; 395 passed, 2 skipped on Linux) with 0 failures and 0 errors.

---

### Implementation Status Matrix

| Subsystem / Feature | Classification | Notes |
|---|---|---|
| Workstation Hardware Profiler | **Implemented & Tested** | Queries AMD Ryzen CPU, RAM, RTX 3050 VRAM, and storage with safe fallbacks and status categorization (`measured`/`zero_available`/`unavailable`). |
| Model Memory Footprint Estimator | **Implemented & Tested** | Accurately factors in GGUF weight size, context KV cache, and runtime overhead with approximate labeling. |
| Pydantic Settings & YAML Loader | **Implemented & Tested** | Type-safe configuration with typed environment variable overrides. |
| Strict Privacy Contract & Socket Guard | **Implemented & Tested** | Enforces zero telemetry, zero cloud fallback, and full low-level socket/DNS interception with atomic rollback, numeric loopback enforcement, socket family restriction, and native `sendmsg` testing. |
| Windows Firewall Policy Manager | **Implemented & Tested** | Refuses shared python interpreter rules; provides dedicated binary rules with 5-point structural PE validation, fail-closed profile checking, complete 18-property NetSecurity CIM filter schema across all 7 categories, lossless `CimFieldRecord` serialization with strict invariant checking, exact 1:1 Value/Type metadata consistency (rejecting dicts/nested objects/unsupported types), strict Program value validation without relying solely on string_value, Package validation without truthiness coercion, filter association integrity (`Count -eq 1`), unmanufactured ActiveStore Outbound Allow bypass evaluation (`OverrideBlockRules=True`) with literal wildcard detection across exact executable and all-programs scopes without error suppression, broad type category preservation, exact stable-name creation/deletion via PowerShell, fail-closed strict 8-key JSON envelopes (`SchemaVersion: 1`), and honest structured query inspection. |
| Structured Logging (Console/JSONL) | **Implemented & Tested** | Thread-safe, rotating, color-coded, reconfigurable log system with Windows file unlock. |
| Orchestrator Composition Root | **Implemented & Tested** | Thread-safe reentrant lifecycle management (`initialize`, `start`, `stop`) tested via bounded subprocesses. |
| CLI Interface & Packaging | **Implemented & Tested** | Tested via wheel build, isolated venv installation, and `tsukiko --check-hardware`. |
| Automated Pytest Test Suite | **Implemented & Tested** | 397 unit, regression, packaging, and integration tests (393 passed, 4 skipped on Windows; 395 passed, 2 skipped on Linux). |
| Continuous Integration (CI) | **Implemented & Tested** | GitHub Actions dual-platform CI workflow at `.github/workflows/ci.yml` (Windows 11 and Linux with offscreen PySide6 and 6-stage read-only ActiveStore inspection). |
| PySide6 Desktop Companion UI | **Implemented & Tested** | Procedural vector moonlight emblem, compact left menu, safe foreground fullscreen detection with Win32 ctypes signatures, reversible Game Mode, tray manager with accessible fallback panel, dynamic settings persistence, and main window. |
| llama.cpp Local Brain Engine | **Implemented & Tested** | Pure-Python GGUF inspection, 9-state ModelManager lifecycle, hardware-aware RAM/VRAM offloading with 400MB headroom, non-thinking personality engine, streaming ChatWorker, cancellation, retry on error, temporary in-memory history pruning, and Settings/Status telemetry cards. |
| Conversational Autonomy & Initiative | **Implemented & Tested** | Automatic `CompanionInitiativeScheduler` with idle timer ($\ge 45$s), cooldown (120s), anti-spam backoff, background `ProactiveInitiativeWorker(QThread)` non-blocking inference, zero auto-load invariant, and `CompanionSpeechBubble` desktop popover. |
| Historical Character Identity & Canon | **Implemented & Tested** | 12 canonical life milestones in `CharacterBiography`, 4-stage rapport-gated disclosure tracker (`DisclosureTracker`), and strict stage-isolated prompt content in `prompts.py`. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
