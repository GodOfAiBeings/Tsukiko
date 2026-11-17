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

### Implementation Status Matrix

| Subsystem / Feature | Classification | Notes |
|---|---|---|
| Workstation Hardware Profiler | **Implemented & Tested** | Queries AMD Ryzen CPU, RAM, RTX 3050 VRAM, and storage with safe fallbacks and status categorization (`measured`/`zero_available`/`unavailable`). |
| Model Memory Footprint Estimator | **Implemented & Tested** | Accurately factors in GGUF weight size, context KV cache, and runtime overhead with approximate labeling. |
| Pydantic Settings & YAML Loader | **Implemented & Tested** | Type-safe configuration with typed environment variable overrides. |
| Strict Privacy Contract & Socket Guard | **Implemented & Tested** | Enforces zero telemetry, zero cloud fallback, and full low-level socket/DNS interception with atomic rollback, numeric loopback enforcement, socket family restriction, and native `sendmsg` testing. |
| Windows Firewall Policy Manager | **Implemented & Tested** | Refuses shared python interpreter rules; provides dedicated binary rules with 5-point structural PE validation, fail-closed profile checking, complete 18-property NetSecurity CIM filter schema across all 7 categories, lossless `CimFieldRecord` serialization, filter association integrity (`Count -eq 1`), ActiveStore Outbound Allow bypass evaluation (`OverrideBlockRules=True`), exact stable-name creation/deletion via PowerShell, fail-closed versioned JSON envelopes (`SchemaVersion: 1`), and honest structured query inspection. |
| Structured Logging (Console/JSONL) | **Implemented & Tested** | Thread-safe, rotating, color-coded, reconfigurable log system with Windows file unlock. |
| Orchestrator Composition Root | **Implemented & Tested** | Thread-safe reentrant lifecycle management (`initialize`, `start`, `stop`) tested via bounded subprocesses. |
| CLI Interface & Packaging | **Implemented & Tested** | Tested via wheel build, isolated venv installation, and `tsukiko --check-hardware`. |
| Automated Pytest Test Suite | **Implemented & Tested** | 241 unit, regression, packaging, and integration tests (237 passed, 4 skipped on Windows; all 241 passed on Linux). |
| Continuous Integration (CI) | **Implemented & Tested** | GitHub Actions dual-platform CI workflow at `.github/workflows/ci.yml` (Windows 11 and Linux with 5-stage read-only ActiveStore inspection). |
| PySide6 Desktop Companion UI | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting approval. |
| llama.cpp Local Brain Engine | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No models downloaded yet. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
