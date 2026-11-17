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
| Automated Pytest Test Suite | **Implemented & Tested** | 293 unit, regression, packaging, and integration tests (289 passed, 4 skipped on Windows; 291 passed, 2 skipped on Linux). |
| Continuous Integration (CI) | **Implemented & Tested** | GitHub Actions dual-platform CI workflow at `.github/workflows/ci.yml` (Windows 11 and Linux with 6-stage read-only ActiveStore inspection). |
| PySide6 Desktop Companion UI | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting approval. |
| llama.cpp Local Brain Engine | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No models downloaded yet. |
| SQLite Long-Term Memory | *Designed (Phase 4)* | Staged in `app/memory/`. Schema designed, database not yet created. |
| Desktop Perception Pipeline | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Capture OFF by default. |
| Offline Voice Subsystem (STT/TTS) | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Voice OFF by default. |
| Desktop Control Permission Guard | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |
