# Changelog

All notable changes to the Tsukiko project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.8] - Final CIM Value Validation Correction - 2026-11-17

### Fixed
- **Exact CIM Type Metadata Consistency (`app/core/privacy/windows_firewall.py`)**:
  - Enforced exact 1:1 `Type` metadata consistency in `CimFieldRecord.from_raw()` using `PS_CIM_SERIALIZER_SNIPPET` as the authoritative contract:
    - Boolean Value -> strictly Boolean Type (rejects Boolean with String, Integer, Array, or unknown Type).
    - Integer Value -> strictly Integer Type (rejects Integer with Boolean, String, Array, or unknown Type).
    - Array Value   -> strictly Array Type (rejects Array with Boolean, Integer, String, or unknown Type).
    - String Value  -> strictly String Type (rejects String with Boolean, Integer, Array, or unknown Type).
  - Eliminated invented type mappings: numeric floats are not serialized as raw numeric JSON by PowerShell and are strictly rejected from VALID state when supplied as non-string representations.
  - Removed exceptions that previously accepted Boolean, Integer, or Array values under String Type.
- **Strict Program Value Validation in `validate_firewall_filters` (`app/core/privacy/windows_firewall.py`)**:
  - Requires the `Program` property to be in `CimFieldState.VALID` state, contain a supported string `Value`, and have a matching, non-contradictory `StringValue`.
  - Rejects directly constructed model records with dictionaries, arrays, numeric integers, booleans, or contradictory executable paths.
  - Continues normalizing and matching the executable path against the expected dedicated binary.
- **Truthiness Coercion Elimination for Package Value (`app/core/privacy/windows_firewall.py`)**:
  - Eliminated `str(value or "")` truthiness coercion which previously allowed `False` or `0` to silently coerce to empty strings.
  - Requires a `VALID` Package field to have a supported string `Value` matching `StringValue`.
  - Genuinely `NULL` Package fields remain supported for unpackaged Win32 executables.
  - Legitimate empty or unrestricted string tokens (`""`, `"any"`, `"*"`) remain fully supported.
- **Verification Smoke Test Enhancements (`scripts/verify_windows_firewall_inspection.py`)**:
  - Stage 5 checks extended to verify:
    - Inconsistent Type metadata (String with Boolean Type) is strictly rejected as malformed.
    - Program record with unsupported Value type (dict) is strictly rejected.
    - Package record with boolean False is strictly rejected without truthiness coercion.
- **Test Suite Expansion (`tests/test_windows_firewall.py`)**:
  - Expanded firewall test suite to 238 tests covering:
    - String Value with Boolean, Integer, Array, or Unknown Type rejection.
    - Boolean, Integer, and Array Values declared as String rejection.
    - Directly constructed Program records with unsupported Value types (`dict`, `list`, `int`, `bool`, contradictory paths).
    - Directly constructed Package records with `False`, `0`, dictionaries, and contradictory `StringValue`.
    - Legitimate serializer-produced values and existing unrestricted firewall rules.
  - Total test suite expanded to 293 collected items (289 passed, 4 skipped on Windows; 291 passed, 2 skipped on Linux). Corrected previous documentation that claimed all 289 passed on Linux to reflect actual CI evidence of 2 skipped (due to native PowerShell absence on Ubuntu).

## [0.1.7] - Final Phase 1 Blocker Correction - 2026-11-17

### Fixed
- **ActiveStore Bypass Literal Wildcard Application Matching (`app/core/privacy/windows_firewall.py`)**:
  - Replaced PowerShell wildcard expression `$prog -like "*?*"` with explicit literal wildcard detection: `$trimmedProg.Contains("?") -or ($trimmedProg.Contains("*") -and $trimmedProg -ne "*")`.
  - Fixes single-character wildcard trap where `?` matched any non-empty string.
  - Recognizes exact Tsukiko executable path as `ExactExecutable` (`applies = true`).
  - Recognizes `Any`, `*`, or empty string (with no AppContainer package) as `AllPrograms` (`applies = true`).
  - Classifies different exact executable paths as unrelated (`applies = false`) without throwing exceptions.
  - Throws inspection exception on ambiguous wildcard patterns (`?` or embedded `*`), failing closed.
  - Evaluates ordinary Windows executable paths without classifying them as ambiguous.
- **Strict CIM StringValue Validation & Filter Semantic Integrity (`app/core/privacy/windows_firewall.py`)**:
  - `CimFieldRecord.from_raw()` strictly requires non-null string `StringValue` for `VALID` states.
  - Rejects contradictory combinations between `Value` and `StringValue` across strings, lists, booleans, and numeric types as `MALFORMED`.
  - Disallows `field.string_value or ""` from treating missing/null values as unrestricted.
  - `validate_firewall_filters()` validates both `field.string_value` and `field.value` directly against allowed tokens.
  - Enforces property-specific semantics: disallows empty string `""` for `LocalAddress`, `RemoteAddress`, `Protocol`, `LocalPort`, `RemotePort`, and `InterfaceAlias` (`allow_empty=False`). Permitted empty string is preserved only for `Service`, `InterfaceType`, `Package`, `IcmpType`, `DynamicTarget`, `LocalUser`, `RemoteUser`, and `RemoteMachine`.
  - Validates `Authentication`, `Encryption`, and `OverrideBlockRules` values and string values strictly against `NotRequired` / `False`.
- **Broad CIM Type Category Preservation Documentation & Boundary Tests**:
  - Clarified documentation in `PRIVACY.md`, `DEVELOPMENT.md`, `DEVELOPMENT_LOG.md`, and `CHANGELOG.md` that the production PowerShell serializer (`Get-CimFieldRecord`) classifies properties into broad type categories (`Boolean`, `Integer`, `String`, `Array`, `Null`, `None`).
  - Reworked boundary tests in `tests/test_windows_firewall.py` to exercise the actual PowerShell serialization boundary (`PS_CIM_SERIALIZER_SNIPPET` -> `Get-CimFieldRecord`) across all 6 broad type categories.
- **Test Suite Expansion**:
  - Added 13 new regression tests in `tests/test_windows_firewall.py` (elevating module to 224 tests).
  - Total test suite expanded to 279 collected items (275 passed, 4 skipped on Windows; all 279 passing on Linux).

## [0.1.6] - Final Phase 1 Acceptance Fixes - 2026-11-17

### Added
- **Unmanufactured ActiveStore Outbound Allow Bypass Discovery (`app/core/privacy/windows_firewall.py`)**:
  - Removed all error suppression (`-ErrorAction SilentlyContinue`) from NetSecurity bypass inspection.
  - Enumerates security filters with `OverrideBlockRules=True` (`Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -OverrideBlockRules $true`). Handles expected CIM `CmdletizationQuery_NotFound` gracefully while propagating any real cmdlet failure.
  - Enforces 1-to-1 association cardinality (`Count -eq 1`) for candidate rules, security filters, and application filters.
  - Evaluates scope applicability: identifies exact executable matches (`Program == targetExe`) and unrestricted all-programs rules (`Program` is Any/empty/`*` without an AppContainer `Package`). Unrelated application rules do not invalidate Tsukiko.
  - Ambiguous wildcard patterns (`?` or embedded `*`) fail closed.
  - Any applicable bypass rule prevents `os_policy_active`.
- **Strict Response Envelope Schema (`validate_response_envelope`)**:
  - Strictly validates all 8 canonical fields: `SchemaVersion` (strictly int 1), `Success` (strict bool), `InspectionComplete` (strict bool), `PolicyStore` (string matching expected store), `Profiles` (list), `Rules` (list), `BypassRules` (list), and `Errors` (list).
  - Enforces non-contradictory states: `Success` must equal `InspectionComplete`; non-empty `Errors` is forbidden when `Success=True`.
  - Applied uniformly to `query_matching_firewall_rules`, `verify_effective_firewall_policy`, and `parse_powershell_rules_json`.
- **Strict Invariant Validation on `CimFieldRecord.from_raw()`**:
  - Audited `CimFieldRecord.from_raw()`: eliminated weak `bool()` coercion on arbitrary strings; strictly requires boolean types for `Exists` and `IsNull`.
  - Validates state consistency across `VALID`, `NULL`, `MISSING`, and `MALFORMED`.
  - Rejects contradictory combinations (e.g. `VALID` with `exists=False`, `NULL` with non-null value) and marks them `MALFORMED`.
  - Preserves exact underlying CIM types (`$prop.CimType`).
- **Enhanced 6-Stage Read-Only Smoke Test (`scripts/verify_windows_firewall_inspection.py`)**:
  - Removed duplicate PowerShell serializer and eliminated hardcoded `BypassRules = @()`.
  - Imports and exercises production serializer and unmanufactured ActiveStore bypass discovery.
  - Tests 6 distinct stages: profile verification, unmanufactured ActiveStore bypass discovery, real associated filter objects across 10 sample rules, CIM field-state consistency invariants, boolean fidelity (`OverrideBlockRules`, `Enabled`), 11 synthetic filter rejections, 4 envelope rejections, and fail-closed command failure behavior (exit code 1 with failure envelope).
- **Expanded Test Suite (`tests/test_windows_firewall.py`)**:
  - Added 25 regression tests covering bypass discovery, envelope validation, and CIM field invariants, raising `tests/test_windows_firewall.py` to 211 tests. Total suite expanded to 266 collected items (262 passed, 4 skipped on Windows; all 266 passed on Linux).

## [0.1.5] - Definitive Phase 1 Security Closure - 2026-11-17

### Added
- **Full 18-Property NetSecurity CIM Filter Schema (`app/core/privacy/windows_firewall.py`)**:
  - Expanded filter validation across all 7 categories from 15 to 18 properties:
    - Application (2): `Program`, `Package`
    - Address (2): `LocalAddress`, `RemoteAddress`
    - Port (5): `Protocol`, `LocalPort`, `RemotePort`, `IcmpType`, `DynamicTarget`
    - Service (1): `Service`
    - Interface (1): `InterfaceAlias`
    - InterfaceType (1): `InterfaceType`
    - Security (6): `Authentication`, `Encryption`, `OverrideBlockRules`, `LocalUser`, `RemoteUser`, `RemoteMachine`
  - Unpackaged Win32 binaries require `Package` to be null/empty; restrictive AppContainer package SIDs are rejected.
  - `IcmpType` and `DynamicTarget` require unrestricted `Any` (or `0`).
- **Lossless PowerShell-to-Python Field-State Serialization (`Get-CimFieldRecord`, `CimFieldRecord`)**:
  - Replaced lossy PowerShell string casting with structured field-state records distinguishing:
    - `PROPERTY_PRESENT_WITH_VALID_VALUE`
    - `PROPERTY_PRESENT_WITH_NULL`
    - `PROPERTY_MISSING`
    - `PROPERTY_PRESENT_WITH_MALFORMED_VALUE`
  - Preserves exact CIM types and maps directly into typed `CimFieldRecord` models in Python.
- **CIM Filter Association Integrity (`Count -eq 1`)**:
  - PowerShell inspection confirms that each of the 7 associated filter cmdlets returns exactly 1 associated CIM filter object per rule (`Count -eq 1`). Any association count mismatch immediately fails closed.
- **Strict Versioned JSON Envelope (`SchemaVersion: 1`)**:
  - Response envelope enforces `SchemaVersion: 1`, `Success`, `InspectionComplete`, `PolicyStore`, `Profiles`, `Rules`, `BypassRules`, and `Errors`. Unsupported schema versions fail closed.
- **ActiveStore Conflicting Bypass Evaluation (`OverrideBlockRules == True`)**:
  - ActiveStore inspection queries Outbound Allow rules targeting `tsukiko.exe` where `OverrideBlockRules` is `$true`. If present, populated in `BypassRules` and rejected from `os_policy_active`.
- **Elimination of Incomplete Fallbacks**:
  - Removed netsh fallback for rule queries and policy verification. Netsh cannot inspect CIM filter objects or ActiveStore effective policy. If NetSecurity is unavailable, queries fail closed (`success=False`), mapping directly to `os_policy_unverified`.
- **Unified Rule Verification (`verify_firewall_rule`)**:
  - Refactored `verify_firewall_rule()` to query the policy store via NetSecurity and validate rule ownership, active profiles, and all 18 CIM filter properties.
- **Enhanced 5-Stage Read-Only Smoke Test (`scripts/verify_windows_firewall_inspection.py`)**:
  - Validates ActiveStore profiles, retrieves real rules, verifies 26 required fields (8 rule + 18 filter fields), checks boolean serialization, and runs 11 synthetic parser rejection tests. Strictly read-only on live Windows host.
- **Expanded Test Suite (`tests/test_windows_firewall.py`)**:
  - Added 18-property parameterized matrix tests and 8 integration tests covering bypass rules, filter association count mismatches, envelope schema versions, missing/null rules, PowerShell absence, and restrictive package/icmp/dynamic targets.
  - Total test suite expanded to 241 collected items (237 passed, 4 skipped on Windows; all 241 passed on Linux).

### Added
- **Exact NetSecurity CIM Security Filter Properties (`app/core/privacy/windows_firewall.py`)**:
  - Migrated security-filter queries and Python validation from incorrect plural names to exact Microsoft NetSecurity CIM properties:
    - `Authentication: [string]$sec.Authentication` (requires `NotRequired`)
    - `Encryption: [string]$sec.Encryption` (requires `NotRequired`)
    - `OverrideBlockRules: [bool]$sec.OverrideBlockRules` (strictly requires boolean `False`)
    - `LocalUser: [string]$sec.LocalUser` (requires unrestricted `Any`)
    - `RemoteUser: [string]$sec.RemoteUser` (requires unrestricted `Any`)
    - `RemoteMachine: [string]$sec.RemoteMachine` (requires unrestricted `Any`)
  - Added `override_block_rules: Optional[Any] = None` in `FirewallRuleInfo` to prevent missing values from silently defaulting to `False`.
  - Added backwards-compatible `@property` accessors (`local_users`, `remote_users`, `remote_machines`) mapping to singular CIM fields.
  - Added helper `FirewallRuleInfo.create_unrestricted()` for test and synthesis baseline creation.
- **Fail-Closed Parsing & Strict Missing-Value Semantics (`parse_powershell_rules_json`, `validate_firewall_filters`)**:
  - Removed artificial fallback defaults (`.get("LocalAddress", "Any")`, etc.) in `parse_powershell_rules_json`.
  - Distinguishes explicitly verified unrestricted values from explicitly verified restrictive values, missing properties (`None`), null properties (`None`), and malformed properties.
  - All 14 required properties across all 7 filter categories strictly fail validation closed if missing or null.
- **PowerShell Fail-Closed Response Envelopes & Strict Error Propagation**:
  - Set `$ErrorActionPreference = 'Stop'` and removed `-ErrorAction SilentlyContinue` across all NetSecurity queries.
  - Cmdlet and filter query failures now propagate to PowerShell's outer catch handler, emitting a JSON envelope with `Success = $false`, `InspectionComplete = $false`, and terminating with exit code 1.
  - Python query handlers require both `Success=True` and `InspectionComplete=True`. Truncated, empty, or failed queries fail closed (`success=False, inspection_complete=False`) and are never conflated with rule absence.
  - `create_firewall_rule()` refuses creation if pre-creation inspection fails or is incomplete.
  - `remove_firewall_rule()` refuses deletion confirmation if post-deletion inspection fails or is incomplete.
- **Enhanced 5-Stage Read-Only Windows Inspection Verification (`scripts/verify_windows_firewall_inspection.py`)**:
  - Rewritten to execute a 5-stage inspection test:
    1. ActiveStore Firewall Profiles schema and state verification.
    2. Real Windows Firewall rules sampling.
    3. Full 23-property schema verification across all 7 filter categories.
    4. NetSecurity CIM boolean property serialization (`OverrideBlockRules`, `Enabled`).
    5. Python parser validation and synthetic rejection tests (missing property, OverrideBlockRules=True, malformed booleans, plural property substitution).
  - Strictly read-only with zero system mutations.
- **Expanded Test Suite (`tests/test_windows_firewall.py`)**:
  - Added 10 Defect A regression tests.
  - Added 60 parameterized matrix regression tests (15 properties x 4 conditions) for Defect B fail-closed semantics.
  - Added 7 Defect C fail-closed PowerShell integration tests.
  - Total test suite expanded to 221 tests (217 passed, 4 skipped on Windows; all 221 passed on Linux).

---

## [0.1.3] - Final Windows Firewall Security Correction - 2026-11-16

### Added
- **Exact Firewall Rule Identity & PowerShell Creation (`app/core/privacy/windows_firewall.py`)**:
  - Stable, immutable internal identifier `STABLE_RULE_ID = "Tsukiko_Privacy_Outbound_Block"`.
  - Rule creation migrated to PowerShell `New-NetFirewallRule` with explicit `-Name`, `-DisplayName`, `-Group`, `-Description`, `-Direction Outbound`, `-Action Block`, `-Enabled True`, `-Profile Any`, `-Program`, and `-PolicyStore`.
  - Pre-creation check queries policy store and halts if inspection fails, if foreign conflicting rules exist, or if ambiguous matching rules exist.
  - Added `generate_powershell_firewall_rule_command()` and `generate_powershell_remove_rule_command()`.
- **Safe Exact-Name Deletion & Post-Deletion Verification (`app/core/privacy/windows_firewall.py`)**:
  - `remove_firewall_rule()` strictly deletes rules by exact internal Name using PowerShell `Remove-NetFirewallRule -Name Tsukiko_Privacy_Outbound_Block -PolicyStore PersistentStore`.
  - Never deletes rules by DisplayName alone.
  - Automatically detects legacy rules lacking the internal stable ID and refuses automatic deletion with actionable operator guidance.
  - Re-queries the policy store post-deletion to confirm the rule was genuinely removed from the system.
- **Complete Effective Outbound Traffic-Filter Verification (`validate_firewall_filters`)**:
  - `verify_effective_firewall_policy()` queries and validates all 7 NetSecurity filter categories:
    1. **Application Filter**: Matches normalized target executable path (`tsukiko.exe`); wildcards and empty targets fail verification.
    2. **Address Filter**: `LocalAddress` and `RemoteAddress` cover `Any`; specific IPs, subnets, and ranges fail verification.
    3. **Port & Protocol Filter**: `Protocol`, `LocalPort`, and `RemotePort` cover `Any`; port and protocol restrictions fail verification.
    4. **Service Filter**: Applies to all services (`Any` / unrestricted).
    5. **Interface Filter**: Applies to all interfaces (`Any` / unrestricted).
    6. **Interface-Type Filter**: Applies to all interface types (`Any` / unrestricted).
    7. **Security Filter**: Requires no IPsec authentication (`NotRequired`), encryption (`NotRequired`), or machine/user restrictions.
  - Rejection of any restrictive filter fails closed to prevent partial bypasses.
- **Structured Query Results & Honest Status Reporting (`FirewallQueryResult`)**:
  - Replaced ambiguous list-only return in `query_matching_firewall_rules()` with `FirewallQueryResult(success, inspection_complete, rules, error, policy_store)`.
  - Positively distinguishes confirmed absence (`success=True, rules=[]`) from inspection failure (`success=False, error=...`).
  - `get_security_status()` reports `os_policy_unverified` on inspection failure; never falsely reports `os_policy_not_configured`.
- **Read-Only Windows Firewall CI Verification (`scripts/verify_windows_firewall_inspection.py`)**:
  - Created standalone read-only policy inspection verification script.
  - Added step to `.github/workflows/ci.yml` on `windows-latest` running real ActiveStore queries across all 7 filter categories and validating Python JSON deserialization.
  - Completely non-destructive: does not create, modify, or delete any firewall rules.
- **Expanded Test Suite (`tests/test_windows_firewall.py`)**:
  - 20 new regression tests (80 total in module, 135 total across test suite).

---

## [0.1.2] - Final Phase 1 Security Closure - 2026-11-16

### Added
- **Fail-Closed Windows Firewall Profile Verification (`app/core/privacy/windows_firewall.py`)**:
  - `validate_firewall_profiles()` strictly fails closed on missing, empty, unknown, and partial profile sets.
  - Accepts only `Any` or `Domain,Private,Public`.
  - Eliminates false-positive verification when netsh output omits or truncates the `Profiles` field.
- **ActiveStore Effective Policy Verification (`app/core/privacy/windows_firewall.py`)**:
  - `verify_effective_firewall_policy()` queries PowerShell NetSecurity ActiveStore to distinguish persistent rule registration from effective active runtime policy.
  - Safe parameter passing via process environment variables (`TSUKIKO_TARGET_RULE_NAME`, `TSUKIKO_TARGET_GROUP`) eliminates shell injection and parsing issues.
  - Verifies that all network profiles (`Domain`, `Private`, `Public`) are enabled in ActiveStore.
  - Verifies that local rule merging is permitted (`AllowLocalFirewallRules` is true) and not overridden by domain/GPO policy.
  - Verifies that the effective rule in ActiveStore is enabled, outbound, blocking, targets the dedicated executable, and covers all profiles.
  - Updated `get_security_status()` to require confirmed ActiveStore effective policy for `os_policy_active`, falling back to `os_policy_unverified` when policy cannot be established.
- **Precise Rule Ownership & Safe Multi-Rule Deletion (`app/core/privacy/windows_firewall.py`)**:
  - Defined `FirewallRuleInfo` model and `is_tsukiko_owned_rule()` verifying DisplayName (`Tsukiko Outbound Privacy Boundary`), Name (`Tsukiko_Privacy_Outbound_Block`), Group (`Tsukiko Desktop Companion`), and Description marker (`[Tsukiko-Privacy-Core:Outbound-Block]`).
  - Added multi-rule parsers `parse_netsh_rule_blocks()` and `parse_powershell_rules_json()`.
  - `remove_firewall_rule()` enumerates all matching rules, verifies exact Tsukiko ownership, safely deletes single owned rules, strictly refuses deletion of foreign rules, and halts if multiple candidates match ambiguously.
  - `create_firewall_rule()` verifies that no foreign conflicting rule exists with the same name before attempting creation.
- **Strict Windows Portable Executable (PE) Structural Validation (`app/core/privacy/windows_firewall.py`)**:
  - Implemented `validate_pe_structure()`:
    1. Verifies file size >= 64 bytes (minimum DOS header size).
    2. Validates MS-DOS magic bytes `b"MZ"` (0x4D, 0x5A) at byte 0.
    3. Reads 4-byte unsigned little-endian integer at offset `0x3C` (`e_lfanew`).
    4. Validates bounds: `0x40 <= pe_offset <= file_size - 4` (prevents DOS header overlap and file out-of-bounds).
    5. Reads 4-byte signature at `pe_offset` and confirms equality to `b"PE\x00\x00"`.
  - Integrated into `is_safe_target_executable()`.
  - Explicitly documented distinction between binary structural format validation and cryptographic Authenticode code-signing.
- **Real Native `sendmsg` Integration Testing (`tests/test_privacy_enforcement.py`)**:
  - Added `test_real_connected_tcp_sendmsg`: Real connected loopback TCP `sendmsg` data exchange.
  - Added `test_real_udp_explicit_destination_sendmsg`: Real UDP loopback `sendmsg` with explicit destination.
  - Added `test_real_sendmsg_rejects_external_destination`: UDP `sendmsg` targeting external destination raises `PrivacyViolationError`.
  - Tests run natively on platforms supporting `sendmsg` (Linux) and skip cleanly on Windows.
- **Dual-Platform Windows and Linux CI Matrix (`.github/workflows/ci.yml`)**:
  - Maintained `windows-test-and-packaging` on `windows-latest`.
  - Added `linux-integration-and-packaging` on `ubuntu-latest` running the complete pytest suite, building wheel, and testing out-of-tree CLI installation.
  - Validates native `sendmsg` and real `AF_UNIX` socket execution in CI.

### Changed
- `app/core/privacy/windows_firewall.py`: Integrated structural PE validation, fail-closed profile verification, ActiveStore policy inspection, and safe multi-rule deletion.
- `tests/test_windows_firewall.py`: Expanded with 41 new regression tests (60 total) covering all PE structure failure modes, profile edge cases, ActiveStore failure conditions, and safe ownership deletion.
- `tests/test_privacy_enforcement.py`: Added 3 real native `sendmsg` tests (22 total).
- Total test suite expanded to 115 collected tests (111 passed, 4 skipped on Windows; all 115 passing on Linux).

---

## [0.1.1] - Final Phase 1 Security Acceptance Pass - 2026-11-11

### Added
- **Numeric Loopback Enforcement & Hostname Trust Elimination (`app/core/privacy/enforcement.py`)**:
  - `is_numeric_loopback_ip()` strictly requires numeric loopback IPs (`127.0.0.0/8`, `::1`).
  - Rejects raw `localhost` string from raw connection authorization to prevent DNS hijacking and unexpected resolution.
  - Sockets attempting connections to `localhost` have their destination address converted deterministically to numeric loopback (`127.0.0.1` for AF_INET, `::1` for AF_INET6) before invoking low-level C `connect` or `connect_ex` routines, guaranteeing zero external network DNS queries.
- **Fail-Closed Low-Level DNS Interception (`app/core/privacy/enforcement.py`)**:
  - `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo` strictly fail closed with `PrivacyViolationError` for any non-loopback or external destination.
  - Eliminated unrestricted system DNS fallback for `localhost`.
  - Deterministic loopback results for `localhost` and loopback reverse lookups (`127.0.0.1`, `::1`).
- **Socket Family Restrictions (`app/core/privacy/enforcement.py`)**:
  - `_is_allowed_destination` strictly validates socket family (`AF_INET`, `AF_INET6`, `AF_UNIX`).
  - Any unknown or unsupported socket family (e.g. `AF_BLUETOOTH`, `AF_NETLINK`, `AF_PACKET`, or arbitrary integers) fails closed immediately, even if the destination address is formatted as an IP tuple.
- **Platform-Compliant `sendmsg` Argument Forwarding (`app/core/privacy/enforcement.py`)**:
  - Fixed argument forwarding in `_guarded_socket_sendmsg`: for connected sockets where `address is None`, `address` is omitted entirely rather than passed as `address=None`, preserving native C socket API semantics.
  - Explicit address sendmsg calls are validated and normalized.
- **Real AF_UNIX Local IPC Communication Test (`tests/test_privacy_enforcement.py`)**:
  - Added `test_real_af_unix_ipc_exchange` testing genuine socket bind, listen, connect, bidirectional message exchange, and teardown.
  - Automatically skips with clear explanation on Windows Python builds where `hasattr(socket, "AF_UNIX")` is false.
- **Tsukiko Windows Firewall Ownership & Profile Verification (`app/core/privacy/windows_firewall.py`)**:
  - Documented and enforced Tsukiko rule ownership identity:
    - Rule Name: `Tsukiko Outbound Privacy Boundary`
    - Grouping: `Tsukiko Desktop Companion`
    - Description Marker: `[Tsukiko-Privacy-Core:Outbound-Block]`
  - Extended rule verification to inspect Grouping, Description ownership marker, and profile applicability (`Domain,Private,Public` or `Any`).
  - Rejects foreign or unrelated rules sharing the Tsukiko prefix.
  - Safe removal requires verified Tsukiko ownership before deletion.
- **Deployment Binary PE Header Validation (`app/core/privacy/windows_firewall.py`)**:
  - Added binary format validation in `is_safe_target_executable`: reads first 2 bytes and validates the DOS/PE `MZ` executable header magic (`0x4D 0x5A`).
  - Plain text stubs and arbitrary non-PE files are rejected.
  - Documented limitation: PE header check confirms binary format, not cryptographic Authenticode signature verification.
- **Windows Continuous Integration Workflow (`.github/workflows/ci.yml`)**:
  - Established GitHub Actions workflow on `windows-latest` with Python 3.11.
  - Runs full 71-test pytest suite, builds wheel distribution, and executes out-of-tree CLI packaging test.

### Changed
- `app/core/privacy/enforcement.py`: Strict numeric loopback validation, deterministic DNS handling, family-level gating, and fixed sendmsg forwarding.
- `app/core/privacy/windows_firewall.py`: Rule ownership identity, PE header inspection, profile checking, and safe deletion verification.
- `tests/test_privacy_enforcement.py`: Added 5 new regression tests for numeric loopback, sendmsg, real AF_UNIX, and DNS resolution.
- `tests/test_windows_firewall.py`: Updated fixtures with mock PE headers (`b'MZ'`) and added tests for ownership rejection, incomplete profiles, and non-PE executables.
- Total test count expanded to 71 tests (70 passed, 1 skipped on Windows due to platform AF_UNIX absence).

---

## [0.1.0] - Phase 1 Foundation & Engineering Hardening - 2026-11-11

### Added
- **Family-Aware Local IPC & Socket Interception**:
  - Rewrote address validation in `app.core.privacy.enforcement` to inspect socket family (`self.family`) prior to validating addresses.
  - Permitted `AF_UNIX` filesystem paths and abstract socket names as valid local IPC, preventing paths from being misinterpreted as Internet hostnames.
  - Expanded socket interception across all outbound transmission interfaces: `socket.connect`, `connect_ex`, `send`, `sendall`, `sendmsg`, and `sendto` (supporting both calling signatures).
  - Enforced strict loopback address allowlist (`127.0.0.0/8`, `::1`).
  - Strictly rejected unspecified addresses (`0.0.0.0`, `::`), empty strings, and external destinations.
  - Added atomic rollback during guard activation and preserved process-lifetime protection.
- **Strict Windows Firewall Policy Management (`app.core.privacy.windows_firewall`)**:
  - Implemented strict target executable validation requiring the file to exist on disk, resolve to a `.exe`, match the dedicated deployment binary (`tsukiko.exe`), and contain no command-injection characters.
  - Refused to create firewall rules against shared Python interpreters (`python.exe`, `pythonw.exe`, `py.exe`, `pytest.exe`) or shell binaries.
  - Implemented property-level rule verification confirming `Direction=Out`, `Action=Block`, `Enabled=Yes`, and exact normalized executable path.
  - Implemented 4 distinct security status states: `in_process_only`, `os_policy_not_configured`, `os_policy_unverified`, and `os_policy_active`.
  - Required explicit user authorization (`user_authorized=True`) and administrator elevation for rule creation and removal.
- **Fail-Safe VRAM Classification Matrix (`app.core.resource_manager/hardware.py`)**:
  - Fixed GPU data representation to preserve `None` for missing, `[N/A]`, `[Not Supported]`, or malformed metrics rather than converting to zero.
  - Established three distinct VRAM states:
    - `measured`: Known total VRAM and positive free VRAM -> dynamic safe budget `min(total - 1200, free - 400)`.
    - `zero_available`: Known total VRAM and confirmed 0 MB free VRAM -> 0 MB GPU budget and CPU-only fallback.
    - `unavailable`: No GPU, query failed/timed out, or metrics `[N/A]`/malformed -> 0 MB GPU budget and CPU-only fallback.
  - Ensured hardware diagnostic never substitutes positive default budgets when safe VRAM is zero or unavailable.
- **Genuine Wheel Packaging Verification (`tests/test_packaging.py`)**:
  - Implemented integration tests verifying all four packaging milestones:
    1. Wheel successfully built (`tsukiko-0.1.0-py3-none-any.whl`).
    2. Wheel successfully installed into an isolated temporary virtual environment.
    3. Installed console entry point (`tsukiko --check-hardware`) successfully executed outside the repository checkout without `PYTHONPATH`.
    4. Packaged resources (`default_config.yaml`) successfully located without access to repository source checkout.
