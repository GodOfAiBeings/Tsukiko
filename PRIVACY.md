# Tsukiko Privacy & Security Specification

Tsukiko is built with a zero-trust, privacy-first architecture. This document defines the privacy guarantees, boundaries, and enforcement mechanisms across all design, implementation, and testing stages.

---

## 1. Privacy Implementation & Verification Matrix

| Privacy Invariant | Status | Enforcement Mechanism | Verification Test |
|---|---|---|---|
| **Local-Only Inference** | **Implemented & Tested** | `PrivacyConfig.validate_local_only()` throws `ValidationError` if `local_only=False`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **In-Process Network & DNS Interception** | **Implemented & Tested** | Comprehensive socket interception in `app.core.privacy.enforcement` covering `connect`, `connect_ex`, `send`, `sendall`, `sendmsg`, `sendto` (both signatures), `create_connection`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo`. | `tests/test_privacy_enforcement.py` (19 tests) |
| **Numeric Loopback Enforcement** | **Implemented & Tested** | Connection authorization requires numeric loopback IPs (`127.0.0.0/8`, `::1`). `localhost` is resolved deterministically without system DNS fallback. `is_numeric_loopback_ip` rejects raw hostnames. | `tests/test_privacy_enforcement.py::test_numeric_loopback_enforcement` |
| **Socket Family Restrictions** | **Implemented & Tested** | `_is_allowed_destination` explicitly distinguishes `AF_INET`, `AF_INET6`, and `AF_UNIX`. Unsupported families fail closed immediately. | `tests/test_privacy_enforcement.py::test_unsupported_socket_families_fail_closed` |
| **AF_UNIX Local IPC Support** | **Implemented & Tested** | Socket family inspection distinguishes `AF_UNIX` local IPC from Internet sockets. Filesystem paths are permitted for local IPC where supported, and gracefully skipped on unsupported platforms. | `tests/test_privacy_enforcement.py::test_af_unix_local_ipc_validation`, `test_real_af_unix_ipc_exchange` |
| **Deterministic Fail-Closed DNS** | **Implemented & Tested** | `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo` fail closed on all external destinations. No unrestricted fallback queries. | `tests/test_privacy_enforcement.py::test_localhost_deterministic_dns_resolution`, `test_external_dns_requests_strictly_blocked` |
| **Windows Firewall Rule Ownership & Safe Deletion** | **Implemented & Tested** | Unique rule identity (`Tsukiko Outbound Privacy Boundary`), Stable ID (`Tsukiko_Privacy_Outbound_Block`), Grouping (`Tsukiko Desktop Companion`), and Description marker (`[Tsukiko-Privacy-Core:Outbound-Block]`). Enumerates multiple rules, safely deletes single owned rules, refuses foreign deletion, and halts on ambiguous candidates. | `tests/test_windows_firewall.py` (Safe Deletion & Ownership tests) |
| **Fail-Closed Firewall Profile Validation** | **Implemented & Tested** | `validate_firewall_profiles()` strictly fails closed on missing, empty, unknown, or partial profiles. Only `Any` or `Domain,Private,Public` are accepted. | `tests/test_windows_firewall.py` (Profile Validation tests) |
| **ActiveStore Effective Policy Verification** | **Implemented & Tested** | `verify_effective_firewall_policy()` inspects PowerShell NetSecurity ActiveStore view. Verifies all profiles are enabled, local rule merging is permitted (`AllowLocalFirewallRules`), effective Outbound Block rule is active with all 18 CIM filter properties unrestricted, and no conflicting bypass Outbound Allow rules (`OverrideBlockRules=True`) exist for Tsukiko or all-programs scope. Evaluates security filters without error suppression. | `tests/test_windows_firewall.py` (25+ ActiveStore & Bypass tests) |
| **Windows PE Binary Structure Validation** | **Implemented & Tested** | `validate_pe_structure()` verifies minimum 64-byte DOS header, `MZ` magic, 32-bit `e_lfanew` offset at `0x3C`, bounds `0x40 <= pe_offset <= file_size - 4`, and `PE\0\0` signature. | `tests/test_windows_firewall.py` (PE Structure tests) |
| **Native sendmsg Communication (where supported)** | **Implemented & Tested** | Real TCP and UDP `sendmsg` data exchange on loopback, and strict rejection of external destinations on supported platforms (Linux), with clean test skipping on Windows. | `tests/test_privacy_enforcement.py::test_real_connected_tcp_sendmsg`, `test_real_udp_explicit_destination_sendmsg`, `test_real_sendmsg_rejects_external_destination` |
| **Persistent Guard Lifecycle & Atomic Rollback** | **Implemented & Tested** | Offline guard installs atomically with rollback on failure. Protection persists for process lifetime; orchestrator `stop()` does not disable it. | `tests/test_privacy_enforcement.py::test_guard_activation_failure_atomic_rollback` |
| **Fail-Safe VRAM Classification** | **Implemented & Tested** | Distinguishes `measured`, `zero_available`, and `unavailable`. Unknown or zero VRAM yields 0 MB GPU budget and safe CPU-only fallback. | `tests/test_hardware.py` (14 passing tests) |
| **Zero Outbound Telemetry** | **Implemented & Tested** | `PrivacyConfig.validate_no_telemetry()` throws `ValidationError` if `allow_external_telemetry=True`. Socket guard blocks outbound traffic. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **No Cloud LLM Fallback** | **Implemented & Tested** | `PrivacyConfig.validate_no_cloud()` throws `ValidationError` if `allow_cloud_fallback=True`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **Screen Capture OFF by Default** | **Implemented & Tested** | Hardcoded default `screen_sharing_enabled=False` in `PerceptionConfig` & enforced in `Orchestrator.initialize()`. | `tests/test_config.py::test_default_config_privacy_guarantees` |
| **Microphone OFF by Default** | **Implemented & Tested** | Hardcoded default `mic_enabled=False` in `VoiceConfig`. | `tests/test_config.py::test_default_config_privacy_guarantees` |
| **Desktop Control Disabled** | **Implemented & Tested** | Hardcoded default `enabled=False` in `DesktopControlConfig`. | `tests/test_config.py::test_default_config_privacy_guarantees` |
| **Active Screen Capture Gate** | *Designed (Phase 5)* | Frame poll thread terminated and hardware handle released immediately upon toggle OFF. | Scheduled for Phase 5 verification |
| **Sensitive Window Exclusion** | *Designed (Phase 5)* | Ignore window titles matching `*Bitwarden*`, `*1Password*`, `*KeePass*`, `*Private*`. | Scheduled for Phase 5 verification |
| **Volatile Audio Buffers** | *Designed (Phase 6)* | In-memory PCM buffer wiped immediately after Whisper transcription token generation. | Scheduled for Phase 6 verification |
| **Transparent Memory Inspection** | *Designed (Phase 4)* | Full CRUD UI to inspect, redact, and permanently delete facts from `tsukiko_memory.sqlite`. | Scheduled for Phase 4 verification |

---

## 2. In-Process Defense vs. Operating System Security Boundary

Tsukiko explicitly distinguishes between **in-process runtime defense** and **operating system kernel-level firewall enforcement**:

### A. In-Process Python Interception (`app.core.privacy.enforcement`)
* **Scope**: Hooks all primary Python socket and resolver APIs:
  * Connection establishment: `connect`, `connect_ex`, `create_connection`
  * Outbound transmission: `send`, `sendall`, `sendmsg`, `sendto` (supporting both calling signatures)
  * Name and address resolution: `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo`
* **Protection**: Aborts any dependency or application code attempting outbound non-loopback network communication with a `PrivacyViolationError`.
* **Technical Limitations**: In-process interception operates within user-space Python. It provides defense-in-depth against accidental outbound requests by dependencies. However, it **does not** constitute an OS kernel security boundary against external processes or native C-extensions that bypass Python's Berkeley socket abstractions.

### B. Numeric Loopback & Fail-Closed DNS Resolution
* **Connection Authorization**: Socket connections require numeric IPv4 loopback (`127.0.0.0/8`) or IPv6 loopback (`::1`). The string `localhost` is resolved locally to numeric loopback addresses before invocation of low-level connect routines.
* **No Unrestricted System Fallback**: If numeric resolution fails, resolution raises `PrivacyViolationError`. Low-level resolvers never fall through to system DNS for `localhost` or unknown hostnames.
* **Fail-Closed Resolution**: `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo` strictly reject external domains and public IPs.
* **Socket Family Enforcement**: Sockets are inspected by family (`self.family`) before addresses are validated:
  * `AF_UNIX`: Filesystem path strings or bytes are permitted as local IPC endpoints and are never misinterpreted as external Internet hostnames.
  * `AF_INET`: Strictly validates numeric IPv4 loopback or locally mapped `localhost`.
  * `AF_INET6`: Strictly validates numeric IPv6 loopback or locally mapped `localhost`.
  * Unsupported families: Fail closed immediately (returns `False`), even if address formatting resembles an IP tuple.

---

## 3. Windows Firewall Policy Management (`app.core.privacy.windows_firewall`)

### A. The Shared Interpreter Prohibition
Creating a Windows Firewall outbound blocking rule against `python.exe`, `pythonw.exe`, or `py.exe` is dangerous because it indiscriminately cuts off network access for all other Python development, CLI utilities, and package managers across the user's computer. Tsukiko strictly refuses to generate or apply firewall rules targeting shared interpreters.

### B. Dedicated Deployment Binary Requirement & Structural PE Validation
OS-level Windows Firewall enforcement is only available when Tsukiko is built and installed as a standalone dedicated executable (`tsukiko.exe`). The path must:
1. Actually exist as a regular file on disk.
2. Resolve to a normalized absolute path ending in `.exe`.
3. Strictly match the dedicated executable name (`tsukiko.exe`). Arbitrary binaries are rejected.
4. Pass structural Windows Portable Executable (PE) validation (`validate_pe_structure`):
   * Minimum file size >= 64 bytes (valid DOS header).
   * MS-DOS magic bytes `b"MZ"` (0x4D, 0x5A) at offset 0.
   * 4-byte unsigned little-endian integer at offset `0x3C` (`e_lfanew`).
   * Validated offset bounds: `0x40 <= pe_offset <= file_size - 4` (preventing DOS header overlap and file out-of-bounds).
   * Confirmed 4-byte PE signature `b"PE\0\0"` (0x50, 0x45, 0x00, 0x00) at `pe_offset`.
5. Contain no control characters or command-injection sequences.

> **Explicit Limitation on Executable Identity:** Checking file naming and internal Windows PE binary structure confirms that the file is formatted as a valid Windows PE executable. It is **not** cryptographic proof of identity (such as Authenticode digital signature verification). Real cryptographic integrity verification requires an established code-signing certificate and signature verification infrastructure.

### C. Fail-Closed Profile Validation & ActiveStore Effective Policy
Tsukiko strictly validates network profiles and distinguishes persistent rules from effective runtime policy:
* **Fail-Closed Profiles (`validate_firewall_profiles`):**
  * Missing (None), empty, or whitespace profile strings strictly fail verification.
  * Partial profiles (e.g., Domain-only, Private-only, Public-only) fail verification.
  * Unrecognized profile tokens fail verification.
  * Only rules explicitly covering `Any` or all three profiles (`Domain,Private,Public`) are accepted.
* **ActiveStore Effective Policy (`verify_effective_firewall_policy`):**
  * Queries PowerShell NetSecurity `ActiveStore` policy store via static script using process environment variables.
  * Enforces versioned JSON response envelope (`SchemaVersion: 1`, `PolicyStore`, `BypassRules`, `Errors`).
  * Verifies all three network profiles (`Domain`, `Private`, `Public`) are enabled in ActiveStore.
  * Verifies local firewall rule merging is allowed (`AllowLocalFirewallRules` is true) and not blocked by corporate GPO.
  * Confirms that an effective Outbound Block rule exists in ActiveStore, is enabled, outbound, blocking, covers all profiles, and matches the target binary.
  * Evaluates ActiveStore for conflicting Outbound Allow bypass rules without error suppression: enumerates all security filters with `OverrideBlockRules=True` using `Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -OverrideBlockRules $true`. Resolves candidate rules and verifies 1-to-1 association cardinality. Evaluates applicability against Tsukiko: detects exact-executable matches (`Program == targetExe`) and unrestricted all-programs rules (`Program` is Any/empty/`*` with no AppContainer package). Unrelated application rules do not invalidate Tsukiko. If any applicable bypass rule exists, reports bypass conflict and rejects `os_policy_active`.
  * Verifies all 18 outbound filter properties across all 7 categories are unrestricted (`validate_firewall_filters`):
    1. **Application Filter (`Get-NetFirewallApplicationFilter`)**:
       - `Program`: Matches the dedicated deployment binary path (`tsukiko.exe`). Wildcards and empty targets are rejected.
       - `Package`: Unrestricted for Win32 unpackaged binaries requires null/empty package SID. Restrictive AppContainer package SIDs are rejected.
    2. **Address Filter (`Get-NetFirewallAddressFilter`)**:
       - `LocalAddress`: Covers `Any`. Any specific IP, subnet, or keyword restriction is rejected.
       - `RemoteAddress`: Covers `Any`. Any specific IP, subnet, or keyword restriction is rejected.
    3. **Port & Protocol Filter (`Get-NetFirewallPortFilter`)**:
       - `Protocol`: Covers `Any`.
       - `LocalPort`: Covers `Any`.
       - `RemotePort`: Covers `Any`.
       - `IcmpType`: Covers `Any` (or `0`). Restrictive ICMP type filters are rejected.
       - `DynamicTarget`: Covers `Any`. Dynamic targets (e.g., ProximityBySharing, WifiDirect) are rejected.
    4. **Service Filter (`Get-NetFirewallServiceFilter`)**:
       - `Service`: Applies to all services (`Any`).
    5. **Interface Filter (`Get-NetFirewallInterfaceFilter`)**:
       - `InterfaceAlias`: Applies to all interfaces (`Any`).
    6. **Interface-Type Filter (`Get-NetFirewallInterfaceTypeFilter`)**:
       - `InterfaceType`: Applies to all interface types (`Any`).
    7. **Security Filter (`Get-NetFirewallSecurityFilter`)**:
       - `Authentication`: Requires `NotRequired`.
       - `Encryption`: Requires `NotRequired`.
       - `OverrideBlockRules`: Explicit boolean verification that `OverrideBlockRules` is strictly `False` (blocking rules cannot be bypassed).
       - `LocalUser`: Covers `Any`.
       - `RemoteUser`: Covers `Any`.
       - `RemoteMachine`: Covers `Any`.
  * Rejects missing, null, unrecognized, or legacy plural properties.

### D. Rule Ownership Identity, Safe Deletion & Query Results
Tsukiko enforces a unique, documented rule ownership and query mechanism:
* **Display Name:** `Tsukiko Outbound Privacy Boundary`
* **Internal Name (Stable ID):** `Tsukiko_Privacy_Outbound_Block`
* **Grouping:** `Tsukiko Desktop Companion`
* **Ownership Marker:** `[Tsukiko-Privacy-Core:Outbound-Block]`
* **PowerShell Creation & Deletion:**
  * Rule creation uses `New-NetFirewallRule` with explicit `-Name Tsukiko_Privacy_Outbound_Block`, `-DisplayName`, `-Group`, `-Description`, `-Direction Outbound`, `-Action Block`, `-Enabled True`, `-Profile Any`, and `-Program`.
  * Rule removal strictly targets `-Name Tsukiko_Privacy_Outbound_Block -PolicyStore PersistentStore` via `Remove-NetFirewallRule`. Rules are never deleted by DisplayName alone.
  * Post-deletion re-query in the policy store verifies that the rule was actually removed.
  * Legacy rules without the stable internal identifier are reported as unverified legacy rules and automatic deletion is strictly refused.
  * Foreign rules sharing the name prefix or display name are rejected and will never be deleted.
  * If multiple rules claim Tsukiko ownership, deletion halts with an ambiguous identity error requiring operator intervention.
  * Creation refuses to proceed if pre-creation inspection fails or if a conflicting foreign rule already exists.
* **Lossless CIM Serialization & Association Integrity:**
  * Inspection scripts query CIM objects using `Get-CimFieldRecord` helper, outputting structured records with explicit state:
    - `PROPERTY_PRESENT_WITH_VALID_VALUE`
    - `PROPERTY_PRESENT_WITH_NULL`
    - `PROPERTY_MISSING`
    - `PROPERTY_PRESENT_WITH_MALFORMED_VALUE`
  * Eliminates lossy conversions (`[string]`, `[bool]`) in PowerShell that previously collapsed `$null` into empty strings or booleans into strings.
  * Association integrity check confirms exactly 1 associated CIM filter object per category (`Count -eq 1`). Multiple or missing associated filter objects trigger immediate failure.
* **PowerShell Fail-Closed Response Envelope (`SchemaVersion: 1`):**
  * Inspection scripts execute under `$ErrorActionPreference = 'Stop'` without `-ErrorAction SilentlyContinue`. Cmdlet failures, missing modules, or CIM filter errors trigger the catch handler, emit a structured error envelope, and terminate with exit code 1.
  * Output is wrapped in a strict versioned envelope requiring all 8 canonical fields: `{ "SchemaVersion": 1, "Success": bool, "InspectionComplete": bool, "PolicyStore": string, "Profiles": [...], "Rules": [...], "BypassRules": [...], "Errors": [...] }`.
  * Python query handlers enforce `validate_response_envelope()`: requires `SchemaVersion == 1`, `Success` (strict bool), `InspectionComplete` (strict bool), matching `PolicyStore`, list types for all container fields, non-contradictory states (`Success` must equal `InspectionComplete`, and `Success=True` cannot have non-empty `Errors`). Truncated output, empty stdout, malformed JSON, or missing envelope fields strictly fail closed (`success=False, inspection_complete=False`).
  * Empty output or query errors are never conflated with confirmed absence.
  * Pre-creation inspection requires complete, successful inspection before allowing rule creation; post-deletion verification requires complete, successful re-inspection to confirm rule elimination.
* **Strict Missing-Value Semantics & Invariant Field-State Validation:**
  * The parser never manufactures unrestricted defaults (`"Any"`, `"NotRequired"`, `False`) when properties are missing or null.
  * `CimFieldRecord.from_raw()` rejects non-boolean `Exists` / `IsNull` values (disallowing arbitrary string coercion), enforces state consistency across `VALID`, `NULL`, `MISSING`, and `MALFORMED`, and rejects contradictory combinations.
  * All 18 required filter properties across all 7 categories are deserialized into typed `CimFieldRecord` models and validated with fail-closed semantics.
* **No Incomplete Fallbacks:**
  * `netsh advfirewall` is strictly prohibited from declaring complete inspection or evaluating security status. If PowerShell NetSecurity cmdlets are unavailable, queries fail closed (`success=False`), mapping directly to `os_policy_unverified`.
* **Structured Query Result (`FirewallQueryResult`):**
  * Queries return a structured `FirewallQueryResult` distinguishing:
    * **Confirmed Absence**: `success=True`, `inspection_complete=True`, `rules=[]` (supports `os_policy_not_configured`).
    * **Confirmed Presence**: `success=True`, `inspection_complete=True`, `len(rules) > 0` (proceeds to effective policy checks).
    * **Inspection Failure**: `success=False` or `inspection_complete=False` (reports `os_policy_unverified`; never conflated with rule absence).

### E. Four Honest Security States
1. `in_process_only`: Running under a development Python interpreter (`python.exe`) or on non-Windows platforms. In-process socket interception is active; OS-level firewall rules are deliberately omitted to preserve workstation tooling.
2. `os_policy_not_configured`: Running as dedicated `tsukiko.exe`, confirmed absence of matching rules in the policy store.
3. `os_policy_unverified`: Inspection failure, or rule exists in configuration but effective policy in ActiveStore could not be verified (e.g. program mismatch, action not Block, profiles incomplete, profile disabled in ActiveStore, local rule merge restricted, restrictive filter, or missing ownership marker).
4. `os_policy_active`: Dedicated `tsukiko.exe` with verified active Windows Firewall Outbound Block rule and all 7 filter categories confirmed unrestricted in the ActiveStore effective policy layer.

### F. Authorization and Elevation
* **No Automatic Modifications**: Tsukiko will **never** modify Windows Firewall rules automatically at startup.
* **Explicit User Authorization**: Creation and removal functions require `user_authorized=True` and administrative elevation.
* **Refusal on Shared Interpreters**: Strictly refuses rule creation against shared development interpreters.
* **Continuous Integration Verification**: Windows CI runs non-destructive read-only ActiveStore queries verifying NetSecurity cmdlets and Python JSON parser compatibility without altering host firewall state.

---

## 4. Desktop Screen Sharing Privacy Policy

1. **Default State is OFF:** Screen capture is physically blocked until the user explicitly toggles screen sharing ON in the companion interface.
2. **Immediate Stop:** Switching the toggle OFF instantly kills frame polling and unbinds capture handles.
3. **Excluded Windows:** Tsukiko maintains a configurable filter list of sensitive windows that are excluded from visual processing:
   * Password managers (`*1Password*`, `*Bitwarden*`, `*KeePass*`)
   * Private / Incognito browser windows (`*Private Browsing*`, `*Incognito*`)
4. **No Continuous Raw Recordings:** Desktop frames are processed in-memory for change detection and discarded immediately. No continuous video or screenshot sequences are saved to disk unless explicitly configured by the user.

---

## 5. Audio & Voice Privacy Policy

1. **Microphone is Inactive by Default:** Tsukiko does not listen in the background unless voice listening is turned ON by the user.
2. **Local Transcription Only:** All audio processing occurs on-device via local speech engines (e.g., Whisper).
