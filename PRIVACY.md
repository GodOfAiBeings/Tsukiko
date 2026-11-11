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
| **Windows Firewall Rule Ownership** | **Implemented & Tested** | Unique rule identity (`Tsukiko Outbound Privacy Boundary`), Grouping (`Tsukiko Desktop Companion`), and Description marker (`[Tsukiko-Privacy-Core:Outbound-Block]`). Refuses deletion or verification of unowned rules. | `tests/test_windows_firewall.py::test_verify_firewall_rule_rejects_unowned_or_foreign_rule`, `test_remove_firewall_rule_enforces_authorization_prefix_and_ownership` |
| **Executable Identity & PE Header Check** | **Implemented & Tested** | Validates dedicated regular file named `tsukiko.exe`, checks DOS/PE binary `MZ` magic header, and strictly rejects shared interpreters. | `tests/test_windows_firewall.py::test_is_safe_target_executable_rejects_non_pe_binary_header`, `test_is_safe_target_executable_accepts_dedicated_tsukiko_binary` |
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

### B. Dedicated Deployment Binary Requirement & Executable Identity
OS-level Windows Firewall enforcement is only available when Tsukiko is built and installed as a standalone dedicated executable (`tsukiko.exe`). The path must:
1. Actually exist as a regular file on disk.
2. Resolve to a normalized absolute path ending in `.exe`.
3. Strictly match the dedicated executable name (`tsukiko.exe`). Arbitrary binaries are rejected.
4. Possess a valid Windows PE binary header (DOS/PE `MZ` magic header, `0x4D 0x5A`).
5. Contain no control characters or command-injection sequences.

> **Explicit Limitation on Executable Identity:** Checking file naming and the Windows PE `MZ` binary header confirms that the file is formatted as a valid Windows PE executable. It is **not** cryptographic proof of identity (such as Authenticode digital signature verification). Real cryptographic integrity verification requires an established code-signing certificate and signature verification infrastructure.

### C. Rule Ownership & Property-Level Verification
Tsukiko enforces a unique, documented rule ownership mechanism:
* **Rule Name:** `Tsukiko Outbound Privacy Boundary`
* **Grouping:** `Tsukiko Desktop Companion`
* **Ownership Marker:** `[Tsukiko-Privacy-Core:Outbound-Block]`
* **Required Properties:**
  1. `Enabled: Yes`
  2. `Direction: Out`
  3. `Action: Block`
  4. `Program: <Normalized Path to tsukiko.exe>`
  5. `Profiles: Domain,Private,Public` (or `Any`)
  6. `Ownership: Grouping or Description contains Tsukiko ownership marker`

Rules that share the name prefix but lack the Tsukiko ownership grouping or description marker are strictly rejected as foreign/unowned rules.

### D. Four Honest Security States
1. `in_process_only`: Running under a development Python interpreter (`python.exe`). In-process socket interception is active; OS-level firewall rules are deliberately omitted to preserve workstation tooling.
2. `os_policy_not_configured`: Running as dedicated `tsukiko.exe`, but no Windows Firewall outbound rule has been configured.
3. `os_policy_unverified`: A rule named `Tsukiko Outbound Privacy Boundary` exists, but property or ownership verification failed (e.g., program mismatch, action not Block, profiles incomplete, or missing ownership marker).
4. `os_policy_active`: Dedicated `tsukiko.exe` with verified active Windows Firewall Outbound Block rule enforced at the Windows kernel filtering layer.

### E. Authorization and Safe Removal
* **No Automatic Modifications**: Tsukiko will **never** modify Windows Firewall rules automatically at startup.
* **Explicit User Authorization**: Creation and removal functions require `user_authorized=True` and administrative elevation.
* **Safe Removal**: Only verified Tsukiko-owned rules possessing the Tsukiko ownership marker and prefix can be deleted. Arbitrary firewall rules cannot be deleted.

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
