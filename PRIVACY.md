# Tsukiko Privacy & Security Specification

Tsukiko is built with a zero-trust, privacy-first architecture. This document defines the privacy guarantees, boundaries, and enforcement mechanisms across all design, implementation, and testing stages.

---

## 1. Privacy Implementation & Verification Matrix

| Privacy Invariant | Status | Enforcement Mechanism | Verification Test |
|---|---|---|---|
| **Local-Only Inference** | **Implemented & Tested** | `PrivacyConfig.validate_local_only()` throws `ValidationError` if `local_only=False`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **In-Process Network & DNS Interception** | **Implemented & Tested** | Comprehensive socket interception in `app.core.privacy.enforcement` covering `connect`, `connect_ex`, `send`, `sendall`, `sendmsg`, `sendto` (both signatures), `create_connection`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo`. | `tests/test_privacy_enforcement.py` (14 passing tests) |
| **Family-Aware Local IPC Support** | **Implemented & Tested** | Socket family inspection distinguishes `AF_UNIX` local IPC from Internet sockets. Filesystem paths are permitted for local IPC and never misinterpreted as Internet hostnames. | `tests/test_privacy_enforcement.py::test_af_unix_local_ipc_validation` |
| **Strict Loopback Address Allowlist** | **Implemented & Tested** | Permits strictly IPv4 loopback (`127.0.0.0/8`), IPv6 loopback (`::1`), and locally verified `localhost`. Strictly rejects unspecified addresses (`0.0.0.0`, `::`), empty strings, and external destinations. | `tests/test_privacy_enforcement.py::test_unspecified_addresses_strictly_rejected` |
| **Persistent Guard Lifecycle & Atomic Rollback** | **Implemented & Tested** | Offline guard installs atomically with rollback on failure. Protection persists for process lifetime; orchestrator `stop()` does not disable it. | `tests/test_privacy_enforcement.py::test_guard_activation_failure_atomic_rollback` |
| **Windows Firewall Policy Strategy** | **Implemented & Tested** | `app.core.privacy.windows_firewall` strictly validates dedicated deployment binary (`tsukiko.exe`), refuses shared Python interpreters, verifies all rule properties (Out, Block, Enabled, Program path), and reports honest 4-state status. | `tests/test_windows_firewall.py` (13 passing tests) |
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

### B. Local IPC & Family-Aware Address Validation
* **Family Awareness**: Sockets are inspected by family (`self.family`) before addresses are validated:
  * `AF_UNIX` (where available on Windows/Linux): Filesystem path strings or bytes are permitted as local IPC endpoints and are never misinterpreted as external Internet hostnames.
  * `AF_INET` / `AF_INET6`: Subjected to strict loopback validation.
* **Address Allowlist**:
  * Allowed: IPv4 loopback `127.0.0.0/8` (e.g. `127.0.0.1`), IPv6 loopback `::1`, and literal `localhost` (resolved locally with `AI_NUMERICHOST` to prevent network DNS lookups).
  * Forbidden: Unspecified addresses (`0.0.0.0`, `::`), empty strings, LAN IPs, and external Internet destinations.
  * Fail-closed: All unknown destination types and unsupported configurations raise `PrivacyViolationError`.

---

## 3. Windows Firewall Policy Management (`app.core.privacy.windows_firewall`)

### A. The Shared Interpreter Prohibition
Creating a Windows Firewall outbound blocking rule against `python.exe`, `pythonw.exe`, or `py.exe` is dangerous because it indiscriminately cuts off network access for all other Python development, CLI utilities, and package managers across the user's computer. Tsukiko strictly refuses to generate or apply firewall rules targeting shared interpreters.

### B. Dedicated Deployment Binary Requirement
OS-level Windows Firewall enforcement is only available when Tsukiko is built and installed as a standalone dedicated executable (`tsukiko.exe`). The path must:
1. Actually exist as a regular file on disk.
2. Resolve to a normalized absolute path ending in `.exe`.
3. Strictly match the dedicated executable name (`tsukiko.exe`). Arbitrary binaries are rejected.
4. Contain no control characters or command-injection sequences.

### C. Property-Level Rule Verification
A rule with a matching name is not sufficient. Tsukiko inspects the effective policy and verifies all five properties:
1. `Enabled: Yes`
2. `Direction: Out`
3. `Action: Block`
4. `Program: <Normalized Path to tsukiko.exe>`
5. Identity & Prefix: Matches `Tsukiko Outbound Block`

### D. Four Honest Security States
1. `in_process_only`: Running under a development Python interpreter (`python.exe`). In-process socket interception is active; OS-level firewall rules are deliberately omitted to preserve workstation tooling.
2. `os_policy_not_configured`: Running as dedicated `tsukiko.exe`, but no Windows Firewall outbound rule has been configured.
3. `os_policy_unverified`: A rule named `Tsukiko Outbound Block` exists, but property verification failed (e.g., program mismatch, action not Block, or direction not Out).
4. `os_policy_active`: Dedicated `tsukiko.exe` with verified active Windows Firewall Outbound Block rule enforced at the Windows kernel filtering layer.

### E. Authorization and Safe Removal
* **No Automatic Modifications**: Tsukiko will **never** modify Windows Firewall rules automatically at startup.
* **Explicit User Authorization**: Creation and removal functions require `user_authorized=True` and administrative elevation.
* **Safe Removal**: Only rules starting with the prefix `Tsukiko` can be deleted.

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
3. **No Voice Storage:** Audio buffers are processed in temporary memory and flushed immediately after transcription.

---

## 6. Memory Transparency & Control

* **Local Storage:** All persistent memories are stored in `data/memory/tsukiko_memory.sqlite`.
* **No Secret Long-Term Memorization:** Tsukiko does not convert raw conversation turns into permanent facts without user visibility.
* **Full Inspection & Deletion:** Users can inspect, modify, or permanently delete any memory category (facts, preferences, project info) at any time through the Memory Inspector interface.
