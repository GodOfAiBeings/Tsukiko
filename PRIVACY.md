# Tsukiko Privacy & Security Specification

Tsukiko is built with a zero-trust, privacy-first architecture. This document defines the privacy guarantees, boundaries, and enforcement mechanisms across all design, implementation, and testing stages.

---

## 1. Privacy Implementation & Verification Matrix

| Privacy Invariant | Status | Enforcement Mechanism | Verification Test |
|---|---|---|---|
| **Local-Only Inference** | **Implemented & Tested** | `PrivacyConfig.validate_local_only()` throws `ValidationError` if `local_only=False`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **In-Process Network & DNS Sandbox** | **Implemented & Tested** | Interception in `app.core.privacy.enforcement` hooks `connect`, `connect_ex`, `sendto` (UDP), `create_connection`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo`, throwing `PrivacyViolationError` for any non-loopback outbound socket or resolution. | `tests/test_config.py::test_offline_privacy_guard_enforcement` |
| **Strict Loopback Address Allowlist** | **Implemented & Tested** | Strictly permits only IPv4 `127.0.0.0/8`, IPv6 `::1`, and strictly validated `localhost`. Strictly rejects unspecified addresses (`0.0.0.0`, `::`), empty hosts, and unknown domain names. | `tests/test_config.py::test_offline_privacy_guard_enforcement` |
| **Process-Lifetime Guard Lifecycle** | **Implemented & Tested** | Offline guard remains active for process lifetime; normal orchestrator `stop()` does not disable protection. Rolls back atomically on failure. | `tests/test_entrypoint.py::test_orchestrator_guard_lifecycle_subprocess` |
| **OS-Level Windows Firewall Strategy** | **Implemented & Tested** | `app.core.privacy.windows_firewall` refuses rules against shared interpreters (`python.exe`/`pythonw.exe`) to prevent breaking system tools, supporting dedicated binaries (`tsukiko.exe`) with outbound block rules and honest status inspection. | `tests/test_windows_firewall.py` |
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

## 2. In-Process Defense vs. OS-Level Firewall Boundary

To avoid false security claims, Tsukiko explicitly distinguishes between **in-process runtime interception** and **operating system kernel network policy**:

### A. In-Process Python Interception (`app.core.privacy.enforcement`)
* **Scope**: Hooks all primary Python networking entry points (`socket.socket.connect`, `connect_ex`, `sendto`, `create_connection`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo`).
* **Protection**: Blocks unintentional or dependency-initiated outbound HTTP, TCP, UDP, or DNS requests originating from Python code.
* **Limitations**: While robust defense-in-depth, in-process hooks run inside user-space Python and do not constitute an OS kernel security boundary against native C-extensions or external processes that bypass Python's `socket` module.

### B. OS-Level Windows Firewall Strategy (`app.core.privacy.windows_firewall`)
* **The Shared Interpreter Constraint**: Creating a Windows Firewall outbound blocking rule against `python.exe` or `pythonw.exe` is dangerous because it indiscriminately blocks internet connectivity for all other Python development, CLI utilities, and package managers across the entire workstation.
* **Dedicated Binary Strategy**: When packaged as a standalone dedicated application (e.g. `tsukiko.exe`), an outbound blocking rule (`netsh advfirewall firewall add rule name="Tsukiko Outbound Block" dir=out action=block program="<path>\tsukiko.exe" enable=yes`) establishes an OS-level kernel boundary without affecting other Python programs.
* **Honest Security Status Reporting**: Tsukiko inspects its execution environment and reports one of three honest states:
  1. `in_process_only`: Running under a shared Python interpreter (`python.exe`, `pythonw.exe`). In-process socket and DNS hooks are active; OS firewall rule is deliberately omitted to prevent workstation disruption.
  2. `os_policy_not_configured`: Running as a dedicated application binary (`tsukiko.exe`), but Windows Firewall outbound rule has not yet been registered by an administrator.
  3. `os_policy_active`: Running as a dedicated binary with active Windows Firewall outbound blocking verified at the OS filtering layer.

---

## 3. Strict Address Allowlist & Socket Operations

The offline guard enforces a strict address filter:

1. **Permitted Loopback Targets**:
   * IPv4 Loopback: `127.0.0.0/8` (e.g., `127.0.0.1`, `127.0.0.5`)
   * IPv6 Loopback: `::1`
   * Validated `localhost`: Tested against unhooked resolution to ensure it strictly resolves to `127.0.0.1` or `::1`, protecting against DNS rebind or hosts file poisoning.
2. **Forbidden Targets**:
   * Unspecified Addresses: `0.0.0.0` and `::` are strictly rejected.
   * Empty/Null Hosts: Rejected.
   * External Domains & IPs: Any LAN or Internet address (e.g., `8.8.8.8`, `api.openai.com`) raises `PrivacyViolationError`.

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
