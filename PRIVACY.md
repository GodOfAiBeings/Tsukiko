# Tsukiko Privacy & Security Specification

Tsukiko is built with a zero-trust, privacy-first architecture. This document defines the privacy guarantees, boundaries, and enforcement mechanisms across all design, implementation, and testing stages.

---

## 1. Privacy Implementation & Verification Matrix

| Privacy Invariant | Status | Enforcement Mechanism | Verification Test |
|---|---|---|---|
| **Local-Only Inference** | **Implemented & Tested** | `PrivacyConfig.validate_local_only()` throws `ValidationError` if `local_only=False`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **Zero Outbound Telemetry** | **Implemented & Tested** | `PrivacyConfig.validate_no_telemetry()` throws `ValidationError` if `allow_external_telemetry=True`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **No Cloud LLM Fallback** | **Implemented & Tested** | `PrivacyConfig.validate_no_cloud()` throws `ValidationError` if `allow_cloud_fallback=True`. | `tests/test_config.py::test_privacy_enforcement_raises_on_invalid_settings` |
| **Screen Capture OFF by Default** | **Implemented & Tested** | Hardcoded default `screen_sharing_enabled=False` in `PerceptionConfig` & enforced in `Orchestrator.initialize()`. | `tests/test_config.py::test_default_config_privacy_guarantees` |
| **Microphone OFF by Default** | **Implemented & Tested** | Hardcoded default `mic_enabled=False` in `VoiceConfig`. | `tests/test_config.py::test_default_config_privacy_guarantees` |
| **Desktop Control Disabled** | **Implemented & Tested** | Hardcoded default `enabled=False` in `DesktopControlConfig`. | `tests/test_config.py::test_default_config_privacy_guarantees` |
| **Active Screen Capture Gate** | *Designed (Phase 5)* | Frame poll thread terminated and hardware handle released immediately upon toggle OFF. | Scheduled for Phase 5 verification |
| **Sensitive Window Exclusion** | *Designed (Phase 5)* | Ignore window titles matching `*Bitwarden*`, `*1Password*`, `*KeePass*`, `*Private*`. | Scheduled for Phase 5 verification |
| **Volatile Audio Buffers** | *Designed (Phase 6)* | In-memory PCM buffer wiped immediately after Whisper transcription token generation. | Scheduled for Phase 6 verification |
| **Transparent Memory Inspection** | *Designed (Phase 4)* | Full CRUD UI to inspect, redact, and permanently delete facts from `tsukiko_memory.sqlite`. | Scheduled for Phase 4 verification |

---

## 2. Zero Cloud Transmission Guarantee

* **100% Offline Inference:** Tsukiko never connects to external cloud LLMs, transcription services, or telemetry endpoints during normal execution.
* **No Remote Telemetry:** All logs and metrics stay on the local disk (`logs/` directory).
* **Network Isolation Verification:** Code strictly asserts that `privacy.local_only = True` at the configuration schema level and runtime initialization.

---

## 3. Desktop Screen Sharing Privacy Policy

1. **Default State is OFF:** Screen capture is physically blocked until the user explicitly toggles screen sharing ON in the companion interface.
2. **Immediate Stop:** Switching the toggle OFF instantly kills frame polling and unbinds capture handles.
3. **Excluded Windows:** Tsukiko maintains a configurable filter list of sensitive windows that are excluded from visual processing:
   * Password managers (`*1Password*`, `*Bitwarden*`, `*KeePass*`)
   * Private / Incognito browser windows (`*Private Browsing*`, `*Incognito*`)
4. **No Continuous Raw Recordings:** Desktop frames are processed in-memory for change detection and discarded immediately. No continuous video or screenshot sequences are saved to disk unless explicitly configured by the user.

---

## 4. Audio & Voice Privacy Policy

1. **Microphone is Inactive by Default:** Tsukiko does not listen in the background unless voice listening is turned ON by the user.
2. **Local Transcription Only:** All audio processing occurs on-device via local speech engines (e.g., Whisper).
3. **No Voice Storage:** Audio buffers are processed in temporary memory and flushed immediately after transcription.

---

## 5. Memory Transparency & Control

* **Local Storage:** All persistent memories are stored in `data/memory/tsukiko_memory.sqlite`.
* **No Secret Long-Term Memorization:** Tsukiko does not convert raw conversation turns into permanent facts without user visibility.
* **Full Inspection & Deletion:** Users can inspect, modify, or permanently delete any memory category (facts, preferences, project info) at any time through the Memory Inspector interface.
