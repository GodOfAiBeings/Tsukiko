# Tsukiko Privacy & Security Specification

Tsukiko is built with a zero-trust, privacy-first architecture. This document defines the privacy guarantees, boundaries, and enforcement mechanisms implemented in the codebase.

---

## 1. Zero Cloud Transmission Guarantee

* **100% Offline Inference:** Tsukiko never connects to external cloud LLMs, transcription services, or telemetry endpoints during normal execution.
* **No Remote Telemetry:** All logs and metrics stay on the local disk (`logs/` directory).
* **Network Isolation Verification:** Tests verify that the core orchestrator forces `privacy.local_only = True` even if accidentally altered.

---

## 2. Desktop Screen Sharing Privacy Policy

1. **Default State is OFF:** Screen capture is physically blocked until the user explicitly toggles screen sharing ON in the companion interface.
2. **Immediate Stop:** Switching the toggle OFF instantly kills frame polling and unbinds capture handles.
3. **Excluded Windows:** Tsukiko maintains a configurable filter list of sensitive windows that are excluded from visual processing:
   * Password managers (`*1Password*`, `*Bitwarden*`, `*KeePass*`)
   * Private / Incognito browser windows (`*Private Browsing*`, `*Incognito*`)
4. **No Continuous Raw Recordings:** Desktop frames are processed in-memory for change detection and discarded immediately. No continuous video or screenshot sequences are saved to disk unless explicitly configured by the user.

---

## 3. Audio & Voice Privacy Policy

1. **Microphone is Inactive by Default:** Tsukiko does not listen in the background unless voice listening is turned ON by the user.
2. **Local Transcription Only:** All audio processing occurs on-device via local speech engines (e.g., Whisper).
3. **No Voice Storage:** Audio buffers are processed in temporary memory and flushed immediately after transcription.

---

## 4. Memory Transparency & Control

* **Local Storage:** All persistent memories are stored in `data/memory/tsukiko_memory.sqlite`.
* **No Secret Long-Term Memorization:** Tsukiko does not convert raw conversation turns into permanent facts without user visibility.
* **Full Inspection & Deletion:** Users can inspect, modify, or permanently delete any memory category (facts, preferences, project info) at any time through the Memory Inspector interface.
