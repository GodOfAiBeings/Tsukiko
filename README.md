# Tsukiko (月子) 🌙

**An offline-first, privacy-respecting AI desktop companion for Windows 11.**

Tsukiko is an original AI woman companion designed to live on your Windows desktop. She is thoughtful, calm, observant, and persistent—not a corporate chatbot or a gimmick. She understands conversations, retains long-term memory, observes desktop activity via an explicit live screen-sharing pipeline when granted permission, and interacts entirely offline on constrained consumer hardware.

---

## Hardware Specification & Resource Target

Tsukiko is engineered from first principles for:
* **OS:** Windows 11 64-bit
* **CPU:** AMD Ryzen 5 5600H (6 Cores / 12 Threads)
* **RAM:** 16 GB DDR4 (Safe LLM budget: ~3.5 GB)
* **GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
* **Storage:** ~136 GB Available NVMe SSD

### Architecture Priorities
1. **Zero Outbound Telemetry / Zero Cloud APIs**: Runs completely local.
2. **Strict Privacy by Default**: Screen sharing and microphone are explicitly disabled at startup.
3. **Fail-Safe Dynamic VRAM Budgeting**: Rejects hardcoded VRAM fallbacks. Distinguishes `measured`, `zero_available`, and `unavailable` GPU states. Automatically selects CPU inference if safe VRAM is depleted.
4. **Dual-Layer Privacy Enforcement**: Combines technical in-process family-aware socket/DNS interception with an honest OS-level Windows Firewall strategy for dedicated packaged binaries.
5. **Decoupled Modular Subsystems**: Independent brain, memory, perception, voice, desktop control, and UI modules.

---

## Implementation Status (Designed vs. Implemented vs. Tested)

| Subsystem / Capability | Status | Details |
|---|---|---|
| **Core Architecture & Orchestrator** | **Implemented & Tested** | Composition root with thread-safe `threading.RLock()` lifecycle. Verified via bounded subprocess deadlock tests in `tests/test_entrypoint.py`. |
| **Pydantic Configuration System** | **Implemented & Tested** | Type-safe settings with typed env var parsing (`bool`, `int`, `float`, `str`). Verified in `tests/test_config.py`. |
| **Strict Privacy Assertions** | **Implemented & Tested** | Enforces `local_only=True`, zero telemetry, zero cloud fallback. Verified in `tests/test_config.py`. |
| **Family-Aware Socket & DNS Guard** | **Implemented & Tested** | Hooks `connect`, `connect_ex`, `send`, `sendall`, `sendmsg`, `sendto` (both signatures), `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, `getnameinfo`. Enforces numeric loopback, rejects unsupported socket families, deterministic fail-closed DNS. Verified in `tests/test_privacy_enforcement.py` (19 tests). |
| **Windows Firewall Policy Strategy** | **Implemented & Tested** | `app.core.privacy.windows_firewall` protects shared interpreters, validates PE `MZ` headers, enforces rule ownership identity (`Tsukiko Outbound Privacy Boundary`), verifies all profiles, and reports 4 honest security states. Verified in `tests/test_windows_firewall.py` (19 tests). |
| **Hardware & Resource Auditor** | **Implemented & Tested** | Safe `nvidia-smi` parser, distinct ML framework check (`llama.cpp`, `torch`, `onnxruntime`), fail-safe VRAM classification matrix (`measured`, `zero_available`, `unavailable`). Verified in `tests/test_hardware.py` (14 tests). |
| **Structured Logging** | **Implemented & Tested** | Color console + rotating `tsukiko.log` & `tsukiko.jsonl`, dynamic log re-routing, Windows file unlock. Verified in `tests/test_logging.py`. |
| **Packaging & Distribution** | **Implemented & Tested** | Genuine wheel build, isolated venv installation, out-of-tree CLI execution, and resource isolation verified. Verified in `tests/test_packaging.py` (3 tests). |
| **Continuous Integration (CI)** | **Implemented & Tested** | Windows 11 / Python 3.11 GitHub Actions workflow in `.github/workflows/ci.yml`. |
| **Automated Test Suite** | **Implemented & Tested** | 317 unit, regression, packaging, and integration tests (313 passing, 4 skipped on Windows; 315 passing, 2 skipped on Linux) with 0 failures and 0 errors. |
| **Desktop Companion UI** | **Implemented & Tested** | PySide6-Essentials floating companion widget, procedural moonlight avatar, compact vertical left menu, main window, and 5 views. Verified in `tests/test_desktop_companion.py` (24 tests). |
| **Local AI Brain (llama.cpp)** | *Designed (Phase 3)* | Staged in `requirements/ai.txt` and `app/core/brain/`. No model weights downloaded. |
| **Persistent Long-Term Memory** | *Designed (Phase 4)* | Staged in `app/memory/`. SQLite schema designed; database not yet created. |
| **Desktop Perception Pipeline** | *Designed (Phase 5)* | Staged in `requirements/perception.txt` and `app/perception/`. Screen capture OFF by default. |
| **Offline Voice Subsystem** | *Designed (Phase 6)* | Staged in `requirements/voice.txt` and `app/voice/`. Microphone OFF by default. |
| **Permitted Desktop Control** | *Designed (Phase 7)* | Staged in `app/desktop/permissions/`. Control strictly disabled. |

---

## Quick Start (Phase 1 Foundation)

### 1. Environment Verification
Verify Python 3.11+ and Git are installed:
```powershell
python --version
git --version
```

### 2. Setup Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements/base.txt
pip install -r requirements/ui.txt
pip install -e ".[dev]"
```

### 3. Run Hardware Audit
Inspect CPU, RAM, GPU memory budgets, and runtime compatibility:
```powershell
tsukiko --check-hardware
```
*(Or via python module invocation)*
```powershell
python -m app.main --check-hardware
```

### 4. Launch Desktop Companion (Phase 2 GUI)
Launch the floating desktop companion widget and Moonlight interface:
```powershell
tsukiko
```
*(Or in headless mode without GUI)*
```powershell
tsukiko --headless
```

### 5. Execute Test Suite
Run automated unit and integration tests (317 tests):
```powershell
pytest -v
```

---

## Desktop Companion Interface (Phase 2)

* **Floating Companion Widget**: Frameless, translucent desktop widget with a procedural vector moonlight avatar (`QPainter`). Draggable across screens, clamped to display boundaries, and supports Game Mode (suspends visual activity without game hooking).
* **Compact Vertical Menu**: Clicking the logo opens an 8-item menu immediately to its left:
  1. `Open` — opens the complete Tsukiko main application window.
  2. `Microphone` — voice input control (*locked / Phase 6*).
  3. `Speaker` — Tsukiko voice output control (*locked / Phase 6*).
  4. `Screen Sharing` — explicit screen-sharing control (*locked / Phase 5*).
  5. `Settings` — opens UI settings in the main window.
  6. `Game Mode` — hides widget and suspends visual animations.
  7. `Hide Widget` — hides floating widget without exiting Tsukiko.
  8. `Exit` — cleanly terminates the application and orchestrator.
* **Main Companion Window**: Sidebar navigation featuring Chat (Phase 3 disclaimer), System & Hardware Status (genuine metrics), Privacy & Security (locked sensors and zero-trust verification), Memory (Phase 4 placeholder), and Settings (UI customization).
* **Independent Operation**: Closing the main window hides it to the background while the floating widget continues to function independently.

---

## Documentation Links

* [Developer Guide](DEVELOPMENT.md)
* [System Architecture](ARCHITECTURE.md)
* [Hardware & Model Compatibility](MODEL_COMPATIBILITY.md)
* [Privacy & Security Specification](PRIVACY.md)
* [Troubleshooting Guide](TROUBLESHOOTING.md)
* [Development Log](DEVELOPMENT_LOG.md)
* [Changelog](CHANGELOG.md)
