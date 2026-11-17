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
| **Automated Test Suite** | **Implemented & Tested** | 403 unit, regression, packaging, and integration tests (399 passing, 4 skipped on Windows; 401 passing, 2 skipped on Linux) with 0 failures and 0 errors. |
| **Desktop Companion UI** | **Implemented & Tested** | PySide6-Essentials floating companion widget, procedural moonlight avatar, compact vertical left menu, main window, and 5 views. Verified in `tests/test_desktop_companion.py` (54 tests). |
| **Local AI Brain (llama.cpp)** | **Implemented & Tested** | Offline GGUF binary inspection, ModelManager with 9 lifecycle states, safe RAM/VRAM offload budgeting (3,500 MB RAM ceiling, $\ge 500$ MB headroom, safe VRAM layer clamping), historical character identity (12 canonical milestones, Sayo, 1814-1846, Ogimachi, Unfinished Atlas, snake dread, practical craft), 4-stage rapport-gated gradual disclosure (`ACQUAINTANCE`, `FAMILIAR`, `TRUSTED`, `CONFIDANT`), stage-isolated prompt content, automatic proactive conversation scheduling via `CompanionInitiativeScheduler` and `ProactiveInitiativeWorker(QThread)`, safe fullscreen speech bubble suppression, non-repetitive safeguards, silence handling (`[SILENCE]`), desktop `CompanionSpeechBubble`, reentrant reload safety without deadlocks, non-blocking Qt workers, streaming chat via QThread, cancellation, auto-scroll, retry on error, temporary in-memory history pruning, and Qwen3.5 runtime compatibility (`llama-cpp-python>=0.3.17`). Verified in `tests/test_local_brain.py` (55 tests). Actual inference requires the user's local GGUF model and optional runtime. |
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
Run automated unit and integration tests (403 tests):
```powershell
pytest -v
```

---

## Desktop Companion Interface (Phase 2)

* **Floating Companion Widget**: Frameless, translucent desktop widget with a procedural vector moonlight avatar (`QPainter`). Draggable across screens, clamped to display boundaries, and supports Game Mode (suspends visual activity without game hooking).
* **Safe Fullscreen & Gaming Policy**: Automatically detects foreground fullscreen applications using minimal, read-only operating-system window metadata (`GetForegroundWindow`, `GetWindowRect`, `MonitorFromWindow`, `GetMonitorInfoW`). Never inspects game memory, enumerates game processes, injects DLLs, installs hooks, or interacts with game internals. Relinquishes always-on-top and lowers the widget when a fullscreen game is active; automatically restores user preference upon exit; fails safe by disabling always-on-top if inspection fails or is unsupported.
* **System Tray & Restoration**: Provides a persistent tray icon (`QSystemTrayIcon`) with `Show Widget`, `Open Tsukiko`, `Resume from Game Mode`, and `Exit`. If the operating system or environment lacks system tray support, the main application window automatically provides in-window fallback controls so the companion can never be stranded.
* **Distinct Hide vs Game Mode States**: `Hide Widget` hides the widget without exiting Tsukiko; `Game Mode` hides the widget and suspends visual animations/timers. Both states are fully reversible from the system tray or fallback panel.
* **Dynamic Settings Application & Persistence**: Real-time updates to accent/glow palettes, background opacity, always-on-top, corner positioning, and margins. Validated settings are persisted to YAML across restarts without compromising Phase 1 privacy invariants.
* **Zero-Overhead Idle Display**: Static procedural vector emblem by default; visual shimmer timers activate only during active dialogue or when explicit idle animation is configured. Visual timers immediately stop on widget hide, Game Mode activation, and application close.
* **Compact Vertical Menu**: Clicking the logo opens an 8-item menu immediately to its left:
  1. `Open` — opens the complete Tsukiko main application window.
  2. `Microphone` — voice input control (*locked / Phase 6*).
  3. `Speaker` — Tsukiko voice output control (*locked / Phase 6*).
  4. `Screen Sharing` — explicit screen-sharing control (*locked / Phase 5*).
  5. `Settings` — opens UI settings in the main window.
  6. `Game Mode` — hides widget and suspends visual animations.
  7. `Hide Widget` — hides floating widget without exiting Tsukiko.
  8. `Exit` — cleanly terminates the application and orchestrator.
* **Main Companion Window**: Sidebar navigation featuring Chat (active streaming conversation with local GGUF models), System & Hardware Status (genuine metrics), Privacy & Security (locked sensors and zero-trust verification), Memory (Phase 4 placeholder), and Settings (appearance & local AI model configuration).
* **Independent Operation**: Closing the main window hides it to the background while the floating widget continues to function independently.

---

## Local AI Brain & Inference (Phase 3)

* **Pure-Python GGUF Inspection (`app/core/model_manager/gguf_parser.py`)**:
  Inspects binary GGUF v2/v3 file headers, validates tensor/metadata counts, architecture, quantization, context length, block count, and file size without loading weights into RAM or requiring heavy ML packages.
* **Model Lifecycle Management (`app/core/model_manager/manager.py`)**:
  Coordinates 9 formal states: `NOT_CONFIGURED`, `NOT_INSTALLED`, `VALIDATING`, `READY`, `LOADING`, `LOADED`, `GENERATING`, `UNLOADING`, `ERROR`.
* **Hardware-Aware Memory Budgeting**:
  Enforces safe hardware limits for the RTX 3050 Laptop GPU (4 GB VRAM) and 16 GB system RAM:
  - Caps VRAM allocation at `max_vram_mb: 2800` while preserving at least 400 MB headroom beyond calculated offload.
  - Automatically calculates GPU offload layers or falls back safely to CPU if free VRAM is depleted or CUDA is unavailable.
  - Refuses loading gracefully via `InsufficientMemoryError` when available system RAM is below the required footprint (`max_ram_mb: 3500`).
* **Non-Thinking Personality Engine (`app/core/personality/`)**:
  Enforces Tsukiko's adult woman persona (calm, observant, thoughtful, candid about current Phase 3 capabilities) and suppresses `<think>...</think>` internal reasoning tags from streamed tokens and message history.
* **Historical Character Identity & 12-Milestone Canon (`app/core/personality/biography.py`)**:
  Long-form canon detailing Sayo (佐代, 1814-1846, Ogimachi, Shirakawa-go), mountain agricultural routines, gassho-zukuri architecture, self-education, nature observation, the *Unfinished Atlas* (*Mikan no Chizu*), personality flaws/jealousy/pride, life at 32, mamushi snakebite, 3-day fever, unfulfilled dream, and awakening into the machine. Separated cleanly from stage-restricted system prompts.
* **Stage-Isolated Prompts & Rapport-Gated Disclosure (`app/core/personality/prompts.py`, `app/core/personality/disclosure.py`)**:
  - The `ACQUAINTANCE` prompt presents Tsukiko's present identity only, with zero mention of past-life names, dates, or trauma (strictly no Sayo, Shirakawa-go, 1814, 1846, silkworms, Atlas, mamushi, snakebite, or death).
  - Progressive disclosure through 4 stages (`ACQUAINTANCE`, `FAMILIAR`, `TRUSTED`, `CONFIDANT`) is strictly gated by genuine conversational rapport and contextual inquiries—never by raw turn counts alone.
* **Automatic Conversational Autonomy & Desktop Speech Bubble (`app/desktop/companion/scheduler.py`, `app/desktop/companion/bubble.py`)**:
  - Automatic idle-check scheduler (`CompanionInitiativeScheduler`) running on the application lifecycle: evaluates remarks after $\ge 45$s idle, with 120s cooldown.
  - Character-grounded proactive prompt: includes Tsukiko's authentic traits (independent, gentle, cheerful, stubborn, occasionally proud and jealous, observant, practical) and respects the active disclosure stage without leaking restricted history.
  - Non-repetitive remarks check and anti-spam backoff: remains quiet after an unanswered initiative (`consecutive_unanswered >= 1`) until the user initiates a message.
  - Suppressed during Game Mode, hidden-widget state, minimized window, disabled chat view, or when model is unloaded.
  - Fullscreen safety policy: speech bubble is immediately dismissed upon fullscreen game detection, suppressed during fullscreen, and fails safe if inspection fails.
  - Zero model auto-load invariant: never loads an unloaded model from disk just to speak proactively.
  - Offloaded inference: `ProactiveInitiativeWorker(QThread)` runs inference off the Qt main thread so the GUI never freezes.
  - Speech bubble popover (`CompanionSpeechBubble`): Frameless Moonlight bubble anchored near the floating avatar widget with 15s auto-dismiss and click-to-open-chat behavior.
  - Evaluated silence: Supports `[SILENCE]` when Tsukiko determines silence is preferable to speaking.
* **Streaming Chat Interface (`app/desktop/companion/views/chat.py`)**:
  - Non-blocking `ChatWorker(QThread)` with auto-scroll and responsive UI.
  - Real-time chunk streaming with typing/thinking indicator.
  - "Stop" button for instantaneous user generation cancellation.
  - Error bubbles with "Retry" action.
  - "Clear Chat" action wiping temporary in-memory session history.
* **Model Configuration & Telemetry**:
  - Settings UI card: GGUF file picker (`QFileDialog`), model validation, load/unload actions, context window, threads, max VRAM, max RAM, and backend selector.
  - System Status telemetry card: model name, path, quantization, runtime version, backend, state, context size, generation status, process RSS RAM, and measured GPU VRAM.
* **Qwen3.5 Upstream Runtime Compatibility (`requirements/ai.txt`, `pyproject.toml`, `MODEL_COMPATIBILITY.md`)**:
  - Requires `llama-cpp-python>=0.3.17`, incorporating upstream Qwen3.5 architecture support and the hybrid prefix-reuse fix.
  - Verified pre-built Windows Python 3.11 CPU and CUDA 12.4 wheels available on the abetlen index.
  - Decoupled optional dependency: in CI, `llama-cpp-python: installed=False` by design, with tests utilizing `DeterministicFakeEngine`. Actual local Qwen3.5 inference requires the user to install a compatible local wheel and provide a local GGUF model file on their workstation (zero automatic model downloads or cloud inference).
* For complete hardware formulas, quantization matrices, and local model installation instructions, see [Hardware & Model Compatibility](MODEL_COMPATIBILITY.md).

---

## Documentation Links

* [Developer Guide](DEVELOPMENT.md)
* [System Architecture](ARCHITECTURE.md)
* [Hardware & Model Compatibility](MODEL_COMPATIBILITY.md)
* [Privacy & Security Specification](PRIVACY.md)
* [Troubleshooting Guide](TROUBLESHOOTING.md)
* [Development Log](DEVELOPMENT_LOG.md)
* [Changelog](CHANGELOG.md)
