# Tsukiko System Architecture

## 1. Architectural Philosophy

Tsukiko is structured around four non-negotiable principles:
1. **Decoupled Autonomy**: Each subsystem (Brain, Memory, Perception, Voice, UI, Desktop Control) can function, be tested, and be initialized independently.
2. **Resource Conservatism**: On an RTX 3050 4GB GPU and 16GB system RAM, models are never left idle in VRAM without cause. VRAM budgets are strictly measured before loading.
3. **Explicit Consent & Privacy**: Capture, microphone listening, and desktop interaction are physically blocked by default until explicitly enabled by the user in the UI.
4. **Deterministic Fail-Safes**: If GPU acceleration or ML libraries are unavailable, systems degrade gracefully to optimized CPU fallbacks or report transparent diagnostics.

---

## 2. Subsystem Decomposition

```mermaid
flowchart TD
    subgraph UI ["Desktop UI Layer (PySide6)"]
        Icon["Floating Companion Widget\n(Passive & Active Moonlight Aura)"]
        Chat["Chat & Memory Inspector"]
        Controls["Screen Share & Mic Toggles"]
    end

    subgraph Core ["Core Orchestrator"]
        Orchestrator["TsukikoOrchestrator"]
        Config["TsukikoConfig (Pydantic / YAML)"]
        Logger["Structured Logger (Console / JSONL)"]
        ResMgr["Resource Manager & Hardware Inspector"]
    end

    subgraph Intelligence ["Cognitive Subsystems"]
        Brain["Local AI Brain (llama.cpp / Q4_K_M)"]
        ModelMgr["Model Manager (Lazy Loader / VRAM Allocator)"]
        Persona["Personality Engine"]
    end

    subgraph Storage ["Memory Subsystem"]
        SQLite["SQLite Persistent DB"]
        Retriever["Fact Retriever & Summarizer"]
    end

    subgraph Sensory ["Perception & Voice"]
        Capture["Windows Native Frame Capture\n(10-15 FPS Adaptive)"]
        ChangeDetect["Change Detector & OCR"]
        Vision["Local Vision Model (Sequential load)"]
        Voice["Offline Whisper (STT) + Piper (TTS)"]
    end

    subgraph Automation ["Desktop Control (Future)"]
        PermGate["Permission Gatekeeper"]
        ActionExec["Audited Action Dispatcher"]
    end

    Icon --> Orchestrator
    Controls --> Orchestrator
    Orchestrator --> Config
    Orchestrator --> ResMgr
    Orchestrator --> Brain
    Orchestrator --> Storage
    Orchestrator --> Sensory
    Orchestrator --> Automation

    Brain --> ModelMgr
    ModelMgr --> ResMgr
    Capture --> ChangeDetect
    ChangeDetect --> Vision
    Vision --> Brain
```

---

## 3. Subsystem Breakdown

### 3.1 Core Orchestrator (`app/core/orchestrator/`)
* Acts as the composition root.
* Coordinates lifecycle (`initialize()`, `start()`, `stop()`).
* Tracks subsystem status across sessions.
* Enforces invariant security policies (e.g., verifying `local_only=True` at startup).

### 3.2 Resource Manager (`app/core/resource_manager/`)
* Queries `nvidia-smi` and `psutil` in real-time.
* Calculates safe VRAM bounds:
  $$\text{Safe VRAM} = \text{Total VRAM} - 1200\text{ MB (OS Headroom)}$$
* Evaluates framework readiness (detects whether CUDA is actually operational before launching GPU workloads).

### 3.3 Local Brain & Model Manager (`app/core/brain/`, `app/core/model_manager/`, `app/core/personality/`)
* **Binary GGUF Parser (`app/core/model_manager/gguf_parser.py`)**:
  * Pure-Python, zero-dependency parser for GGUF v2 and v3 container formats.
  * Reads magic bytes (`b"GGUF"`), version, tensor counts, metadata KV pairs, architecture names, block/layer counts, context lengths, and quantization types.
  * Validates file size, integrity, and compatibility before attempting memory allocation.
* **Model Lifecycle State Machine (`app/core/model_manager/lifecycle.py`)**:
  * Formal 9-state machine: `NOT_CONFIGURED`, `NOT_INSTALLED`, `VALIDATING`, `READY`, `LOADING`, `LOADED`, `GENERATING`, `UNLOADING`, `ERROR`.
  * Real-time metadata tracking: model path, name, quantization, parameters, architecture, active context size, load timestamps, and last-used timestamps.
* **Hardware-Aware Memory & VRAM Offload Budgeting (`app/core/model_manager/manager.py`)**:
  * Designed for target workstation (AMD Ryzen 5 5600H, RTX 3050 Laptop 4GB, 16GB RAM).
  * Safe LLM RAM budget: `max_ram_mb: 3500` (defaults to 3500 MB).
  * Safe GPU VRAM budget: `max_vram_mb: 2800` (defaults to 2800 MB).
  * **Headroom Invariant**: Ensures at least 400 MB of VRAM headroom remains untouched on the GPU beyond any calculated allocation:
    $$\text{Safe VRAM} = \min(\text{Configured Max}, \text{Total VRAM} - 1200\text{ MB}, \text{Free VRAM} - 400\text{ MB})$$
  * Layer offload calculation:
    $$N_{\text{gpu\_layers}} = \min\left(\text{Total Blocks}, \left\lfloor\frac{\text{Safe VRAM Bytes}}{\text{Bytes per Layer}}\right\rfloor\right)$$
  * Graceful memory refusal: If available system RAM is below the required footprint, raises `InsufficientMemoryError` rather than risking an operating system OOM crash.
  * Safe CPU fallback: If GPU free VRAM is 0 MB, `nvidia-smi` is unavailable, or CUDA is absent, `n_gpu_layers` is set to 0.
* **Inference Engine Abstraction (`app/core/model_manager/engine.py`)**:
  * `BaseInferenceEngine`: Abstract base defining `load()`, `generate_stream()`, `cancel()`, `unload()`, and `is_loaded`.
  * `LlamaCppInferenceEngine`: Production engine wrapping `llama-cpp-python` with lazy imports, CUDA capability checks, thread-safe cancellation checking between tokens, and non-thinking reasoning filtering.
  * `DeterministicFakeEngine`: Pure Python test double for reproducible unit/integration tests and CI environments without model weights or GPU drivers.
* **Concurrency Lockout & Inactivity Auto-Unload**:
  * Reentrant locks prevent simultaneous loading or overlapping generation requests.
  * Inactivity timer (configurable, default 300s): automatically unloads model weights from RAM/VRAM after idle duration without interrupting active generation.
* **Personality & Non-Thinking Engine (`app/core/personality/`)**:
  * `TSUKIKO_DEFAULT_SYSTEM_PROMPT`: Directs Tsukiko as an adult woman companion—calm, observant, thoughtful, candid, zero corporate filler.
  * Strictly honest about active Phase 3 capabilities and disabled Phase 4-7 sensors (no screen watching, no microphone listening, no persistent memory, no desktop automation).
  * Non-thinking mode: Suppresses `<think>...</think>` internal reasoning tags from streamed chunks and in-memory history.
* **In-Memory Context Window Management (`app/core/brain/brain.py`)**:
  * Temporary in-memory session history only (zero SQLite database creation).
  * Dynamic context window pruning (`_prune_history_to_fit_context`) drops oldest dialogue turns when estimated token count exceeds `max_context - max_tokens - 100`, preserving the system prompt.
  * History is completely cleared on "Clear Chat" or application exit.

### 3.4 Persistent Long-Term Memory (`app/memory/`)
* SQLite-backed relational schema storing:
  * Conversational turns.
  * Extracted facts (user preferences, project details, user instructions).
  * Summarized session memory.
* Transparent inspection: Users can browse, update, or purge any stored fact.

### 3.5 Live Desktop Perception (`app/perception/`)
* **Strict Privacy Gate**: Capturer thread does not run while switch is OFF.
* **Adaptive Pipeline**:
  1. Capture frames at 10–15 FPS.
  2. Perform fast pixel change detection.
  3. If significant UI delta occurs, run OCR / UI Automation.
  4. Only invoke heavy visual reasoning models when user explicitly asks about the screen or when critical tasks require understanding.
* Never records continuous raw desktop video unless explicitly enabled.

### 3.6 Desktop Control & Security (`app/desktop/permissions/`)
* Strict permission architecture for future action execution.
* Model proposals must pass through explicit user confirmation dialogs before execution.
* Audit trail logged to `logs/tsukiko.jsonl`.

### 3.7 Desktop Companion UI Subsystem (`app/desktop/companion/`)
* **Floating Companion Widget (`FloatingCompanionWidget`)**:
  * Frameless, transparent floating Qt window displaying Tsukiko logo/avatar emblem.
  * Procedural vector rendering (`QPainter`) without VRM, Live2D, 3D character, or GPU engine.
  * Draggable across display work area with screen boundary clamping.
  * Left-clicking the logo toggles the compact vertical menu immediately to its left.
  * Right-clicking also opens the menu.
  * Never forces itself over fullscreen exclusive games or applications.
* **Safe Fullscreen & Gaming Policy (`app/desktop/companion/fullscreen.py`)**:
  * Employs `FullscreenDetector` using strictly read-only operating system window geometry (`GetForegroundWindow`, `GetWindowRect`, `MonitorFromWindow`, `GetMonitorInfoW`, `GetClassNameW`, `GetWindowThreadProcessId`).
  * Explicit ctypes function signatures (`argtypes` and pointer-sized `restype` using `HWND`, `HMONITOR`, `BOOL`, `DWORD`, `RECT`, and `MONITORINFO`) across all 10 Win32 APIs, eliminating 64-bit handle truncation.
  * **Anti-Cheat Safe Invariants**:
    1. NEVER inspects game process memory, scans memory pages, or reads game structures.
    2. NEVER enumerates game processes or checks running executable names.
    3. NEVER injects DLLs, installs API hooks, or registers global hooks (`SetWindowsHookEx`).
    4. NEVER captures screen buffers, window frames, or automates user input.
    5. Fails safe: disables always-on-top if OS metadata is unavailable, unsupported (non-Windows/headless), or raises an exception.
  * Automatically removes `Qt.WindowStaysOnTopHint` and calls `lower()` when a fullscreen foreground window is active.
  * Automatically restores the user's configured always-on-top preference when fullscreen mode exits.
  * Does not claim universal anti-cheat compatibility or guarantee that every game permits third-party desktop companions.
* **Compact Vertical Menu (`CompactCompanionMenu`)**:
  * Positioned immediately to the left of the floating avatar with screen edge fallback.
  * Ordered options: Open, Microphone (locked Phase 6), Speaker (locked Phase 6), Screen Sharing (locked Phase 5), Settings, Game Mode, Hide Widget, Exit.
  * Dismisses smoothly when clicking outside (`Qt.Popup`).
* **System Tray & Restoration Architecture (`app/desktop/companion/tray.py`)**:
  * Lightweight `QSystemTrayIcon` with procedural vector icon.
  * Tray actions: `Show Widget`, `Open Tsukiko`, `Resume from Game Mode` (visible/enabled when Game Mode active), and `Exit`.
  * Distinct states: `Hide Widget` and `Game Mode` are separate states (Game Mode suspends visual animation timers; both reversible from tray).
  * **Tray Fallback Guarantee**: If `QSystemTrayIcon.isSystemTrayAvailable()` returns False (e.g. headless, unsupported display server), Tsukiko launches `CompanionMainWindow` at startup with an in-window companion control panel (`fallback_frame`) including `Show Widget`, `Resume from Game Mode`, and `Exit Tsukiko`. Closing the main window in fallback mode minimizes to the OS taskbar rather than hiding, ensuring controls remain continuously accessible.
* **Zero-Overhead Idle Animation (`app/desktop/companion/avatar.py`)**:
  * Uses `UIConfig.fps` and `UIConfig.idle_animation`.
  * Static procedural vector emblem by default (`idle_animation: false`): the visual animation timer (`_timer`) is NOT started at initialization unless `is_active=True` or `idle_animation=True`.
  * Hiding the widget, entering Game Mode, and closing the widget immediately stops visual timers.
  * Provides `render_to_pixmap()` and `render_to_icon()` for static emblem rendering without running timers.
* **Dynamic Settings Application & YAML Persistence (`app/desktop/companion/views/settings_view.py`)**:
  * Real-time in-memory application of accent/glow color palettes, background opacity, default corner positioning, and margins.
  * Validated settings persist across application restarts to YAML via `save_config()`, with error handling that truthfully distinguishes session application from disk failure.
  * Tracks `_ACTIVE_CONFIG_PATH` to honor custom configuration files specified via `--config`.
  * Privacy and zero-trust policies strictly cannot be altered or bypassed from the UI.
* **Companion Main Window (`CompanionMainWindow`)**:
  * Complete application window launched via `Open` or `Settings`.
  * Silver-blue Moonlight design system (`MoonlightTheme`).
  * 5 modular views: `ChatView` (streaming local chat interface with thinking indicator, cancellation, error retry, clear history), `SystemStatusView` (genuine hardware metrics & local AI brain telemetry), `PrivacyView` (locked sensor indicators and zero-trust invariants), `MemoryView` (Phase 4 placeholder), `SettingsView` (appearance customization and local AI model management).
  * Closing the main window hides it to the background while preserving independent widget execution (or minimizes in fallback mode).
* **Testing Architecture**:
  * Full offscreen Qt test execution via `QT_QPA_PLATFORM=offscreen`.
  * Verified in `tests/test_desktop_companion.py` (49 dedicated unit tests) and `tests/test_local_brain.py` (31 dedicated unit/integration tests).
  * Full project test suite: 373 tests passing cleanly across Windows and Linux CI.
