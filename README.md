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
* **Storage:** ~137 GB Available NVMe SSD

### Architecture Priorities
1. **Zero Outbound Telemetry / Zero Cloud APIs**: Runs completely local.
2. **Strict Privacy by Default**: Screen sharing and microphone are explicitly disabled at startup.
3. **Adaptive VRAM Budgeting**: Respects 4GB VRAM ceiling (~2.8 GB max safe layer offload) using quantized 3B–4B models and sequential model unloading.
4. **Decoupled Modular Subsystems**: Independent brain, memory, perception, voice, desktop control, and UI modules.

---

## Implementation Status (Designed vs. Implemented vs. Tested)

| Subsystem / Capability | Status | Details |
|---|---|---|
| **Core Architecture & Orchestrator** | **Implemented & Tested** | Composition root with thread-safe `threading.RLock()` lifecycle. Verified in `tests/test_entrypoint.py`. |
| **Pydantic Configuration System** | **Implemented & Tested** | Type-safe settings with typed env var parsing (`bool`, `int`, `float`, `str`). Verified in `tests/test_config.py`. |
| **Strict Privacy Assertions** | **Implemented & Tested** | Enforces `local_only=True`, zero telemetry, zero cloud fallback. Verified in `tests/test_config.py`. |
| **Hardware & Resource Auditor** | **Implemented & Tested** | Safe `nvidia-smi` parser, distinct ML framework check (`llama.cpp`, `torch`, `onnxruntime`), and realistic VRAM budget model (weights + KV cache + CUDA overhead). Verified in `tests/test_hardware.py`. |
| **Structured Logging** | **Implemented & Tested** | Color console + rotating `tsukiko.log` & `tsukiko.jsonl`, dynamic log re-routing, Windows file unlock. Verified in `tests/test_logging.py`. |
| **CLI Entry Point** | **Implemented & Tested** | `app/main.py` supporting `--version`, `--help`, `--check-hardware`, `--headless`, `--log-level`. |
| **Automated Test Suite** | **Implemented & Tested** | 16 unit and regression tests passing with 0 warnings/errors. |
| **Desktop Companion UI** | *Designed (Phase 2)* | Staged in `requirements/ui.txt` and `app/desktop/companion/`. Awaiting Phase 2 approval. |
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
```

### 3. Run Hardware Audit
Inspect CPU, RAM, GPU memory budgets, and runtime compatibility:
```powershell
python scripts/check_hardware.py
```
*(Or via entry point)*
```powershell
python app/main.py --check-hardware
```

### 4. Execute Test Suite
Run automated unit and integration tests:
```powershell
pytest -v
```

---

## Documentation Links

* [Installation Guide](INSTALLATION.md)
* [System Architecture](ARCHITECTURE.md)
* [Hardware & Model Compatibility](MODEL_COMPATIBILITY.md)
* [Privacy Guarantees](PRIVACY.md)
* [Troubleshooting Guide](TROUBLESHOOTING.md)
* [Development Log](DEVELOPMENT_LOG.md)
