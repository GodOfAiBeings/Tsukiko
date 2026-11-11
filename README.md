# Tsukiko (月子) 🌙

**An offline-first, privacy-respecting AI desktop companion for Windows 11.**

Tsukiko is an original AI woman companion designed to live on your Windows desktop. She is thoughtful, calm, observant, and persistent—not a corporate chatbot or a gimmick. She understands conversations, retains long-term memory, observes desktop activity via an explicit live screen-sharing pipeline when granted permission, and interacts entirely offline on constrained consumer hardware.

---

## Hardware Specification & Resource Target

Tsukiko is engineered from first principles for:
* **OS:** Windows 11 64-bit
* **CPU:** AMD Ryzen 5 5600H (6 Cores / 12 Threads)
* **RAM:** 16 GB DDR4 (Safe LLM budget: ~4 GB)
* **GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
* **Storage:** ~137 GB Available NVMe SSD

### Architecture Priorities
1. **Zero Outbound Telemetry / Zero Cloud APIs**: Runs completely local.
2. **Strict Privacy by Default**: Screen sharing and microphone are explicitly disabled at startup.
3. **Adaptive VRAM Budgeting**: Respects 4GB VRAM ceiling (~2.8 GB max safe layer offload) using quantized 3B–4B models and sequential model unloading.
4. **Decoupled Modular Subsystems**: Independent brain, memory, perception, voice, desktop control, and UI modules.

---

## Architecture Overview

```
Tsukiko/
│
├── app/
│   ├── main.py                     # Application entry point & CLI flags
│   ├── core/
│   │   ├── config/                 # Pydantic type-safe configuration system
│   │   ├── logging/                # Structured console + rotating text & JSONL logger
│   │   ├── resource_manager/       # Real-time CPU, RAM, GPU/VRAM hardware inspection
│   │   ├── orchestrator/           # Central subsystem lifecycle coordinator
│   │   ├── brain/                  # Offline conversational LLM engine (Phase 3)
│   │   ├── personality/            # Tsukiko persona, prompts, and tone guidelines
│   │   └── model_manager/          # Dynamic weight loading/offloading & VRAM guardian
│   │
│   ├── memory/                     # SQLite persistent storage, retrieval & inspector (Phase 4)
│   ├── perception/                 # Live Windows capture, OCR, ROI & vision pipeline (Phase 5)
│   ├── voice/                      # Offline STT (Whisper) & TTS (Piper/SAPI5) (Phase 6)
│   ├── desktop/                    # Companion presentation & permission gatekeeper (Phases 2 & 7)
│   └── interface/                  # PySide6 desktop views, chat, and settings dialogs
│
├── config/
│   ├── default_config.yaml         # Master system configuration
│   └── personality.yaml            # Persona definition & prompt templates
├── data/                           # Local SQLite databases, conversations, and observations
├── logs/                           # Rotating log files (tsukiko.log, tsukiko.jsonl)
├── models/                         # Local GGUF, ONNX, and speech weights (gitignored)
├── requirements/                   # Modular requirement layers (base, ui, ai, perception, voice)
├── scripts/                        # Diagnostics and hardware auditing tools
└── tests/                          # Automated Pytest suite
```

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
Inspect CPU, RAM, and GPU memory budgets:
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

## Development Roadmap & Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1: Foundation** | Environment audit, modular packaging, logging, configuration, hardware profiling, unit tests | **Complete** |
| **Phase 2: Desktop Application** | PySide6 floating companion, moonlight visual identity, animations, drag-to-snap, settings | Pending Approval |
| **Phase 3: Local AI Brain** | Quantized model runner (llama.cpp), memory-efficient loader, persona engine | Queued |
| **Phase 4: Long-Term Memory** | SQLite persistence, structured facts, retrieval, summarization, inspection UI | Queued |
| **Phase 5: Desktop Perception** | On-demand screen capture pipeline, change detection, OCR, visual reasoning | Queued |
| **Phase 6: Voice System** | Offline speech recognition (STT) and low-latency speech synthesis (TTS) | Queued |
| **Phase 7: Desktop Control** | Permission architecture, approved automation workflows, execution audit logs | Queued |

---

## Documentation Links

* [Installation Guide](INSTALLATION.md)
* [System Architecture](ARCHITECTURE.md)
* [Hardware & Model Compatibility](MODEL_COMPATIBILITY.md)
* [Privacy Guarantees](PRIVACY.md)
* [Troubleshooting Guide](TROUBLESHOOTING.md)
* [Development Log](DEVELOPMENT_LOG.md)
