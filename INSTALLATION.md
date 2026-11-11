# Tsukiko Installation & Environment Setup Guide

This document details all prerequisite verifications, setup commands, and configuration instructions for Windows 11.

---

## 1. System Requirements

* **Operating System:** Windows 11 64-bit (Build 22000+)
* **Processor:** AMD Ryzen 5 5600H or equivalent (6 Cores / 12 Threads)
* **System RAM:** 16 GB (Minimum 4 GB free physical memory)
* **Dedicated GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
* **Driver:** NVIDIA Game Ready / Studio Driver 550.0+ (Driver 616.56 verified)
* **Available Storage:** >= 30 GB SSD space (137 GB verified available)

---

## 2. Prerequisites Verification

Open PowerShell in the project directory (`C:\REA\Tsukiko`):

```powershell
# 1. Verify Python 3.11 64-bit
python --version

# 2. Verify Git
git --version

# 3. Verify NVIDIA Driver and GPU detection
nvidia-smi
```

---

## 3. Dedicated Virtual Environment Setup

Always install Tsukiko dependencies inside an isolated virtual environment to prevent package pollution:

```powershell
# Create virtual environment
python -m venv .venv

# Enable script execution in PowerShell if restricted
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip
```

---

## 4. Layered Dependency Installation

Tsukiko provides modular dependency tiers to avoid bloated or incompatible mass installations:

### Tier 1: Core Foundation (Phase 1)
Required for logging, configuration, hardware inspection, and automated testing:
```powershell
pip install -r requirements/base.txt
```

### Tier 2: Desktop User Interface (Phase 2)
PySide6 Qt framework:
```powershell
pip install -r requirements/ui.txt
```

### Tier 3: Local AI Brain (Phase 3)
Inference engines (llama-cpp-python / onnxruntime):
```powershell
pip install -r requirements/ai.txt
```

### Tier 4: Perception Subsystem (Phase 5)
Image capture and processing libraries:
```powershell
pip install -r requirements/perception.txt
```

### Tier 5: Voice Subsystem (Phase 6)
Audio capture and offline synthesis engines:
```powershell
pip install -r requirements/voice.txt
```

---

## 5. Verification Commands

Verify that the foundational layer is properly wired and operational:

```powershell
# 1. Run Hardware Audit
python scripts/check_hardware.py

# 2. Test CLI Entrypoint
python app/main.py --version
python app/main.py --check-hardware

# 3. Run Pytest Suite
pytest -v
```
